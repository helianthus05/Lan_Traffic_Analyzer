import os
import re
import requests
import firebase_admin
from firebase_admin import credentials, firestore
from google.api_core.exceptions import GoogleAPIError

SIGN_UP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signUp"
SIGN_IN_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
SEND_OOB_URL = "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode"
LOOKUP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:lookup"
TOKEN_URL = "https://securetoken.googleapis.com/v1/token"
FIREBASE_APP_NAME = "packet-sniffer-auth"


def validate_password(password: str) -> tuple[bool, str]:
    """Check for a strong password: 8+ chars, upper, lower, digit, and symbol."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must include at least one special character."
    return True, "OK"


def normalize_username(username: str) -> tuple[bool, str]:
    """Normalize username to lowercase and enforce safe characters (3-20 chars)."""
    clean = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_]{3,20}", clean):
        return False, "Username must be 3-20 characters (letters, numbers, or underscores)."
    return True, clean


class FirebaseAuthClient:
    def __init__(self, web_api_key: str, service_account_path: str):
        if not web_api_key:
            raise ValueError("Missing FIREBASE_WEB_API_KEY.")
        if not service_account_path or not os.path.exists(service_account_path):
            raise FileNotFoundError(f"Service account JSON not found: {service_account_path}")

        self.api_key = web_api_key

        try:
            app = firebase_admin.get_app(FIREBASE_APP_NAME)
        except ValueError:
            cred = credentials.Certificate(service_account_path)
            app = firebase_admin.initialize_app(cred, name=FIREBASE_APP_NAME)
        self.db = firestore.client(app=app)

    def _post(self, base_url: str, payload: dict) -> dict:
        resp = requests.post(
            base_url,
            params={"key": self.api_key},
            json=payload,
            timeout=15,
        )
        data = resp.json()
        if not resp.ok:
            msg = data.get("error", {}).get("message", "FIREBASE_AUTH_ERROR")
            raise RuntimeError(msg)
        return data

    def is_username_available(self, username: str) -> bool:
        ok, clean = normalize_username(username)
        if not ok:
            return False
        doc = self.db.collection("usernames").document(clean).get()
        return not doc.exists

    def register_user(self, username: str, email: str, password: str) -> dict:
        """Create account, reserve unique username in Firestore, and send verification email."""
        ok_u, clean_username = normalize_username(username)
        if not ok_u:
            return {"ok": False, "error": clean_username}

        clean_email = email.strip().lower()
        if not clean_email.endswith("@gmail.com"):
            return {"ok": False, "error": "Please use a valid @gmail.com address."}

        ok_p, msg_p = validate_password(password)
        if not ok_p:
            return {"ok": False, "error": msg_p}

        # Reserve the username atomically in Firestore first
        username_ref = self.db.collection("usernames").document(clean_username)
        transaction = self.db.transaction()

        @firestore.transactional
        def reserve_username(txn, ref):
            snap = ref.get(transaction=txn)
            if snap.exists:
                raise ValueError("USERNAME_TAKEN")
            txn.set(ref, {
                "username": clean_username,
                "email": clean_email,
                "created_at": firestore.SERVER_TIMESTAMP,
            })

        try:
            reserve_username(transaction, username_ref)
        except ValueError:
            return {"ok": False, "error": "That username is already taken."}

        # Create the Firebase Auth user
        created_uid = None
        try:
            auth_data = self._post(
                SIGN_UP_URL,
                {
                    "email": clean_email,
                    "password": password,
                    "returnSecureToken": True,
                },
            )
            id_token = auth_data["idToken"]
            uid = auth_data["localId"]
            created_uid = uid

            self.db.collection("users").document(uid).set({
                "uid": uid,
                "username": clean_username,
                "email": clean_email,
                "email_verified": False,
                "created_at": firestore.SERVER_TIMESTAMP,
            })

            # Send verification email after storing the profile so an email
            # delivery failure can be recovered by signing in and resending.
            self._post(
                SEND_OOB_URL,
                {
                    "requestType": "VERIFY_EMAIL",
                    "idToken": id_token,
                },
            )

            return {
                "ok": True,
                "uid": uid,
                "username": clean_username,
                "message": "Account created! Check your Gmail to verify before logging in.",
            }

        except Exception as exc:
            if created_uid is None:
                username_ref.delete()
                return {"ok": False, "error": f"Registration failed: {exc}"}
            return {
                "ok": False,
                "error": (
                    "The account was created, but setup did not finish. "
                    "Sign in with the username or Gmail and resend the "
                    f"verification email. Details: {exc}"
                ),
            }

    def send_verification_email(self, id_token: str) -> tuple[bool, str]:
        try:
            self._post(
                SEND_OOB_URL,
                {
                    "requestType": "VERIFY_EMAIL",
                    "idToken": id_token,
                },
            )
            return True, "Verification email sent."
        except Exception as exc:
            return False, str(exc)

    def sign_in(self, email_or_username: str, password: str) -> dict:
        """Sign in with email or username and verify that Gmail is confirmed."""
        identifier = email_or_username.strip().lower()
        if not identifier or not password:
            return {"ok": False, "error": "Email/username and password are required."}

        # Allow logging in with either Gmail or reserved username
        if "@" not in identifier:
            ok_u, clean_u = normalize_username(identifier)
            if not ok_u:
                return {"ok": False, "error": "Invalid username or email."}
            u_doc = self.db.collection("usernames").document(clean_u).get()
            if not u_doc.exists:
                return {"ok": False, "error": "Account not found."}
            email = u_doc.to_dict().get("email", "")
        else:
            email = identifier

        try:
            auth_data = self._post(
                SIGN_IN_URL,
                {
                    "email": email,
                    "password": password,
                    "returnSecureToken": True,
                },
            )
            id_token = auth_data["idToken"]
            uid = auth_data["localId"]

            # Fetch fresh user details to check emailVerified status
            lookup_data = self._post(LOOKUP_URL, {"idToken": id_token})
            users = lookup_data.get("users", [])
            email_verified = bool(users[0].get("emailVerified", False)) if users else False

            user_doc = self.db.collection("users").document(uid).get()
            user_profile = user_doc.to_dict() if user_doc.exists else {}
            username = user_profile.get("username", email.split("@")[0])

            if not email_verified:
                return {
                    "ok": False,
                    "needs_verification": True,
                    "id_token": id_token,
                    "uid": uid,
                    "username": username,
                    "error": "Your Gmail isn't verified yet. Check your inbox or resend the link.",
                }

            self.db.collection("users").document(uid).set(
                {"email_verified": True, "last_login": firestore.SERVER_TIMESTAMP},
                merge=True,
            )

            return {
                "ok": True,
                "uid": uid,
                "username": username,
                "email": email,
                "id_token": id_token,
                "refresh_token": auth_data.get("refreshToken", ""),
            }

        except RuntimeError as exc:
            code = str(exc)
            friendly = {
                "INVALID_LOGIN_CREDENTIALS": "Incorrect email/username or password.",
                "EMAIL_NOT_FOUND": "No account found with that email.",
                "INVALID_PASSWORD": "Incorrect password.",
                "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many attempts. Try again later.",
            }.get(code, f"Sign-in failed ({code}).")
            return {"ok": False, "error": friendly}
        except Exception as exc:
            return {"ok": False, "error": f"Sign-in error: {exc}"}

    def restore_session(self, refresh_token: str) -> dict:
        """Refresh a saved Firebase session and re-check the account's email status."""
        try:
            response = requests.post(
                TOKEN_URL,
                params={"key": self.api_key},
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                },
                timeout=15,
            )
            data = response.json()
            if not response.ok:
                error = data.get("error", {}).get("message", "FIREBASE_AUTH_ERROR")
                return {"ok": False, "error": f"Saved login could not be refreshed ({error})."}

            id_token = data["id_token"]
            uid = data["user_id"]
            lookup_data = self._post(LOOKUP_URL, {"idToken": id_token})
            users = lookup_data.get("users", [])
            if not users:
                return {"ok": False, "error": "Firebase returned no user for the saved login."}

            user = users[0]
            if not bool(user.get("emailVerified", False)):
                return {
                    "ok": False,
                    "error": "The saved account's Gmail is no longer verified.",
                }

            email = user.get("email", "")
            profile_ref = self.db.collection("users").document(uid)
            profile_doc = profile_ref.get()
            profile = profile_doc.to_dict() if profile_doc.exists else {}

            return {
                "ok": True,
                "uid": uid,
                "username": profile.get("username", email.split("@")[0]),
                "email": email,
                "id_token": id_token,
                "refresh_token": data.get("refresh_token", refresh_token),
            }
        except requests.RequestException as exc:
            return {"ok": False, "error": f"Could not refresh the saved login: {exc}"}
        except (GoogleAPIError, KeyError, ValueError, RuntimeError) as exc:
            return {"ok": False, "error": f"Could not restore the saved login: {exc}"}