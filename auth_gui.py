"""Tkinter login and registration window for Firebase Authentication."""

from threading import Thread
import tkinter as tk
from tkinter import messagebox, ttk


class AuthWindow(tk.Tk):
    def __init__(self, auth_client, session_store, notice: str = ""):
        super().__init__()
        self.auth_client = auth_client
        self.session_store = session_store
        self.result = None

        self.title("Packet Sniffer - Sign in")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        container = ttk.Frame(self, padding=16)
        container.grid(sticky="nsew")
        ttk.Label(
            container,
            text="Sign in or create an account",
            font=("Segoe UI", 14, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 10))
        if notice:
            ttk.Label(
                container,
                text=notice,
                wraplength=420,
                foreground="#9a5b00",
            ).grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.notebook = ttk.Notebook(container)
        self.notebook.grid(row=2, column=0, sticky="nsew")
        self.login_tab = ttk.Frame(self.notebook, padding=12)
        self.register_tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.login_tab, text="Sign in")
        self.notebook.add(self.register_tab, text="Register")
        self.status_var = tk.StringVar()
        ttk.Label(container, textvariable=self.status_var).grid(
            row=3, column=0, sticky="w", pady=(8, 0)
        )

        self._build_login_form()
        self._build_register_form()
        self._center_window()

    def _build_login_form(self):
        tab = self.login_tab
        self.login_identifier = tk.StringVar()
        self.login_password = tk.StringVar()
        self.keep_signed_in = tk.BooleanVar(value=False)

        ttk.Label(tab, text="Username or Gmail").grid(row=0, column=0, sticky="w")
        ttk.Entry(tab, textvariable=self.login_identifier, width=38).grid(
            row=1, column=0, sticky="ew", pady=(2, 8)
        )
        ttk.Label(tab, text="Password").grid(row=2, column=0, sticky="w")
        ttk.Entry(tab, textvariable=self.login_password, show="*", width=38).grid(
            row=3, column=0, sticky="ew", pady=(2, 8)
        )
        ttk.Checkbutton(
            tab,
            text="Keep me signed in until Windows restarts",
            variable=self.keep_signed_in,
        ).grid(row=4, column=0, sticky="w", pady=(0, 8))
        self.login_button = ttk.Button(tab, text="Sign in", command=self._sign_in)
        self.login_button.grid(row=5, column=0, sticky="ew")
        ttk.Label(
            tab,
            text="Gmail is verified once during registration; no email code is sent at each login.",
            wraplength=360,
        ).grid(row=6, column=0, sticky="w", pady=(8, 0))

    def _build_register_form(self):
        tab = self.register_tab
        self.register_username = tk.StringVar()
        self.register_email = tk.StringVar()
        self.register_password = tk.StringVar()
        self.register_confirm = tk.StringVar()

        fields = (
            ("Username", self.register_username, False),
            ("Gmail address", self.register_email, False),
            ("Password", self.register_password, True),
            ("Confirm password", self.register_confirm, True),
        )
        for row, (label, variable, hidden) in enumerate(fields):
            ttk.Label(tab, text=label).grid(row=row * 2, column=0, sticky="w")
            ttk.Entry(
                tab,
                textvariable=variable,
                width=38,
                show="*" if hidden else "",
            ).grid(row=row * 2 + 1, column=0, sticky="ew", pady=(2, 7))
        ttk.Label(
            tab,
            text="Use 3-20 letters, numbers, or underscores for the username. "
            "Passwords need 8+ characters with uppercase, lowercase, a number, and a symbol.",
            wraplength=360,
        ).grid(row=8, column=0, sticky="w", pady=(0, 8))
        self.register_button = ttk.Button(
            tab,
            text="Create account",
            command=self._register_user,
        )
        self.register_button.grid(row=9, column=0, sticky="ew")

    def _center_window(self):
        self.update_idletasks()
        width = self.winfo_reqwidth()
        height = self.winfo_reqheight()
        x = (self.winfo_screenwidth() - width) // 2
        y = (self.winfo_screenheight() - height) // 2
        self.geometry(f"+{x}+{y}")

    def _run_worker(self, operation, on_success):
        self.status_var.set("Contacting Firebase...")
        self.login_button.configure(state="disabled")
        self.register_button.configure(state="disabled")

        def worker():
            try:
                result = operation()
            except Exception as exc:
                message = str(exc)
                self._schedule_ui(lambda: self._show_error(message))
                return
            self._schedule_ui(lambda: on_success(result))

        Thread(target=worker, name="FirebaseAuth", daemon=True).start()

    def _schedule_ui(self, callback):
        try:
            self.after(0, callback)
        except tk.TclError:
            pass

    def _enable_buttons(self):
        self.login_button.configure(state="normal")
        self.register_button.configure(state="normal")
        self.status_var.set("")

    def _show_error(self, message):
        self._enable_buttons()
        messagebox.showerror("Authentication", message, parent=self)

    def _sign_in(self):
        identifier = self.login_identifier.get().strip()
        password = self.login_password.get()
        if not identifier or not password:
            self._show_error("Enter your username or Gmail address and password.")
            return

        self._run_worker(
            lambda: self.auth_client.sign_in(identifier, password),
            self._complete_sign_in,
        )

    def _complete_sign_in(self, result):
        self._enable_buttons()
        if not result.get("ok"):
            if result.get("needs_verification"):
                message = result.get("error", "Verify your Gmail before signing in.")
                if messagebox.askyesno(
                    "Gmail verification required",
                    f"{message}\n\nResend the verification email?",
                    parent=self,
                ):
                    token = result.get("id_token", "")
                    self._run_worker(
                        lambda: self.auth_client.send_verification_email(token),
                        self._complete_resend,
                    )
                return
            messagebox.showerror(
                "Sign-in failed",
                result.get("error", "Firebase sign-in failed."),
                parent=self,
            )
            return

        try:
            if self.keep_signed_in.get():
                self.session_store.save(result.get("refresh_token", ""))
            else:
                self.session_store.clear()
        except (OSError, RuntimeError, ValueError) as exc:
            messagebox.showerror(
                "Could not save session",
                f"Sign-in succeeded, but the saved session could not be secured:\n{exc}",
                parent=self,
            )
            return
        self.result = result
        self.destroy()

    def _complete_resend(self, result):
        self._enable_buttons()
        sent, message = result
        if sent:
            messagebox.showinfo("Verification email", message, parent=self)
        else:
            messagebox.showerror("Verification email", message, parent=self)

    def _register_user(self):
        username = self.register_username.get().strip()
        email = self.register_email.get().strip()
        password = self.register_password.get()
        confirm = self.register_confirm.get()
        if password != confirm:
            self._show_error("The passwords do not match.")
            return
        self._run_worker(
            lambda: self.auth_client.register_user(username, email, password),
            self._complete_register,
        )

    def _complete_register(self, result):
        self._enable_buttons()
        if not result.get("ok"):
            messagebox.showerror(
                "Registration failed",
                result.get("error", "Firebase registration failed."),
                parent=self,
            )
            return
        messagebox.showinfo(
            "Check your Gmail",
            result.get("message", "Check your Gmail for the verification link."),
            parent=self,
        )
        self.login_identifier.set(result.get("username", ""))
        self.login_password.set("")
        self.notebook.select(self.login_tab)

    def _cancel(self):
        self.result = None
        self.destroy()
