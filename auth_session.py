"""Windows-protected persistence for a Firebase refresh token until reboot."""

import ctypes
import json
import os
import uuid
from ctypes import wintypes
from pathlib import Path


class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _BootEnvironmentInfo(ctypes.Structure):
    _fields_ = [
        ("boot_identifier", _Guid),
        ("firmware_type", wintypes.DWORD),
        ("boot_flags", wintypes.DWORD),
    ]


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


class AuthSessionStore:
    """Store refresh tokens encrypted for the current Windows user."""

    def __init__(self, path: Path | None = None):
        if os.name != "nt":
            raise OSError("Saved authentication sessions require Windows DPAPI.")
        if path is None:
            local_app_data = os.environ.get("LOCALAPPDATA")
            if not local_app_data:
                raise OSError("The Windows Local AppData folder could not be located.")
            path = Path(local_app_data) / "PacketSniffer" / "auth_session.bin"
        self.path = path

    @staticmethod
    def _boot_id() -> str:
        ntdll = ctypes.WinDLL("ntdll")
        query_system_information = ntdll.NtQuerySystemInformation
        query_system_information.argtypes = [
            wintypes.ULONG,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        ]
        query_system_information.restype = ctypes.c_long
        boot_info = _BootEnvironmentInfo()
        returned_length = wintypes.ULONG()
        status = query_system_information(
            90,
            ctypes.byref(boot_info),
            ctypes.sizeof(boot_info),
            ctypes.byref(returned_length),
        )
        if status < 0:
            raise OSError(
                f"Windows could not read the current boot identifier "
                f"(NTSTATUS 0x{status & 0xFFFFFFFF:08X})."
            )
        raw_guid = ctypes.string_at(ctypes.byref(boot_info.boot_identifier), 16)
        return uuid.UUID(bytes_le=raw_guid).hex

    @staticmethod
    def _protect(data: bytes, decrypt: bool = False) -> bytes:
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        source_buffer = ctypes.create_string_buffer(data)
        source = _DataBlob(
            len(data),
            ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_byte)),
        )
        output = _DataBlob()
        flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN

        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(_DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        crypt32.CryptProtectData.restype = wintypes.BOOL
        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(_DataBlob),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p

        if decrypt:
            description = wintypes.LPWSTR()
            succeeded = crypt32.CryptUnprotectData(
                ctypes.byref(source),
                ctypes.byref(description),
                None,
                None,
                None,
                flags,
                ctypes.byref(output),
            )
        else:
            description = None
            succeeded = crypt32.CryptProtectData(
                ctypes.byref(source),
                "Packet Sniffer session",
                None,
                None,
                None,
                flags,
                ctypes.byref(output),
            )

        if not succeeded:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            kernel32.LocalFree(output.pbData)
            if description and description:
                kernel32.LocalFree(description)

    def save(self, refresh_token: str) -> None:
        if not refresh_token:
            raise ValueError("A Firebase refresh token is required.")
        payload = json.dumps({
            "refresh_token": refresh_token,
            "boot_id": self._boot_id(),
        }).encode("utf-8")
        encrypted = self._protect(payload)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.path.with_name(self.path.name + ".tmp")
        try:
            temporary_path.write_bytes(encrypted)
            os.replace(temporary_path, self.path)
        finally:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass

    def load(self) -> str | None:
        try:
            encrypted = self.path.read_bytes()
        except FileNotFoundError:
            return None
        try:
            payload = json.loads(self._protect(encrypted, decrypt=True).decode("utf-8"))
            refresh_token = payload["refresh_token"]
            saved_boot_id = payload["boot_id"]
            if not isinstance(refresh_token, str) or not refresh_token:
                raise ValueError("The saved refresh token is invalid.")
            if not isinstance(saved_boot_id, str) or not saved_boot_id:
                raise ValueError("The saved boot identifier is invalid.")
        except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("The protected saved login is invalid.") from exc

        if saved_boot_id != self._boot_id():
            self.clear()
            return None
        return refresh_token

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
