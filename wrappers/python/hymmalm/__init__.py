"""hymmalm — Python wrapper for license-management-core.

Thin ctypes binding over the native ``hymmalm`` shared library
(``include/hymma/hlm_ffi.h``). All licensing logic — JWS verification,
status rules, machine fingerprinting, the REST client flow, retry policy
and clock-tamper resistance — lives in the native core, so every language
wrapper behaves identically. This module only marshals.

Typical use::

    from hymmalm import LicenseClient, LicenseStatus

    client = LicenseClient(
        product_id="PRD_01KWWPEPM0N070BDAHJ7G09RGV",
        client_api_key="PUB_...",              # never a MST_ key
        jwks_json=open("signingkeys.json").read(),
        license_path="~/.myapp/license.lic",
    )
    status = client.check()                    # trial bootstrap on first run
    if status == LicenseStatus.INVALID_TRIAL:
        client.activate(user_entered_receipt_code)

The native library is located via the ``HYMMALM_LIB`` environment variable
(full path), or the standard loader search for ``hymmalm``.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import enum
import os
import sys
from datetime import datetime, timezone
from typing import Optional

__all__ = [
    "LicenseClient",
    "LicenseStatus",
    "SignedFormat",
    "LicenseErrorCode",
    "LicenseError",
    "machine_id",
    "machine_name",
    "verify",
]

_TIME_NONE = -(2**63)  # HLM_TIME_NONE


class SignedFormat(enum.IntEnum):
    """Signed-license wire formats the server can emit."""

    RS256 = 1
    ES256 = 2
    EDDSA = 3


class LicenseStatus(enum.IntEnum):
    """Mirrors the native hlm_status / the .NET SDK's LicenseStatusTitles."""

    UNKNOWN = 0
    EXPIRED = 1
    VALID = 2
    VALID_TRIAL = 3
    INVALID_TRIAL = 4
    RECEIPT_EXPIRED = 5
    RECEIPT_UNREGISTERED = 6


class LicenseErrorCode(enum.IntEnum):
    """Classified reasons the core or the server can refuse an operation."""

    INVALID_ARGUMENT = -1
    BUFFER_TOO_SMALL = -2
    MALFORMED_INPUT = -3
    SIGNATURE_INVALID = -4
    UNSUPPORTED_ALGORITHM = -5
    NO_LICENSE = -6
    NETWORK_FAILURE = -7
    API_REJECTED = -8
    STORAGE_FAILURE = -9
    PRODUCT_MISMATCH = -10
    COMPUTER_MISMATCH = -11
    INVALID_API_KEY = -12
    TRIAL_QUOTA_EXCEEDED = -13
    PAID_FORMAT_REQUIRED = -14
    PLAN_LIMIT_REACHED = -15


class LicenseError(Exception):
    """Raised when the native core reports an error.

    ``code`` is the :class:`LicenseErrorCode`; ``detail`` carries the
    server's human-readable refusal reason when it sent one.
    """

    def __init__(self, code: int, detail: str = ""):
        self.native_code = code
        try:
            self.code: Optional[LicenseErrorCode] = LicenseErrorCode(code)
        except ValueError:
            self.code = None
        self.detail = detail
        name = (_lib().hlm_ffi_err_name(code) or b"").decode()
        super().__init__(f"{name}: {detail}" if detail else name)


# ---------------------------------------------------------------------- #
# native library loading                                                  #
# ---------------------------------------------------------------------- #

_LIB: Optional[ctypes.CDLL] = None


def _candidates():
    env = os.environ.get("HYMMALM_LIB")
    if env:
        yield env
    if sys.platform == "win32":
        names = ["hymmalm.dll"]
    elif sys.platform == "darwin":
        names = ["libhymmalm.dylib"]
    else:
        names = ["libhymmalm.so"]
    here = os.path.dirname(os.path.abspath(__file__))
    for name in names:
        yield os.path.join(here, name)  # bundled alongside the package
        yield name  # standard loader search
    found = ctypes.util.find_library("hymmalm")
    if found:
        yield found


def _lib() -> ctypes.CDLL:
    global _LIB
    if _LIB is not None:
        return _LIB
    last_err: Optional[Exception] = None
    for cand in _candidates():
        try:
            _LIB = ctypes.CDLL(cand)
            break
        except OSError as e:  # try the next candidate
            last_err = e
    if _LIB is None:
        raise OSError(
            "cannot load the native hymmalm library; build it with cmake and "
            "set HYMMALM_LIB to the full path of libhymmalm.so/.dylib/hymmalm.dll"
        ) from last_err
    _bind(_LIB)
    return _LIB


def _bind(lib: ctypes.CDLL) -> None:
    c_p = ctypes.c_void_p
    c_i = ctypes.c_int
    c_s = ctypes.c_char_p
    c_i64 = ctypes.c_int64

    lib.hlm_ffi_create.restype = c_p
    lib.hlm_ffi_create.argtypes = [c_s, c_s, c_s, c_s, c_i, ctypes.c_uint,
                                   c_s, c_s, c_s]
    lib.hlm_ffi_destroy.restype = None
    lib.hlm_ffi_destroy.argtypes = [c_p]
    for fn in ("hlm_ffi_check", "hlm_ffi_deactivate", "hlm_ffi_refresh",
               "hlm_ffi_status", "hlm_ffi_live_mode",
               "hlm_ffi_last_http_status"):
        getattr(lib, fn).restype = c_i
        getattr(lib, fn).argtypes = [c_p]
    lib.hlm_ffi_activate.restype = c_i
    lib.hlm_ffi_activate.argtypes = [c_p, c_s]
    for fn in ("hlm_ffi_status_name", "hlm_ffi_license_id",
               "hlm_ffi_product_name", "hlm_ffi_buyer_email",
               "hlm_ffi_last_error_detail"):
        getattr(lib, fn).restype = c_s
        getattr(lib, fn).argtypes = [c_p]
    for fn in ("hlm_ffi_expires", "hlm_ffi_trial_end",
               "hlm_ffi_receipt_expires"):
        getattr(lib, fn).restype = c_i64
        getattr(lib, fn).argtypes = [c_p]
    lib.hlm_ffi_metadata.restype = c_s
    lib.hlm_ffi_metadata.argtypes = [c_p, c_s]
    lib.hlm_ffi_err_name.restype = c_s
    lib.hlm_ffi_err_name.argtypes = [c_i]
    lib.hlm_ffi_machine_id.restype = c_i
    lib.hlm_ffi_machine_id.argtypes = [c_s, c_i]
    lib.hlm_ffi_machine_name.restype = c_i
    lib.hlm_ffi_machine_name.argtypes = [c_s, c_i]
    lib.hlm_ffi_verify.restype = c_i
    lib.hlm_ffi_verify.argtypes = [c_s, c_s, c_s, c_s, c_i64,
                                   ctypes.POINTER(c_i)]


def _enc(s: Optional[str]) -> Optional[bytes]:
    return None if s is None else s.encode("utf-8")


def _from_unix(seconds: int) -> Optional[datetime]:
    if seconds == _TIME_NONE:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


# ---------------------------------------------------------------------- #
# module-level helpers                                                    #
# ---------------------------------------------------------------------- #

def machine_id() -> str:
    """This machine's hardware fingerprint (52-char Crockford Base32) —
    identical to the .NET SDK's DeviceId on the same machine."""
    buf = ctypes.create_string_buffer(64)
    r = _lib().hlm_ffi_machine_id(buf, len(buf))
    if r != 0:
        raise LicenseError(r)
    return buf.value.decode()


def machine_name() -> str:
    """This computer's name, as the SDK would send it."""
    buf = ctypes.create_string_buffer(256)
    r = _lib().hlm_ffi_machine_name(buf, len(buf))
    if r != 0:
        raise LicenseError(r)
    return buf.value.decode()


def verify(jws: str, jwks_json: str,
           expected_product_id: Optional[str] = None,
           expected_machine_id: Optional[str] = None,
           now: Optional[datetime] = None) -> LicenseStatus:
    """Offline one-shot: verify a signed license string and report its
    status at ``now`` (default: the system clock). Raises
    :class:`LicenseError` when the string is tampered or malformed."""
    unix = 0 if now is None else int(now.timestamp())
    status = ctypes.c_int(0)
    r = _lib().hlm_ffi_verify(_enc(jws), _enc(jwks_json),
                              _enc(expected_product_id),
                              _enc(expected_machine_id), unix,
                              ctypes.byref(status))
    if r != 0:
        raise LicenseError(r)
    return LicenseStatus(status.value)


# ---------------------------------------------------------------------- #
# client                                                                  #
# ---------------------------------------------------------------------- #

class LicenseClient:
    """High-level licensing client (check / activate / deactivate / refresh).

    One instance per thread, or serialize calls yourself — same rule as the
    native handle it wraps.
    """

    def __init__(self, *, product_id: str, client_api_key: str,
                 jwks_json: str, base_url: Optional[str] = None,
                 fmt: SignedFormat = SignedFormat.RS256,
                 valid_days: int = 0,
                 machine_id: Optional[str] = None,
                 machine_name: Optional[str] = None,
                 license_path: Optional[str] = None):
        if license_path:
            license_path = os.path.expanduser(license_path)
        self._h = _lib().hlm_ffi_create(
            _enc(base_url), _enc(product_id), _enc(client_api_key),
            _enc(jwks_json), int(fmt), valid_days, _enc(machine_id),
            _enc(machine_name), _enc(license_path))
        if not self._h:
            raise ValueError(
                "hlm_ffi_create rejected the options (missing product/key/"
                "JWKS, or no machine fingerprint available on this platform)")

    # -- lifecycle ----------------------------------------------------- #

    def close(self) -> None:
        if self._h:
            _lib().hlm_ffi_destroy(self._h)
            self._h = None

    def __enter__(self) -> "LicenseClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):  # best-effort; use close()/with for determinism
        try:
            self.close()
        except Exception:
            pass

    @property
    def _handle(self):
        if not self._h:
            raise ValueError("LicenseClient is closed")
        return self._h

    def _guard(self, err: int) -> LicenseStatus:
        if err != 0:
            detail = (_lib().hlm_ffi_last_error_detail(self._handle) or b"").decode()
            raise LicenseError(err, detail)
        return self.status

    # -- operations ----------------------------------------------------- #

    def check(self) -> LicenseStatus:
        """Silent check; on a fresh machine this also bootstraps the trial."""
        return self._guard(_lib().hlm_ffi_check(self._handle))

    def activate(self, receipt_code: str) -> LicenseStatus:
        """Attach a purchased receipt code to this machine's license."""
        return self._guard(_lib().hlm_ffi_activate(self._handle,
                                                   _enc(receipt_code)))

    def deactivate(self) -> LicenseStatus:
        """Free this machine's seat (uninstall flow)."""
        return self._guard(_lib().hlm_ffi_deactivate(self._handle))

    def refresh(self) -> LicenseStatus:
        """Fetch a fresh signed license, ignoring the cache."""
        return self._guard(_lib().hlm_ffi_refresh(self._handle))

    # -- state ----------------------------------------------------------- #

    @property
    def status(self) -> LicenseStatus:
        return LicenseStatus(_lib().hlm_ffi_status(self._handle))

    @property
    def license_id(self) -> str:
        return (_lib().hlm_ffi_license_id(self._handle) or b"").decode()

    @property
    def product_name(self) -> str:
        return (_lib().hlm_ffi_product_name(self._handle) or b"").decode()

    @property
    def buyer_email(self) -> str:
        return (_lib().hlm_ffi_buyer_email(self._handle) or b"").decode()

    @property
    def live_mode(self) -> bool:
        return _lib().hlm_ffi_live_mode(self._handle) != 0

    @property
    def expires(self) -> Optional[datetime]:
        return _from_unix(_lib().hlm_ffi_expires(self._handle))

    @property
    def trial_end(self) -> Optional[datetime]:
        return _from_unix(_lib().hlm_ffi_trial_end(self._handle))

    @property
    def receipt_expires(self) -> Optional[datetime]:
        return _from_unix(_lib().hlm_ffi_receipt_expires(self._handle))

    @property
    def last_http_status(self) -> int:
        return _lib().hlm_ffi_last_http_status(self._handle)

    def metadata(self, key: str) -> str:
        return (_lib().hlm_ffi_metadata(self._handle, _enc(key)) or b"").decode()
