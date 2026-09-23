"""Salted scrypt password storage; uses only the Python standard library."""

import hashlib
import hmac
import secrets


N, R, P = 2**17, 8, 1
SALT_BYTES, KEY_BYTES = 16, 32
MAX_PASSWORD_BYTES = 1024
PREFIX = f"scrypt${N}${R}${P}"
RECORD_LENGTH = len(PREFIX) + 2 + SALT_BYTES * 2 + KEY_BYTES * 2


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str):
        raise ValueError("Password must be text.")
    encoded = password.encode("utf-8")
    if not 1 <= len(encoded) <= MAX_PASSWORD_BYTES:
        raise ValueError("Password must contain 1 to 1024 UTF-8 bytes.")
    return encoded


def _derive(password: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password, salt=salt, n=N, r=R, p=P, dklen=KEY_BYTES,
        maxmem=256 * 1024 * 1024,
    )


def hash_password(password: str) -> str:
    """Return a versioned record; callers store this entire string."""
    encoded = _password_bytes(password)
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _derive(encoded, salt)
    return f"{PREFIX}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Reject malformed/unsupported records without trusting their cost values."""
    try:
        encoded = _password_bytes(password)
        if not isinstance(stored_hash, str) or len(stored_hash) != RECORD_LENGTH:
            return False
        algorithm, n, r, p, salt_hex, digest_hex = stored_hash.split("$")
        if "$".join((algorithm, n, r, p)) != PREFIX:
            return False
        salt, expected = bytes.fromhex(salt_hex), bytes.fromhex(digest_hex)
        if len(salt) != SALT_BYTES or len(expected) != KEY_BYTES:
            return False
        return hmac.compare_digest(_derive(encoded, salt), expected)
    except (ValueError, UnicodeError):
        return False
