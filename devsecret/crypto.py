"""Vault file format: PBKDF2-HMAC-SHA256 + AES-256-GCM."""

from __future__ import annotations

import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"DEVSCT1\x00"
FORMAT_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
PBKDF2_ITERATIONS = 600_000

HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN


class VaultCryptoError(Exception):
    """Invalid vault file, wrong password, or tampered data."""


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_vault(password: str, plaintext: bytes) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return (
        MAGIC
        + struct.pack("B", FORMAT_VERSION)
        + salt
        + nonce
        + ciphertext
    )


def decrypt_vault(password: str, blob: bytes) -> bytes:
    if len(blob) < HEADER_LEN:
        raise VaultCryptoError("Vault file is too short or corrupt.")
    if blob[: len(MAGIC)] != MAGIC:
        raise VaultCryptoError("Not a DevSecret vault file (bad magic).")
    version = blob[len(MAGIC)]
    if version != FORMAT_VERSION:
        raise VaultCryptoError(f"Unsupported vault format version: {version}.")
    off = len(MAGIC) + 1
    salt = blob[off : off + SALT_LEN]
    off += SALT_LEN
    nonce = blob[off : off + NONCE_LEN]
    off += NONCE_LEN
    ciphertext = blob[off:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise VaultCryptoError(
            "Could not decrypt vault (wrong password or corrupt/tampered file)."
        ) from None
