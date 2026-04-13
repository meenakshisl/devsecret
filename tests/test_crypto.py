"""Tests for devsecret.crypto."""

from __future__ import annotations

import pytest

from devsecret.crypto import HEADER_LEN, MAGIC, VaultCryptoError, decrypt_vault, encrypt_vault

_PW = "correct-horse-battery-staple"


def test_encrypt_decrypt_roundtrip():
    plain = b'{"api_keys":{},"recovery_codes":{}}'
    blob = encrypt_vault(_PW, plain)
    assert decrypt_vault(_PW, blob) == plain


def test_wrong_password_raises():
    blob = encrypt_vault(_PW, b"secret")
    with pytest.raises(VaultCryptoError):
        decrypt_vault("wrong-pass", blob)


def test_decrypt_too_short_blob():
    with pytest.raises(VaultCryptoError, match="too short"):
        decrypt_vault(_PW, b"\x00" * (HEADER_LEN - 1))


def test_decrypt_bad_magic():
    blob = encrypt_vault(_PW, b"x")
    bad = b"XXXXXXX\x00" + blob[len(MAGIC) :]
    with pytest.raises(VaultCryptoError, match="bad magic"):
        decrypt_vault(_PW, bad)


def test_decrypt_unsupported_version():
    blob = bytearray(encrypt_vault(_PW, b"{}"))
    blob[len(MAGIC)] = 99
    with pytest.raises(VaultCryptoError, match="Unsupported vault format version"):
        decrypt_vault(_PW, bytes(blob))


def test_decrypt_tampered_ciphertext():
    blob = bytearray(encrypt_vault(_PW, b'{"x":1}'))
    blob[-1] ^= 0xFF
    with pytest.raises(VaultCryptoError, match="wrong password or corrupt"):
        decrypt_vault(_PW, bytes(blob))
