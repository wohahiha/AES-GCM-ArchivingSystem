from __future__ import annotations

import base64
import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_ITERATIONS = 200_000
KEY_LENGTH = 32
NONCE_LENGTH = 12


@dataclass(frozen=True)
class KeyMaterial:
    encryption_key: bytes
    manifest_key: bytes


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)


def derive_master_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _hkdf(master_key: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)


def derive_keys(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> KeyMaterial:
    master = derive_master_key(password, salt, iterations)
    return KeyMaterial(
        encryption_key=_hkdf(master, b"archive-tool:file-encryption:v1"),
        manifest_key=_hkdf(master, b"archive-tool:manifest-auth:v1"),
    )


def encrypt_chunk(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_chunk(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError("AES-GCM authentication failed") from exc


def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data, "sha256")


def verify_hmac(key: bytes, data: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(compute_hmac(key, data), expected)

