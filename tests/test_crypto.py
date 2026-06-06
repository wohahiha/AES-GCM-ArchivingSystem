from __future__ import annotations

import copy

import pytest

from archive_tool.crypto import decrypt_chunk, derive_keys, encrypt_chunk, generate_salt
from archive_tool.manifest import new_manifest, sign_manifest, verify_manifest_mac
from archive_tool.merkle import leaf_hash, merkle_root


def test_aes_gcm_roundtrip_and_aad_failure() -> None:
    keys = derive_keys("test-password", generate_salt(), 10_000)
    aad = b'{"chunk_index":0}'
    nonce, ciphertext = encrypt_chunk(keys.encryption_key, b"plain text", aad)

    assert decrypt_chunk(keys.encryption_key, nonce, ciphertext, aad) == b"plain text"
    with pytest.raises(ValueError):
        decrypt_chunk(keys.encryption_key, nonce, ciphertext, b'{"chunk_index":1}')


def test_merkle_root_changes_when_leaf_changes() -> None:
    leaf1 = leaf_hash("file-a", 0, b"0" * 12, b"ciphertext-a")
    leaf2 = leaf_hash("file-a", 1, b"1" * 12, b"ciphertext-b")
    original = merkle_root([leaf1, leaf2])
    tampered = merkle_root([leaf1, leaf_hash("file-a", 1, b"1" * 12, b"changed")])

    assert merkle_root([leaf1, leaf2]) == original
    assert tampered != original


def test_manifest_hmac_detects_manifest_change() -> None:
    keys = derive_keys("test-password", generate_salt(), 10_000)
    manifest = new_manifest(password_salt=b"fixed-salt-123456", chunk_size=1024)
    signed = sign_manifest(manifest, keys.manifest_key)

    assert verify_manifest_mac(signed, keys.manifest_key)
    changed = copy.deepcopy(signed)
    changed["archive_id"] = "tampered"
    assert not verify_manifest_mac(changed, keys.manifest_key)

