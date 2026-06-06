from __future__ import annotations

import hashlib


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leaf_hash(file_id: str, chunk_index: int, nonce: bytes, ciphertext: bytes) -> str:
    h = hashlib.sha256()
    h.update(file_id.encode("utf-8"))
    h.update(b"\x00")
    h.update(chunk_index.to_bytes(8, "big"))
    h.update(b"\x00")
    h.update(nonce)
    h.update(ciphertext)
    return h.hexdigest()


def merkle_root(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        return sha256_hex(b"")
    level = [bytes.fromhex(value) for value in leaf_hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()

