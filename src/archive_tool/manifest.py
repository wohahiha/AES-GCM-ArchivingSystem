from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .crypto import DEFAULT_ITERATIONS, b64decode, b64encode, compute_hmac, generate_salt, verify_hmac

SCHEMA_VERSION = 1
ALGORITHM_VERSION = "v1"
DEFAULT_CHUNK_SIZE = 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(manifest)
    payload.pop("manifest_mac", None)
    return payload


def manifest_bytes_for_mac(manifest: dict[str, Any]) -> bytes:
    return canonical_json_bytes(manifest_payload(manifest))


def new_manifest(password_salt: bytes | None = None, chunk_size: int = DEFAULT_CHUNK_SIZE) -> dict[str, Any]:
    salt = password_salt if password_salt is not None else generate_salt()
    return {
        "schema_version": SCHEMA_VERSION,
        "archive_id": uuid4().hex,
        "created_at": utc_now(),
        "algorithm": {
            "algorithm_version": ALGORITHM_VERSION,
            "aead": "AES-256-GCM",
            "hash": "SHA-256",
            "mac": "HMAC-SHA256",
            "kdf": "PBKDF2-HMAC-SHA256",
            "key_derivation": "HKDF-SHA256",
            "chunk_size": chunk_size,
        },
        "kdf": {
            "salt_b64": b64encode(salt),
            "iterations": DEFAULT_ITERATIONS,
            "length": 32,
        },
        "files": [],
    }


def manifest_path(vault_path: Path) -> Path:
    return vault_path / "manifest.json"


def load_manifest(vault_path: Path) -> dict[str, Any]:
    path = manifest_path(vault_path)
    if not path.exists():
        raise FileNotFoundError(f"manifest not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_manifest(vault_path: Path, manifest: dict[str, Any]) -> None:
    manifest_path(vault_path).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def sign_manifest(manifest: dict[str, Any], manifest_key: bytes) -> dict[str, Any]:
    signed = copy.deepcopy(manifest)
    mac = compute_hmac(manifest_key, manifest_bytes_for_mac(signed))
    signed["manifest_mac"] = {
        "algorithm": "HMAC-SHA256",
        "value_b64": b64encode(mac),
    }
    return signed


def verify_manifest_mac(manifest: dict[str, Any], manifest_key: bytes) -> bool:
    mac_record = manifest.get("manifest_mac")
    if not isinstance(mac_record, dict) or "value_b64" not in mac_record:
        return False
    expected = b64decode(mac_record["value_b64"])
    return verify_hmac(manifest_key, manifest_bytes_for_mac(manifest), expected)


def kdf_salt(manifest: dict[str, Any]) -> bytes:
    return b64decode(manifest["kdf"]["salt_b64"])


def kdf_iterations(manifest: dict[str, Any]) -> int:
    return int(manifest["kdf"]["iterations"])

