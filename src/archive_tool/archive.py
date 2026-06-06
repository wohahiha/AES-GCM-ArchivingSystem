from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from .crypto import b64decode, b64encode, decrypt_chunk, derive_keys, encrypt_chunk
from .manifest import (
    ALGORITHM_VERSION,
    DEFAULT_CHUNK_SIZE,
    canonical_json_bytes,
    kdf_iterations,
    kdf_salt,
    load_manifest,
    manifest_path,
    new_manifest,
    save_manifest,
    sign_manifest,
    utc_now,
    verify_manifest_mac,
)
from .merkle import leaf_hash, merkle_root, sha256_hex


@dataclass
class VerifyReport:
    ok: bool
    issues: list[str]


def _vault_chunks_dir(vault_path: Path) -> Path:
    return vault_path / "chunks"


def _derive_from_manifest(password: str, manifest: dict) -> tuple[bytes, bytes]:
    keys = derive_keys(password, kdf_salt(manifest), kdf_iterations(manifest))
    return keys.encryption_key, keys.manifest_key


def _chunk_aad(
    manifest: dict,
    file_id: str,
    chunk_index: int,
    chunk_size: int,
    plaintext_size: int,
    file_version: int = 1,
) -> bytes:
    return canonical_json_bytes(
        {
            "archive_id": manifest["archive_id"],
            "file_id": file_id,
            "file_version": file_version,
            "chunk_index": chunk_index,
            "chunk_size": chunk_size,
            "plaintext_size": plaintext_size,
            "algorithm_version": ALGORITHM_VERSION,
        }
    )


def _file_record(manifest: dict, file_id: str) -> dict:
    for record in manifest.get("files", []):
        if record.get("file_id") == file_id:
            return record
    raise KeyError(f"file_id not found: {file_id}")


def create_archive(vault_path: Path, password: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> dict:
    if manifest_path(vault_path).exists():
        raise FileExistsError(f"archive already exists: {vault_path}")
    vault_path.mkdir(parents=True, exist_ok=True)
    _vault_chunks_dir(vault_path).mkdir(parents=True, exist_ok=True)
    manifest = new_manifest(chunk_size=chunk_size)
    _, manifest_key = _derive_from_manifest(password, manifest)
    signed = sign_manifest(manifest, manifest_key)
    save_manifest(vault_path, signed)
    return signed


def add_file(vault_path: Path, input_file: Path, password: str) -> dict:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    manifest = load_manifest(vault_path)
    encryption_key, manifest_key = _derive_from_manifest(password, manifest)
    if not verify_manifest_mac(manifest, manifest_key):
        raise ValueError("manifest HMAC verification failed")

    file_id = uuid4().hex
    chunk_size = int(manifest["algorithm"]["chunk_size"])
    plaintext_size = input_file.stat().st_size
    file_dir = _vault_chunks_dir(vault_path) / file_id
    file_dir.mkdir(parents=True, exist_ok=False)

    chunks = []
    leaf_hashes = []
    import hashlib

    plain_hash = hashlib.sha256()
    with input_file.open("rb") as src:
        chunk_index = 0
        while True:
            plaintext = src.read(chunk_size)
            if not plaintext:
                break
            plain_hash.update(plaintext)
            aad = _chunk_aad(manifest, file_id, chunk_index, chunk_size, plaintext_size)
            nonce, ciphertext = encrypt_chunk(encryption_key, plaintext, aad)
            chunk_name = f"{chunk_index:06d}.chunk"
            chunk_path = file_dir / chunk_name
            chunk_path.write_bytes(nonce + ciphertext)
            current_leaf = leaf_hash(file_id, chunk_index, nonce, ciphertext)
            leaf_hashes.append(current_leaf)
            chunks.append(
                {
                    "index": chunk_index,
                    "path": f"chunks/{file_id}/{chunk_name}",
                    "nonce_b64": b64encode(nonce),
                    "ciphertext_size": len(ciphertext),
                    "leaf_hash": current_leaf,
                }
            )
            chunk_index += 1

    record = {
        "file_id": file_id,
        "original_name": input_file.name,
        "created_at": utc_now(),
        "file_version": 1,
        "plaintext_size": plaintext_size,
        "plaintext_sha256": plain_hash.hexdigest(),
        "chunk_size": chunk_size,
        "chunk_count": len(chunks),
        "merkle_root": merkle_root(leaf_hashes),
        "chunks": chunks,
    }
    manifest["files"].append(record)
    save_manifest(vault_path, sign_manifest(manifest, manifest_key))
    return record


def list_files(vault_path: Path, password: str) -> list[dict]:
    manifest = load_manifest(vault_path)
    _, manifest_key = _derive_from_manifest(password, manifest)
    if not verify_manifest_mac(manifest, manifest_key):
        raise ValueError("manifest HMAC verification failed")
    return manifest.get("files", [])


def verify_archive(vault_path: Path, password: str) -> VerifyReport:
    issues: list[str] = []
    manifest = load_manifest(vault_path)
    _, manifest_key = _derive_from_manifest(password, manifest)
    if not verify_manifest_mac(manifest, manifest_key):
        return VerifyReport(False, ["manifest HMAC verification failed"])

    for record in manifest.get("files", []):
        file_id = record["file_id"]
        computed_leaves: list[str] = []
        for chunk in sorted(record.get("chunks", []), key=lambda item: item["index"]):
            rel_path = Path(chunk["path"])
            chunk_path = vault_path / rel_path
            if not chunk_path.exists():
                issues.append(f"{file_id}: missing chunk {chunk['index']} at {chunk['path']}")
                continue
            data = chunk_path.read_bytes()
            if len(data) <= 12:
                issues.append(f"{file_id}: invalid chunk {chunk['index']} length")
                continue
            nonce, ciphertext = data[:12], data[12:]
            if b64encode(nonce) != chunk.get("nonce_b64"):
                issues.append(f"{file_id}: nonce mismatch in chunk {chunk['index']}")
            current_leaf = leaf_hash(file_id, int(chunk["index"]), nonce, ciphertext)
            computed_leaves.append(current_leaf)
            if current_leaf != chunk.get("leaf_hash"):
                issues.append(f"{file_id}: leaf hash mismatch in chunk {chunk['index']}")
        current_root = merkle_root(computed_leaves)
        if current_root != record.get("merkle_root"):
            issues.append(f"{file_id}: Merkle root mismatch")

    return VerifyReport(not issues, issues)


def decrypt_file(vault_path: Path, file_id: str, output_file: Path, password: str) -> Path:
    report = verify_archive(vault_path, password)
    if not report.ok:
        raise ValueError("archive verification failed: " + "; ".join(report.issues))

    manifest = load_manifest(vault_path)
    encryption_key, _ = _derive_from_manifest(password, manifest)
    record = _file_record(manifest, file_id)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("wb") as dst:
        for chunk in sorted(record["chunks"], key=lambda item: item["index"]):
            data = (vault_path / Path(chunk["path"])).read_bytes()
            nonce, ciphertext = data[:12], data[12:]
            aad = _chunk_aad(
                manifest,
                file_id,
                int(chunk["index"]),
                int(record["chunk_size"]),
                int(record["plaintext_size"]),
                int(record["file_version"]),
            )
            dst.write(decrypt_chunk(encryption_key, nonce, ciphertext, aad))
    if output_file.stat().st_size != int(record["plaintext_size"]):
        raise ValueError("recovered file size does not match manifest")
    if sha256_hex(output_file.read_bytes()) != record["plaintext_sha256"]:
        raise ValueError("recovered file SHA-256 does not match manifest")
    return output_file


def run_tamper_tests(vault_path: Path, password: str, output_root: Path | None = None) -> dict[str, VerifyReport]:
    output_root = output_root or (vault_path.parent / f"{vault_path.name}_tamper_cases")
    if output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True)

    cases: dict[str, VerifyReport] = {}
    case_names = [
        "modify-chunk",
        "delete-chunk",
        "replace-chunk",
        "swap-chunk-files",
        "modify-manifest",
        "wrong-password",
    ]
    for case in case_names:
        if case == "wrong-password":
            cases[case] = verify_archive(vault_path, password + "-wrong")
            continue

        case_dir = output_root / case
        shutil.copytree(vault_path, case_dir)
        manifest = load_manifest(case_dir)
        first_file = manifest["files"][0] if manifest.get("files") else None
        if first_file is None:
            cases[case] = VerifyReport(False, ["no archived files to tamper"])
            continue
        first_chunk = first_file["chunks"][0]
        second_chunk = first_file["chunks"][1] if len(first_file.get("chunks", [])) > 1 else None
        chunk_path = case_dir / Path(first_chunk["path"])
        if case == "modify-chunk":
            data = bytearray(chunk_path.read_bytes())
            data[-1] ^= 0x01
            chunk_path.write_bytes(bytes(data))
        elif case == "delete-chunk":
            chunk_path.unlink()
        elif case == "replace-chunk":
            if second_chunk is None:
                cases[case] = VerifyReport(False, ["not enough chunks to replace"])
                continue
            replacement_path = case_dir / Path(second_chunk["path"])
            chunk_path.write_bytes(replacement_path.read_bytes())
        elif case == "swap-chunk-files":
            if second_chunk is None:
                cases[case] = VerifyReport(False, ["not enough chunks to swap"])
                continue
            second_path = case_dir / Path(second_chunk["path"])
            first_data = chunk_path.read_bytes()
            second_data = second_path.read_bytes()
            chunk_path.write_bytes(second_data)
            second_path.write_bytes(first_data)
        elif case == "modify-manifest":
            manifest["files"][0]["original_name"] = "tampered-name.txt"
            manifest_path(case_dir).write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        cases[case] = verify_archive(case_dir, password)
    return cases
