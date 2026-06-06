from __future__ import annotations

import json

from archive_tool.archive import add_file, create_archive, decrypt_file, run_tamper_tests, verify_archive
from archive_tool.manifest import load_manifest, manifest_path
from archive_tool.merkle import sha256_hex


def test_archive_encrypt_verify_decrypt_roundtrip(tmp_path) -> None:
    vault = tmp_path / "vault"
    plain = tmp_path / "plain.txt"
    recovered = tmp_path / "recovered.txt"
    plain.write_text("hello archive\n" * 100, encoding="utf-8")

    create_archive(vault, "test123", chunk_size=64)
    record = add_file(vault, plain, "test123")

    assert verify_archive(vault, "test123").ok
    decrypt_file(vault, record["file_id"], recovered, "test123")
    assert sha256_hex(recovered.read_bytes()) == sha256_hex(plain.read_bytes())


def test_multi_chunk_file_roundtrip(tmp_path) -> None:
    vault = tmp_path / "vault"
    plain = tmp_path / "plain.txt"
    recovered = tmp_path / "recovered.txt"
    plain.write_text("multi chunk archive data\n" * 20, encoding="utf-8")

    create_archive(vault, "test123", chunk_size=32)
    record = add_file(vault, plain, "test123")

    assert record["chunk_count"] > 1
    assert verify_archive(vault, "test123").ok
    decrypt_file(vault, record["file_id"], recovered, "test123")
    assert sha256_hex(recovered.read_bytes()) == sha256_hex(plain.read_bytes())


def test_modified_chunk_fails_verify(tmp_path) -> None:
    vault = tmp_path / "vault"
    plain = tmp_path / "plain.txt"
    plain.write_text("tamper me\n" * 20, encoding="utf-8")

    create_archive(vault, "test123", chunk_size=32)
    record = add_file(vault, plain, "test123")
    chunk_path = vault / record["chunks"][0]["path"]
    data = bytearray(chunk_path.read_bytes())
    data[-1] ^= 0x01
    chunk_path.write_bytes(bytes(data))

    report = verify_archive(vault, "test123")
    assert not report.ok
    assert any("leaf hash mismatch" in issue for issue in report.issues)


def test_deleted_chunk_fails_verify(tmp_path) -> None:
    vault = tmp_path / "vault"
    plain = tmp_path / "plain.txt"
    plain.write_text("delete me\n" * 20, encoding="utf-8")

    create_archive(vault, "test123", chunk_size=32)
    record = add_file(vault, plain, "test123")
    (vault / record["chunks"][0]["path"]).unlink()

    report = verify_archive(vault, "test123")
    assert not report.ok
    assert any("missing chunk" in issue for issue in report.issues)


def test_manifest_change_fails_verify(tmp_path) -> None:
    vault = tmp_path / "vault"
    plain = tmp_path / "plain.txt"
    plain.write_text("manifest tamper\n", encoding="utf-8")

    create_archive(vault, "test123", chunk_size=32)
    add_file(vault, plain, "test123")
    manifest = load_manifest(vault)
    manifest["files"][0]["original_name"] = "changed.txt"
    manifest_path(vault).write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    report = verify_archive(vault, "test123")
    assert not report.ok
    assert report.issues == ["manifest HMAC verification failed"]


def test_replaced_chunk_fails_verify(tmp_path) -> None:
    vault = tmp_path / "vault"
    plain = tmp_path / "plain.txt"
    plain.write_text("replace chunk\n" * 20, encoding="utf-8")

    create_archive(vault, "test123", chunk_size=32)
    record = add_file(vault, plain, "test123")
    assert record["chunk_count"] > 1
    first = vault / record["chunks"][0]["path"]
    second = vault / record["chunks"][1]["path"]
    first.write_bytes(second.read_bytes())

    report = verify_archive(vault, "test123")
    assert not report.ok
    assert any("leaf hash mismatch" in issue for issue in report.issues)


def test_swapped_chunk_files_fail_verify(tmp_path) -> None:
    vault = tmp_path / "vault"
    plain = tmp_path / "plain.txt"
    plain.write_text("swap chunk\n" * 20, encoding="utf-8")

    create_archive(vault, "test123", chunk_size=32)
    record = add_file(vault, plain, "test123")
    assert record["chunk_count"] > 1
    first = vault / record["chunks"][0]["path"]
    second = vault / record["chunks"][1]["path"]
    first_data = first.read_bytes()
    second_data = second.read_bytes()
    first.write_bytes(second_data)
    second.write_bytes(first_data)

    report = verify_archive(vault, "test123")
    assert not report.ok
    assert sum("leaf hash mismatch" in issue for issue in report.issues) >= 2


def test_wrong_password_fails_manifest_verification(tmp_path) -> None:
    vault = tmp_path / "vault"
    plain = tmp_path / "plain.txt"
    plain.write_text("wrong password\n", encoding="utf-8")

    create_archive(vault, "test123", chunk_size=32)
    add_file(vault, plain, "test123")

    report = verify_archive(vault, "wrong-password")
    assert not report.ok
    assert report.issues == ["manifest HMAC verification failed"]


def test_tamper_test_reports_expected_cases(tmp_path) -> None:
    vault = tmp_path / "vault"
    plain = tmp_path / "plain.txt"
    plain.write_text("tamper test cases\n" * 20, encoding="utf-8")

    create_archive(vault, "test123", chunk_size=32)
    add_file(vault, plain, "test123")

    results = run_tamper_tests(vault, "test123", tmp_path / "tamper_cases")
    assert set(results) == {
        "modify-chunk",
        "delete-chunk",
        "replace-chunk",
        "swap-chunk-files",
        "modify-manifest",
        "wrong-password",
    }
    assert all(not report.ok for report in results.values())
