from __future__ import annotations

import argparse
from pathlib import Path

from .archive import add_file, create_archive, decrypt_file, list_files, run_tamper_tests, verify_archive
from .manifest import DEFAULT_CHUNK_SIZE


def _password_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--password", required=True, help="archive password; kept visible for demo automation")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AES-GCM and Merkle based archiving prototype")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="create a new encrypted archive")
    create.add_argument("vault", type=Path)
    create.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    _password_arg(create)

    encrypt = sub.add_parser("encrypt", help="encrypt and import a file")
    encrypt.add_argument("vault", type=Path)
    encrypt.add_argument("input_file", type=Path)
    _password_arg(encrypt)

    decrypt = sub.add_parser("decrypt", help="decrypt an archived file")
    decrypt.add_argument("vault", type=Path)
    decrypt.add_argument("file_id")
    decrypt.add_argument("output_file", type=Path)
    _password_arg(decrypt)

    verify = sub.add_parser("verify", help="verify archive integrity")
    verify.add_argument("vault", type=Path)
    _password_arg(verify)

    list_cmd = sub.add_parser("list", help="list archived files")
    list_cmd.add_argument("vault", type=Path)
    _password_arg(list_cmd)

    tamper = sub.add_parser("tamper-test", help="copy an archive and run tamper checks")
    tamper.add_argument("vault", type=Path)
    tamper.add_argument("--output-root", type=Path)
    _password_arg(tamper)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "create":
        manifest = create_archive(args.vault, args.password, args.chunk_size)
        print(f"created archive: {args.vault}")
        print(f"archive_id: {manifest['archive_id']}")
        return 0

    if args.command == "encrypt":
        record = add_file(args.vault, args.input_file, args.password)
        print(f"encrypted: {args.input_file}")
        print(f"file_id: {record['file_id']}")
        print(f"chunks: {record['chunk_count']}")
        print(f"merkle_root: {record['merkle_root']}")
        return 0

    if args.command == "decrypt":
        output = decrypt_file(args.vault, args.file_id, args.output_file, args.password)
        print(f"decrypted to: {output}")
        return 0

    if args.command == "verify":
        report = verify_archive(args.vault, args.password)
        if report.ok:
            print("verify: OK")
            return 0
        print("verify: FAILED")
        for issue in report.issues:
            print(f"- {issue}")
        return 1

    if args.command == "list":
        for record in list_files(args.vault, args.password):
            print(
                f"{record['file_id']}  {record['original_name']}  "
                f"{record['plaintext_size']} bytes  {record['chunk_count']} chunks"
            )
        return 0

    if args.command == "tamper-test":
        results = run_tamper_tests(args.vault, args.password, args.output_root)
        failed_count = 0
        for case, report in results.items():
            status = "detected" if not report.ok else "not detected"
            print(f"{case}: {status}")
            for issue in report.issues:
                print(f"  - {issue}")
            if report.ok:
                failed_count += 1
        return 1 if failed_count else 0

    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())

