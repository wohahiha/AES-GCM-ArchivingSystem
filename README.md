# AES-GCM Archiving System

This repository contains a small command-line prototype for private document archiving with AES-GCM authenticated encryption and Merkle-based integrity checking.

It is built as an experimental system: the code creates an archive directory, encrypts files into authenticated chunks, records chunk metadata in a manifest, verifies the archive before recovery, and runs tamper-detection and benchmark experiments.

## What is implemented

- Archive creation with a JSON manifest and encrypted chunk storage.
- Password-based key derivation with PBKDF2-HMAC-SHA256.
- Key separation with HKDF-SHA256.
- AES-256-GCM chunk encryption with a fresh nonce for each chunk.
- Associated data binding for archive, file, chunk, size, and version context.
- Chunk hash records and Merkle root verification.
- Manifest authentication with HMAC.
- CLI commands for create, encrypt, list, verify, decrypt, and tamper-test.
- Pytest coverage for crypto behavior, archive flow, tamper checks, and wrong-password handling.
- Reproducible demo and benchmark scripts.

## Requirements

- Python 3.11 or newer
- Windows PowerShell for the bundled demo script

The prototype was developed and tested with Python 3.13.

## Setup

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -e ".[test]"
```

## Basic CLI flow

Create a vault:

```powershell
.\.venv\Scripts\python -m archive_tool.main create vault --password test123
```

Encrypt the sample file:

```powershell
.\.venv\Scripts\python -m archive_tool.main encrypt vault demo_files\plain.txt --password test123
```

List archived files:

```powershell
.\.venv\Scripts\python -m archive_tool.main list vault
```

Verify archive integrity:

```powershell
.\.venv\Scripts\python -m archive_tool.main verify vault --password test123
```

Decrypt a file:

```powershell
.\.venv\Scripts\python -m archive_tool.main decrypt vault <file_id> outputs\recovered.txt --password test123
```

## Tests and experiments

Run the automated tests:

```powershell
.\.venv\Scripts\python -m pytest
```

Run the reproducible demo:

```powershell
.\scripts\run_demo.ps1
```

Run the file-size benchmark:

```powershell
.\.venv\Scripts\python scripts\benchmark.py
```

Run the chunk-size benchmark:

```powershell
.\.venv\Scripts\python scripts\chunk_size_benchmark.py
```

Generated archives, recovered files, tamper-test copies, benchmark CSV files, and logs are written under ignored output directories.

## Repository layout

```text
src/archive_tool/      CLI and archive implementation
tests/                 Unit and flow tests
scripts/               Demo and benchmark scripts
demo_files/            Small sample input file
```

Released under the MIT License.
