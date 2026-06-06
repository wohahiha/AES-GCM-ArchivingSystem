from __future__ import annotations

import csv
import shutil
import statistics
import time
from pathlib import Path

from archive_tool.archive import add_file, create_archive, decrypt_file, verify_archive

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = PROJECT_ROOT / "outputs" / "benchmark"
DATA_DIR = OUTPUT_DIR / "data"
RESULTS_CSV = OUTPUT_DIR / "benchmark_results.csv"
SUMMARY_MD = OUTPUT_DIR / "benchmark_summary.md"
PASSWORD = "benchmark123"
RUNS = 3
SIZES = [
    ("1KB", 1024),
    ("100KB", 100 * 1024),
    ("1MB", 1024 * 1024),
    ("10MB", 10 * 1024 * 1024),
]


def write_deterministic_file(path: Path, size: int) -> None:
    pattern = b"AES-GCM-MERKLE-BENCHMARK-DATA\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        remaining = size
        while remaining > 0:
            chunk = pattern[: min(len(pattern), remaining)]
            handle.write(chunk)
            remaining -= len(chunk)


def timed(action):
    start = time.perf_counter()
    result = action()
    return time.perf_counter() - start, result


def run_one(label: str, size: int, run_index: int) -> dict[str, str | int | float]:
    input_file = DATA_DIR / f"plain_{label}.bin"
    vault = OUTPUT_DIR / f"vault_{label}_{run_index}"
    recovered = OUTPUT_DIR / f"recovered_{label}_{run_index}.bin"
    if vault.exists():
        shutil.rmtree(vault)
    if recovered.exists():
        recovered.unlink()

    write_deterministic_file(input_file, size)
    create_archive(vault, PASSWORD)

    encrypt_seconds, record = timed(lambda: add_file(vault, input_file, PASSWORD))
    verify_seconds, report = timed(lambda: verify_archive(vault, PASSWORD))
    if not report.ok:
        raise RuntimeError(f"verify failed for {label}: {report.issues}")
    decrypt_seconds, _ = timed(lambda: decrypt_file(vault, record["file_id"], recovered, PASSWORD))

    return {
        "file_size_label": label,
        "file_size_bytes": size,
        "run_index": run_index,
        "chunk_count": record["chunk_count"],
        "encrypt_seconds": encrypt_seconds,
        "verify_seconds": verify_seconds,
        "decrypt_seconds": decrypt_seconds,
    }


def write_outputs(rows: list[dict[str, str | int | float]]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with RESULTS_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    grouped: dict[str, list[dict[str, str | int | float]]] = {}
    for row in rows:
        grouped.setdefault(str(row["file_size_label"]), []).append(row)

    lines = [
        "# Benchmark Summary",
        "",
        "| 文件大小 | 块数 | 平均加密耗时(s) | 平均校验耗时(s) | 平均解密耗时(s) |",
        "|---|---:|---:|---:|---:|",
    ]
    for label, group in grouped.items():
        chunk_count = int(group[0]["chunk_count"])
        encrypt_avg = statistics.mean(float(row["encrypt_seconds"]) for row in group)
        verify_avg = statistics.mean(float(row["verify_seconds"]) for row in group)
        decrypt_avg = statistics.mean(float(row["decrypt_seconds"]) for row in group)
        lines.append(
            f"| {label} | {chunk_count} | {encrypt_avg:.6f} | {verify_avg:.6f} | {decrypt_avg:.6f} |"
        )
    lines.extend(
        [
            "",
            f"- 每种文件大小运行次数：{RUNS}",
            "- 测试内容：创建归档后执行加密、完整性校验和解密恢复。",
            "- 结果用于课程论文第 3 章性能测试表格，具体数值与本机环境有关。",
        ]
    )
    SUMMARY_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    rows = []
    for label, size in SIZES:
        for run_index in range(1, RUNS + 1):
            rows.append(run_one(label, size, run_index))
    write_outputs(rows)
    print(f"benchmark csv: {RESULTS_CSV}")
    print(f"benchmark summary: {SUMMARY_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

