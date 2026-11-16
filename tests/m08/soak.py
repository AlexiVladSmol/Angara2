#!/usr/bin/env python3
"""Hour-scale 20-client HTTP/HTTPS/CONNECT soak with reloads."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(command: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=check, capture_output=True, text=True)


def read_process(pid: int) -> dict[str, int] | None:
    if pid <= 0 or not Path(f"/proc/{pid}").is_dir():
        return None
    try:
        result: dict[str, int] = {}
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                result["rss_kib"] = int(line.split()[1])
            elif line.startswith("Threads:"):
                result["threads"] = int(line.split()[1])
        result["fds"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        return result
    except OSError:
        return None


def journal_cursor() -> str:
    result = run(
        ["journalctl", "-u", "angara.service", "-n", "0", "--show-cursor", "--no-pager"],
        check=False,
    )
    for line in result.stdout.splitlines():
        if line.startswith("-- cursor: "):
            return line.removeprefix("-- cursor: ")
    return ""


def wait_event(cursor: str, event: str, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cursor:
            result = run(
                [
                    "journalctl",
                    "-u",
                    "angara.service",
                    "--after-cursor",
                    cursor,
                    "-o",
                    "cat",
                    "--no-pager",
                ],
                check=False,
            )
        else:
            result = run(
                [
                    "journalctl",
                    "-u",
                    "angara.service",
                    "--since",
                    "30 seconds ago",
                    "-o",
                    "cat",
                    "--no-pager",
                ],
                check=False,
            )
        if f'"event":"{event}"' in result.stdout:
            return True
        time.sleep(0.1)
    return False


def atomic_write_config(path: Path, text: str) -> None:
    temp = Path(f"/etc/angara/.soak.{os.getpid()}")
    temp.write_text(text, encoding="utf-8")
    shutil.chown(temp, user="root", group="angara")
    os.chmod(temp, 0o640)
    os.replace(temp, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=3600)
    parser.add_argument("--batch-seconds", type=int, default=300)
    parser.add_argument("--warmup-seconds", type=int, default=120)
    parser.add_argument("--warmup-idle", type=int, default=30)
    parser.add_argument("--clients", type=int, default=20)
    parser.add_argument("--proxy-http", default="http://127.0.0.1:3128")
    parser.add_argument("--proxy-https", default="https://127.0.0.1:3129")
    parser.add_argument("--proxy-ca", required=True)
    parser.add_argument("--site", default="https://127.0.0.1:18443")
    parser.add_argument("--site-ca", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--origin-port", type=int, default=18080)
    parser.add_argument("--site-port", type=int, default=18443)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--batch-report-dir", type=Path)
    args = parser.parse_args()
    workdir = Path(
        args.workdir or tempfile.mkdtemp(prefix="angara-m08-soak-")
    )
    batch_dir = args.batch_report_dir or (workdir / "batches")
    batch_dir.mkdir(parents=True, exist_ok=True)
    config_path = Path("/etc/angara/angara.toml")
    valid_config = config_path.read_text(encoding="utf-8")
    script_dir = Path(__file__).resolve().parent
    batches = max(1, args.duration // args.batch_seconds)
    batch_seconds = args.duration // batches
    samples: list[dict[str, object]] = []
    reloads = {"applied": 0, "rejected": 0, "errors": []}
    batch_results: list[dict[str, object]] = []

    def load_command(seconds: int, report: Path) -> list[str]:
        return [
            sys.executable,
            str(script_dir / "load.py"),
            "--clients",
            str(args.clients),
            "--duration",
            str(seconds),
            "--warmup",
            "5",
            "--proxy-http",
            args.proxy_http,
            "--proxy-https",
            args.proxy_https,
            "--proxy-ca",
            args.proxy_ca,
            "--site",
            args.site,
            "--site-ca",
            args.site_ca,
            "--origin-port",
            str(args.origin_port),
            "--site-port",
            str(args.site_port),
            "--password-file",
            args.password_file,
            "--pid",
            str(args.pid),
            "--report",
            str(report),
            "--after-wait",
            "0",
            "--min-success",
            "1.0",
        ]

    try:
        # The threshold is relative to a warmed process, not the cold startup
        # allocator.  Run the same 20-client auth/TLS mix for two minutes,
        # let idle work settle, then record the warmed baseline.
        warmup_report = batch_dir / "warmup.json"
        warmup_started = time.monotonic()
        warmup = subprocess.run(
            load_command(args.warmup_seconds, warmup_report),
            capture_output=True,
            text=True,
        )
        print(
            f"soak warmup ok={warmup.returncode == 0} "
            f"elapsed={time.monotonic() - warmup_started:.1f}s",
            flush=True,
        )
        time.sleep(args.warmup_idle)
        baseline = read_process(args.pid)
        for batch in range(batches):
            batch_report = batch_dir / f"batch-{batch:02d}.json"
            command = load_command(batch_seconds, batch_report)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            accepted_at = max(10, int(batch_seconds * 0.35))
            rejected_at = max(accepted_at + 10, int(batch_seconds * 0.65))
            started = time.monotonic()
            accepted_done = False
            rejected_done = False
            while process.poll() is None:
                elapsed = time.monotonic() - started
                sample = read_process(args.pid)
                if sample is not None:
                    samples.append({"t": round(elapsed, 1), **sample})
                if not accepted_done and elapsed >= accepted_at:
                    atomic_write_config(config_path, valid_config)
                    cursor = journal_cursor()
                    run(["systemctl", "reload", "angara.service"], check=False)
                    if wait_event(cursor, "reload_applied"):
                        reloads["applied"] += 1
                    else:
                        reloads["errors"].append(f"batch {batch}: accepted reload not observed")
                    accepted_done = True
                if accepted_done and not rejected_done and elapsed >= rejected_at:
                    atomic_write_config(
                        config_path, "schema_version = 1\n[[listeners]]\n"
                    )
                    cursor = journal_cursor()
                    run(["systemctl", "reload", "angara.service"], check=False)
                    if wait_event(cursor, "reload_rejected"):
                        reloads["rejected"] += 1
                    else:
                        reloads["errors"].append(f"batch {batch}: rejected reload not observed")
                    atomic_write_config(config_path, valid_config)
                    cursor = journal_cursor()
                    run(["systemctl", "reload", "angara.service"], check=False)
                    if wait_event(cursor, "reload_applied"):
                        reloads["applied"] += 1
                    else:
                        reloads["errors"].append(f"batch {batch}: recovery reload not observed")
                    rejected_done = True
                time.sleep(1)
            stdout, stderr = process.communicate()
            batch_ok = process.returncode == 0
            batch_results.append(
                {
                    "batch": batch,
                    "seconds": batch_seconds,
                    "ok": batch_ok,
                    "stdout_tail": stdout[-2000:],
                    "stderr_tail": stderr[-2000:],
                }
            )
            print(f"soak batch={batch} ok={batch_ok}", flush=True)
        # Restore the valid file even if a batch failed mid-way.
        atomic_write_config(config_path, valid_config)
        time.sleep(30)
        after = read_process(args.pid)
        peak = {
            "rss_kib": max((item["rss_kib"] for item in samples), default=0),
            "fds": max((item["fds"] for item in samples), default=0),
            "threads": max((item["threads"] for item in samples), default=0),
        }
        threshold_ok = (
            peak["rss_kib"] <= 524288
            and after is not None
            and baseline is not None
            and after["fds"] <= baseline["fds"] + 8
            and after["rss_kib"] <= baseline["rss_kib"] + 65536
        )
        warmup_ok = warmup.returncode == 0
        report = {
            "result": "pass"
            if warmup_ok
            and threshold_ok
            and all(item["ok"] for item in batch_results)
            and not reloads["errors"]
            else "fail",
            "duration_s": args.duration,
            "clients": args.clients,
            "batch_seconds": batch_seconds,
            "warmup_seconds": args.warmup_seconds,
            "warmup": {
                "ok": warmup_ok,
                "stdout_tail": warmup.stdout[-2000:],
                "stderr_tail": warmup.stderr[-2000:],
            },
            "baseline": baseline,
            "peak": peak,
            "after": after,
            "samples": samples,
            "reloads": reloads,
            "batches": batch_results,
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "result": report["result"],
                    "warmup": report["warmup"],
                    "baseline": baseline,
                    "peak": peak,
                    "after": after,
                    "reloads": reloads,
                },
                indent=2,
            )
        )
        return 0 if report["result"] == "pass" else 1
    finally:
        try:
            atomic_write_config(config_path, valid_config)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
