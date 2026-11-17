#!/usr/bin/env python3
"""M08 controlled-load driver.

Each logical client is one curl process with a bounded batch of requests.  The
script counts every observed outcome and never turns a timeout or missing
transfer into success.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from origin import pattern_hash  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clients", type=int, required=True)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--mix", choices=["mixed", "http"], default="mixed")
    parser.add_argument("--proxy-http", default="http://127.0.0.1:3128")
    parser.add_argument("--proxy-https", default="https://127.0.0.1:3129")
    parser.add_argument("--proxy-ca", default="")
    parser.add_argument("--site", default="https://127.0.0.1:18443")
    parser.add_argument("--site-ca", default="")
    parser.add_argument("--origin-port", type=int, default=18080)
    parser.add_argument("--site-port", type=int, default=18443)
    parser.add_argument("--password-file", default="")
    parser.add_argument("--pid", type=int, default=0)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--request-delay-ms", type=int, default=50)
    parser.add_argument("--min-success", type=float, default=1.0)
    parser.add_argument("--after-wait", type=int, default=20)
    parser.add_argument("--baseline-wait", type=int, default=20)
    parser.add_argument("--proxy-unit", default="angara.service")
    parser.add_argument("--metrics-wait", type=float, default=3.0)
    return parser.parse_args()


def read_password(path: str) -> str:
    if not path:
        raise SystemExit("--password-file is required for a mixed cohort")
    with open(path, "r", encoding="utf-8") as handle:
        value = handle.readline().rstrip("\n")
    if not value:
        raise SystemExit("password file is empty")
    return value


def write_curl_config(
    path: Path,
    proxy: str,
    proxy_ca: str,
    user: str | None,
    password: str,
    site_ca: str,
    url: str,
    count: int,
    report: bool = True,
) -> None:
    lines = ["silent", "show-error", 'noproxy = ""', f'proxy = "{proxy}"']
    if proxy_ca:
        lines.append(f'proxy-cacert = "{proxy_ca}"')
    if user:
        lines.append(f'proxy-user = "{user}:{password}"')
    if site_ca:
        lines.append(f'cacert = "{site_ca}"')
    lines.append(f"max-time = {max(5, args.request_delay_ms // 1000 + 10)}")
    if report:
        lines.extend(
            [
                'output = "/dev/null"',
                'write-out = "%{http_code} %{time_total}\\n"',
            ]
        )
    if url:
        lines.extend(f'url = "{url}"' for _ in range(count))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def read_process(pid: int) -> dict[str, int] | None:
    if pid <= 0 or not Path(f"/proc/{pid}").is_dir():
        return None
    result: dict[str, int] = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                result["rss_kib"] = int(line.split()[1])
            elif line.startswith("Threads:"):
                result["threads"] = int(line.split()[1])
        result["fds"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    except OSError:
        return None
    return result


def proxy_completed(unit: str) -> int | None:
    completed = subprocess.run(
        [
            "journalctl",
            "-u",
            unit,
            "--since",
            "10 minutes ago",
            "-o",
            "cat",
            "--no-pager",
        ],
        capture_output=True,
        text=True,
    )
    for line in reversed(completed.stdout.splitlines()):
        if '"event":"metrics_summary"' not in line:
            continue
        try:
            value = json.loads(line)
            metrics = value.get("metrics") or {}
            return int(metrics["http_completed"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None
    return None


def run_functional(
    workdir: Path,
    args: argparse.Namespace,
    password: str | None,
) -> dict[str, object]:
    result: dict[str, object] = {"attempts": 0, "errors": [], "checks": {}}
    upload = workdir / "upload.bin"
    upload.write_bytes(os.urandom(1024 * 1024))
    upload_sha = hashlib.sha256(upload.read_bytes()).hexdigest()
    expected_download = pattern_hash(1024 * 1024)

    def config_for(kind: str, name: str) -> Path:
        path = workdir / name
        if kind == "http":
            write_curl_config(
                path, args.proxy_http, "", None, "", "", "", 1, report=False
            )
        elif kind == "https":
            write_curl_config(
                path,
                args.proxy_https,
                args.proxy_ca,
                "alice",
                password or "",
                "",
                "",
                1,
                report=False,
            )
        else:
            write_curl_config(
                path,
                args.proxy_https,
                args.proxy_ca,
                "alice",
                password or "",
                args.site_ca,
                "",
                1,
                report=False,
            )
        return path

    def curl(config: Path, url: str, extra: list[str] | None = None) -> tuple[int, bytes]:
        result["attempts"] = int(result["attempts"]) + 1
        command = ["curl", "--config", str(config), "--noproxy", ""]
        command.extend(extra or [])
        command.extend(["-sS", "-o", str(workdir / "body"), "-w", "%{http_code}", url])
        completed = subprocess.run(command, capture_output=True, timeout=30)
        body = b""
        if (workdir / "body").exists():
            body = (workdir / "body").read_bytes()
        if completed.returncode != 0:
            result["errors"].append(
                f"curl exit {completed.returncode} for {url}: "
                f"{completed.stderr.decode(errors='replace').strip()[:200]}"
            )
            return 0, body
        try:
            return int(completed.stdout.decode().strip()), body
        except ValueError:
            result["errors"].append(f"curl produced no HTTP status for {url}")
            return 0, body

    for kind in ("http", "https", "connect"):
        if args.mix == "http" and kind != "http":
            continue
        name = f"{kind}.conf"
        config = config_for(kind, name)
        target = (
            f"https://127.0.0.1:{args.site_port}"
            if kind == "connect"
            else f"http://127.0.0.1:{args.origin_port}"
        )
        code, body = curl(config, f"{target}/")
        result["checks"][f"{kind}_get"] = code
        if code != 200 or b"m08-origin-ok" not in body:
            result["errors"].append(f"{kind} GET failed")
        code, _ = curl(config, f"{target}/range", ["-H", "Range: bytes=0-15"])
        result["checks"][f"{kind}_range"] = code
        if code != 206:
            result["errors"].append(f"{kind} Range failed")
        code, body = curl(
            config,
            f"{target}/download?bytes=1048576",
        )
        result["checks"][f"{kind}_download"] = code
        if code != 200:
            result["errors"].append(f"{kind} download failed")
        else:
            digest = hashlib.sha256(body).hexdigest()
            if digest != expected_download:
                result["errors"].append(f"{kind} download hash mismatch")
        code, body = curl(
            config,
            f"{target}/upload",
            ["--data-binary", f"@{upload}"],
        )
        result["checks"][f"{kind}_upload"] = code
        if code != 200:
            result["errors"].append(f"{kind} upload failed")
        else:
            try:
                value = json.loads(body)
                if value.get("received") != 1048576 or value.get("sha256") != upload_sha:
                    result["errors"].append(f"{kind} upload mismatch")
            except json.JSONDecodeError:
                result["errors"].append(f"{kind} upload response is not JSON")
    result["ok"] = not result["errors"]
    return result


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def main() -> int:
    global args
    args = parse_args()
    if args.clients < 1:
        raise SystemExit("--clients must be positive")
    if args.mix == "mixed" and (not args.proxy_ca or not args.site_ca):
        raise SystemExit("mixed cohort requires --proxy-ca and --site-ca")
    password = read_password(args.password_file) if args.mix == "mixed" else None
    workdir = Path(tempfile.mkdtemp(prefix="angara-m08-load-", dir=args.workdir))
    try:
        cold_before = read_process(args.pid)
        functional = run_functional(workdir, args, password)
        if not functional["ok"]:
            report = {
                "result": "fail",
                "functional": functional,
                "clients": args.clients,
            }
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(report, indent=2))
            return 1

        total = args.clients
        if args.mix == "http":
            assignments = ["http"] * total
        else:
            http_count = max(1, round(total * 0.4))
            https_count = max(1, round(total * 0.3))
            connect_count = total - http_count - https_count
            if connect_count < 1:
                connect_count = 1
                https_count = max(1, https_count - 1)
            assignments = ["http"] * http_count + ["https"] * https_count + [
                "connect"
            ] * connect_count
            assignments = assignments[:total]
        users = ["alice", "bob"]
        # The origin delay is a floor; local curl process/keep-alive overhead is
        # observable in the warmup.  Target roughly one request per two delay
        # windows so a 60 s cohort finishes near its intended wall-clock size.
        count = max(
            10,
            int(args.duration * 1000 / max(args.request_delay_ms * 2, 1)),
        )
        configs: list[Path] = []
        for index, kind in enumerate(assignments):
            if kind == "http":
                proxy, proxy_ca, site_ca, user = args.proxy_http, "", "", None
                url = f"http://127.0.0.1:{args.origin_port}/delay?ms={args.request_delay_ms}"
            elif kind == "https":
                proxy, proxy_ca, site_ca = args.proxy_https, args.proxy_ca, ""
                user = users[index % len(users)]
                url = f"http://127.0.0.1:{args.origin_port}/delay?ms={args.request_delay_ms}"
            else:
                proxy, proxy_ca, site_ca = args.proxy_https, args.proxy_ca, args.site_ca
                user = users[index % len(users)]
                url = f"https://127.0.0.1:{args.site_port}/delay?ms={args.request_delay_ms}"
            path = workdir / f"client-{index}.conf"
            write_curl_config(
                path, proxy, proxy_ca, user, password or "", site_ca, url, count
            )
            configs.append(path)

        # Warmup: a short batch per client, discarded from the reported result.
        warm_count = max(
            5,
            int(args.warmup * 1000 / max(args.request_delay_ms * 2, 1)),
        )
        warm_configs = []
        for index, config in enumerate(configs):
            warm = workdir / f"warm-{index}.conf"
            text = config.read_text(encoding="utf-8")
            # The warmup uses the same options with fewer URLs.
            options = [
                line
                for line in text.splitlines()
                if not line.startswith("url = ") and not line.startswith("write-out = ")
            ]
            urls = [line for line in text.splitlines() if line.startswith("url = ")]
            [url] = urls[:1]
            with warm.open("w", encoding="utf-8") as handle:
                handle.write("\n".join(options) + "\n")
                handle.write('write-out = "WARM %{http_code}\\n"\n')
                handle.write("\n".join([url] * warm_count) + "\n")
            os.chmod(warm, 0o600)
            warm_configs.append(warm)
        warm_start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=total) as pool:
            warm_processes = [
                pool.submit(subprocess.run, ["curl", "--config", str(path)],
                            capture_output=True, timeout=args.warmup + 60)
                for path in warm_configs
            ]
            for future in warm_processes:
                future.result()
        warm_elapsed = time.monotonic() - warm_start
        print(f"warmup clients={total} elapsed={warm_elapsed:.2f}s")
        time.sleep(args.baseline_wait)
        baseline = read_process(args.pid)
        proxy_before = proxy_completed(args.proxy_unit)
        print(
            f"warm baseline rss={baseline} proxy_http_completed={proxy_before}",
            flush=True,
        )

        processes: list[subprocess.Popen] = []
        started = time.monotonic()
        for index, config in enumerate(configs):
            output = workdir / f"client-{index}.out"
            error = workdir / f"client-{index}.err"
            out_handle = output.open("wb")
            err_handle = error.open("wb")
            processes.append(
                subprocess.Popen(
                    ["curl", "--config", str(config)],
                    stdout=out_handle,
                    stderr=err_handle,
                )
            )
            out_handle.close()
            err_handle.close()
        peak = baseline
        deadline = started + max(args.duration * 3, 180) + 60
        while any(process.poll() is None for process in processes):
            sample = read_process(args.pid)
            if sample is not None:
                if peak is None:
                    peak = sample
                else:
                    peak = {
                        "rss_kib": max(peak.get("rss_kib", 0), sample.get("rss_kib", 0)),
                        "fds": max(peak.get("fds", 0), sample.get("fds", 0)),
                        "threads": max(peak.get("threads", 0), sample.get("threads", 0)),
                    }
            if time.monotonic() > deadline:
                for process in processes:
                    process.kill()
                raise SystemExit("load clients exceeded the overall deadline")
            time.sleep(1)
        elapsed = time.monotonic() - started
        for process in processes:
            process.wait(timeout=5)
        client_exit_errors = [
            f"client {index}: curl exit {process.returncode}"
            for index, process in enumerate(processes)
            if process.returncode != 0
        ]

        codes: dict[str, int] = {}
        latencies: list[float] = []
        observed = 0
        for index in range(total):
            output = workdir / f"client-{index}.out"
            for line in output.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.strip().split()
                if len(parts) != 2:
                    continue
                code, seconds = parts
                observed += 1
                codes[code] = codes.get(code, 0) + 1
                try:
                    latencies.append(float(seconds) * 1000.0)
                except ValueError:
                    pass
        expected = total * count
        unexpected = {code: value for code, value in codes.items() if code != "200"}
        missing = expected - observed
        success = observed - sum(unexpected.values()) - max(missing, 0)
        success_ratio = success / expected if expected else 0.0
        duration_ok = elapsed >= args.duration * 0.85

        metrics_deadline = time.monotonic() + args.metrics_wait
        proxy_after = None
        proxy_delta = None
        while True:
            proxy_after = proxy_completed(args.proxy_unit)
            if proxy_before is not None and proxy_after is not None:
                proxy_delta = proxy_after - proxy_before
                if proxy_delta >= observed:
                    break
            if time.monotonic() >= metrics_deadline:
                break
            time.sleep(0.5)
        proxy_ok = (
            proxy_before is not None
            and proxy_after is not None
            and proxy_delta is not None
            and proxy_delta >= observed
        )

        time.sleep(args.after_wait)
        after = read_process(args.pid)
        peak_rss = (peak or {}).get("rss_kib", 0)
        peak_fds = (peak or {}).get("fds", 0)
        peak_fd_ok = (
            baseline is not None and peak_fds <= baseline["fds"] + 512
        )
        resource_ok = (
            peak is not None
            and peak_rss > 0
            and peak_rss <= 524288
            and peak_fd_ok
            and baseline is not None
            and after is not None
            and after["fds"] <= baseline["fds"] + 8
            and after["rss_kib"] <= baseline["rss_kib"] + 65536
        )
        report = {
            "result": "pass"
            if success_ratio >= args.min_success
            and missing == 0
            and not client_exit_errors
            and duration_ok
            and proxy_ok
            and resource_ok
            else "fail",
            "clients": total,
            "mix": args.mix,
            "duration_s": args.duration,
            "duration_ok": duration_ok,
            "expected_requests": expected,
            "observed_requests": observed,
            "missing_requests": missing,
            "unexpected_codes": unexpected,
            "codes": codes,
            "client_exit_errors": client_exit_errors,
            "proxy_path": {
                "unit": args.proxy_unit,
                "http_completed_before": proxy_before,
                "http_completed_after": proxy_after,
                "http_completed_delta": proxy_delta,
                "observed_requests": observed,
                "ok": proxy_ok,
            },
            "latency_ms": {
                "p50": round(percentile(latencies, 0.50), 3),
                "p95": round(percentile(latencies, 0.95), 3),
                "max": round(max(latencies), 3) if latencies else 0.0,
            },
            "throughput_rps": round(observed / elapsed, 3) if elapsed else 0.0,
            "elapsed_s": round(elapsed, 3),
            "functional": functional,
            "resources": {
                "cold": cold_before,
                "baseline": baseline,
                "peak": peak,
                "after": after,
                "peak_fds": peak_fds,
                "peak_fd_ok": peak_fd_ok,
                "ok": resource_ok,
            },
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 0 if report["result"] == "pass" else 1
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
