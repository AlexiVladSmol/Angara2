#!/usr/bin/env python3
"""M10 cache load evidence on the installed Linux binary.

Runs a private proxy process with cache enabled, a loopback origin and 10/20
concurrent clients. The report includes cache counters and process RSS.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

BODY = b"x" * (64 * 1024)
ORIGIN_PATH = "/cache"
EVICTION_REQUESTS = 128


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Cache-Control", "max-age=3600")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)


def rss_kib(pid: int) -> int:
    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    raise SystemExit("VmRSS missing")


def wait_port(host: str, port: int) -> None:
    for _ in range(100):
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise SystemExit(f"port did not open: {host}:{port}")


def read_response(reader) -> tuple[int, bytes]:
    status_line = reader.readline()
    if not status_line:
        raise RuntimeError("connection closed before status")
    parts = status_line.split()
    if len(parts) < 2:
        raise RuntimeError(f"bad status line: {status_line!r}")
    status = int(parts[1])
    length = 0
    while True:
        line = reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    body = reader.read(length) if length else b""
    return status, body


def run_client(proxy_port: int, origin_port: int, count: int, errors: list[str]) -> int:
    host = f"127.0.0.1:{origin_port}"
    request = (
        f"GET http://{host}{ORIGIN_PATH} HTTP/1.1\r\n"
        f"Host: {host}\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as sock:
            reader = sock.makefile("rb")
            for _ in range(count):
                sock.sendall(request)
                status, body = read_response(reader)
                if status != 200 or body != BODY:
                    errors.append(f"status={status} body={len(body)}")
                    return 0
        return count
    except Exception as error:  # noqa: BLE001 - report the client failure
        errors.append(str(error))
        return 0


def run_unique_cohort(
    proxy_port: int, origin_port: int, count: int
) -> tuple[int, float]:
    host = f"127.0.0.1:{origin_port}"
    started = time.monotonic()
    completed = 0
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as sock:
            reader = sock.makefile("rb")
            for index in range(count):
                request = (
                    f"GET http://{host}/evict?{index} HTTP/1.1\r\n"
                    f"Host: {host}\r\n\r\n"
                ).encode()
                sock.sendall(request)
                status, body = read_response(reader)
                if status != 200 or body != BODY:
                    raise RuntimeError(
                        f"eviction request {index}: status={status} body={len(body)}"
                    )
                completed += 1
    except Exception as error:  # noqa: BLE001 - report the client failure
        raise SystemExit(f"eviction cohort failed: {error}") from error
    return completed, time.monotonic() - started


def run_cohort(proxy_port: int, origin_port: int, clients: int, count: int) -> tuple[int, float]:
    errors: list[str] = []
    results: list[int] = []
    started = time.monotonic()
    threads = [
        threading.Thread(
            target=lambda: results.append(
                run_client(proxy_port, origin_port, count, errors)
            )
        )
        for _ in range(clients)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.monotonic() - started
    if errors:
        raise SystemExit(f"{clients}-client cohort failed: {errors[:3]}")
    return sum(results), elapsed


def last_metrics(path: Path) -> dict:
    metrics = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("event") == "metrics_summary" and isinstance(
            record.get("metrics"), dict
        ):
            metrics = record["metrics"]
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", default=os.environ.get("M08_BIN", "/usr/local/bin/angara"))
    parser.add_argument("--report-dir", type=Path, default=Path("m08-reports"))
    parser.add_argument("--proxy-port", type=int, default=3130)
    parser.add_argument("--origin-port", type=int, default=18081)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--max-rss-growth-kib", type=int, default=16 * 1024)
    args = parser.parse_args()
    args.report_dir.mkdir(parents=True, exist_ok=True)

    origin = http.server.ThreadingHTTPServer(("127.0.0.1", args.origin_port), Handler)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    with tempfile.TemporaryDirectory(prefix="angara-cache-load-") as tmp:
        tmp_path = Path(tmp)
        log = tmp_path / "proxy.log"
        config = tmp_path / "proxy.toml"
        config.write_text(
            f"""schema_version = 1

[runtime]
worker_threads = 2

[limits]
max_connections = 256
max_client_connections = 128
max_header_bytes = 32768
header_read_timeout_ms = 5000
idle_timeout_ms = 60000
shutdown_timeout_ms = 5000

[[listeners]]
id = "proxy"
bind = "127.0.0.1:{args.proxy_port}"
transport = "http"

[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true

[transport]
total_timeout_ms = 5000
connect_timeout_ms = 2000
max_connect_attempts = 2
max_connecting = 64

[http]
max_headers = 100
response_header_timeout_ms = 5000
pool_max_idle = 32
pool_max_idle_per_key = 2
pool_idle_timeout_ms = 15000

[[egress]]
id = "system"
mode = "system"

[routing]
default_egress = "system"

[observability]
metrics_enabled = true
metrics_interval_ms = 1000

[cache]
enabled = true
max_bytes = 1048576
max_object_bytes = 262144
max_entries = 64
max_fills = 8
""",
            encoding="utf-8",
        )
        with log.open("wb") as stderr:
            proxy = subprocess.Popen(
                [args.bin, "serve", "--config", str(config)],
                stdout=subprocess.DEVNULL,
                stderr=stderr,
            )
        try:
            wait_port("127.0.0.1", args.proxy_port)
            # Warm one representation and keep allocator high-water marks out
            # of the first measured cohort.
            run_client(args.proxy_port, args.origin_port, 1, [])
            baseline = rss_kib(proxy.pid)

            cohorts = []
            peak = baseline
            for clients in (10, 20):
                completed, elapsed = run_cohort(
                    args.proxy_port, args.origin_port, clients, args.requests
                )
                current = rss_kib(proxy.pid)
                peak = max(peak, current)
                cohorts.append(
                    {
                        "clients": clients,
                        "requests": completed,
                        "elapsed_s": round(elapsed, 3),
                        "rss_kib": current,
                    }
                )

            time.sleep(2)
            metrics = last_metrics(log)
            after = rss_kib(proxy.pid)
            growth = after - baseline

            eviction_completed, eviction_elapsed = run_unique_cohort(
                args.proxy_port, args.origin_port, EVICTION_REQUESTS
            )
            time.sleep(2)
            eviction_metrics = last_metrics(log)
            eviction_after = rss_kib(proxy.pid)
            eviction_growth = eviction_after - baseline
            report = {
                "result": "pass",
                "requests_per_client": args.requests,
                "cohorts": cohorts,
                "resources": {
                    "baseline_rss_kib": baseline,
                    "peak_rss_kib": max(peak, eviction_after),
                    "after_rss_kib": eviction_after,
                    "growth_kib": eviction_growth,
                },
                "eviction": {
                    "requests": eviction_completed,
                    "elapsed_s": round(eviction_elapsed, 3),
                    "cache_eviction": eviction_metrics.get("cache_eviction", 0),
                    "cache_entries": eviction_metrics.get("cache_entries", 0),
                    "after_rss_kib": eviction_after,
                    "growth_kib": eviction_growth,
                },
                "cache": {
                    key: metrics.get(key, 0)
                    for key in (
                        "cache_hit",
                        "cache_miss",
                        "cache_bypass",
                        "cache_revalidation",
                        "cache_eviction",
                        "cache_fill_refusals",
                        "cache_entries",
                        "cache_bytes",
                    )
                },
            }
            expected = 1 + (10 + 20) * args.requests
            failures = []
            if metrics.get("cache_hit", 0) < expected - 1:
                failures.append(f"cache_hit={metrics.get('cache_hit')} expected>={expected - 1}")
            if metrics.get("cache_miss") != 1:
                failures.append(f"cache_miss={metrics.get('cache_miss')} expected=1")
            if metrics.get("cache_entries") != 1:
                failures.append(f"cache_entries={metrics.get('cache_entries')} expected=1")
            if growth > args.max_rss_growth_kib:
                failures.append(
                    f"RSS growth {growth} KiB exceeds {args.max_rss_growth_kib} KiB"
                )
            if eviction_metrics.get("cache_eviction", 0) <= 0:
                failures.append("eviction cohort did not evict a cache entry")
            if eviction_metrics.get("cache_entries", 0) > 64:
                failures.append(
                    f"eviction cache_entries={eviction_metrics.get('cache_entries')} expected<=64"
                )
            if eviction_growth > args.max_rss_growth_kib:
                failures.append(
                    f"eviction RSS growth {eviction_growth} KiB exceeds {args.max_rss_growth_kib} KiB"
                )
            if failures:
                report["result"] = "fail"
                report["failures"] = failures
            (args.report_dir / "cache-load.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            print(json.dumps(report, indent=2), flush=True)
            if failures:
                raise SystemExit("; ".join(failures))
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait()
            origin.shutdown()


if __name__ == "__main__":
    main()
