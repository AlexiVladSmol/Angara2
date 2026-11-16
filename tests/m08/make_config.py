#!/usr/bin/env python3
"""Generate strict TOML configurations for the M08 stand tests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def q(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def list_q(values: list[str]) -> str:
    return "[" + ", ".join(q(value) for value in values) + "]"


def list_int(values: list[int]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def parse_ports(value: str) -> list[int]:
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def parse_list(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mode", default="functional")
    parser.add_argument("--http-bind", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=3128)
    parser.add_argument("--http2-bind", default="127.0.0.2")
    parser.add_argument("--http2-port", type=int, default=3128)
    parser.add_argument("--https-bind", default="127.0.0.1")
    parser.add_argument("--https-port", type=int, default=0)
    parser.add_argument("--https2-bind", default="127.0.0.2")
    parser.add_argument("--https2-port", type=int, default=0)
    parser.add_argument("--site-port", type=int, default=18443)
    parser.add_argument("--extra-port", type=int, default=18081)
    parser.add_argument("--allow-ports", default="")
    parser.add_argument("--auth-http", choices=["none", "basic"], default="none")
    parser.add_argument("--auth-https", choices=["none", "basic"], default="basic")
    parser.add_argument("--https-users", default="alice")
    parser.add_argument("--users-file", default="")
    parser.add_argument("--tls-cert", default="")
    parser.add_argument("--tls-key", default="")
    parser.add_argument("--workers", default="2")
    parser.add_argument("--shutdown-ms", type=int, default=5000)
    parser.add_argument("--reload-ms", type=int, default=5000)
    parser.add_argument("--idle-ms", type=int, default=60000)
    parser.add_argument("--deny", action="store_true")
    parser.add_argument("--max-connections", type=int, default=256)
    parser.add_argument("--max-client-connections", type=int, default=128)
    parser.add_argument("--source-allow", default="127.0.0.0/8,::1/128")
    parser.add_argument("--ip-networks", default="127.0.0.0/8,::1/128")
    parser.add_argument("--egress-a", default="10.241.1.1")
    parser.add_argument("--egress-b", default="10.241.2.1")
    parser.add_argument("--log-level", default="info")
    parser.add_argument("--metrics-interval", type=int, default=1000)
    args = parser.parse_args()

    mode = args.mode
    if mode == "invalid":
        args.output.write_text("schema_version = 1\n[[listeners]\n", encoding="utf-8")
        return 0

    if mode == "default":
        args.output.write_text(
            f"""schema_version = 1

[runtime]
worker_threads = "auto"

[limits]
max_connections = 256
max_client_connections = 128
max_header_bytes = 32768
header_read_timeout_ms = 10000
idle_timeout_ms = 60000
shutdown_timeout_ms = {args.shutdown_ms}

[operations]
reload_timeout_ms = {args.reload_ms}

[observability]
log_level = "info"
log_queue_capacity = 1024
metrics_enabled = true
metrics_interval_ms = {args.metrics_interval}

[[listeners]]
id = "proxy-loopback"
bind = {q(f'{args.http_bind}:{args.http_port}')}
transport = "http"
auth = "none"

[access]
source_allow = ["127.0.0.0/8", "::1/128"]
ip_default = "deny"

[[egress]]
id = "system"
mode = "system"

[routing]
default_egress = "system"
""",
            encoding="utf-8",
        )
        return 0

    allow_ports = (
        parse_ports(args.allow_ports)
        if args.allow_ports
        else [18080, args.site_port]
    )
    if args.extra_port and args.extra_port not in allow_ports:
        allow_ports.append(args.extra_port)
    source_allow = parse_list(args.source_allow)
    ip_networks = parse_list(args.ip_networks)

    lines: list[str] = [
        "schema_version = 1",
        "",
        "[runtime]",
        f"worker_threads = {q(args.workers) if args.workers == 'auto' else args.workers}",
        "",
        "[limits]",
        f"max_connections = {args.max_connections}",
        f"max_client_connections = {args.max_client_connections}",
        "max_header_bytes = 32768",
        "header_read_timeout_ms = 10000",
        f"idle_timeout_ms = {args.idle_ms}",
        f"shutdown_timeout_ms = {args.shutdown_ms}",
        "",
        "[operations]",
        f"reload_timeout_ms = {args.reload_ms}",
        "",
        "[observability]",
        f"log_level = {q(args.log_level)}",
        "log_queue_capacity = 1024",
        "metrics_enabled = true",
        f"metrics_interval_ms = {args.metrics_interval}",
        "",
    ]

    if args.users_file:
        lines.extend(
            [
                "[auth]",
                f"users_file = {q(args.users_file)}",
                "max_verifying = 2",
                "verify_timeout_ms = 2000",
                "",
            ]
        )

    https_enabled = args.https_port > 0
    if https_enabled:
        lines.extend(
            [
                "[tls]",
                "max_handshaking = 32",
                "handshake_timeout_ms = 5000",
                "",
            ]
        )

    if mode == "network":
        listeners = [
            ("proxy-a", args.http_bind, args.http_port),
            ("proxy-b", args.http2_bind, args.http2_port),
        ]
    else:
        listeners = [("proxy-http", args.http_bind, args.http_port)]
        if https_enabled:
            listeners.append(("proxy-https", args.https_bind, args.https_port))
        if args.https2_port > 0:
            listeners.append(("proxy-https-alt", args.https2_bind, args.https2_port))

    for listener_id, bind_host, port in listeners:
        is_https = listener_id.startswith("proxy-https")
        lines.extend(
            [
                "[[listeners]]",
                f"id = {q(listener_id)}",
                f"bind = {q(f'{bind_host}:{port}')}",
                f"transport = {q('https' if is_https else 'http')}",
                f"auth = {q(args.auth_https if is_https else args.auth_http)}",
                "",
            ]
        )
        if is_https:
            lines.extend(
                [
                    "[listeners.tls]",
                    f"cert_chain_file = {q(args.tls_cert)}",
                    f"private_key_file = {q(args.tls_key)}",
                    "",
                ]
            )

    lines.extend(
        [
            "[access]",
            f"source_allow = {list_q(source_allow)}",
            'ip_default = "deny"',
            "",
        ]
    )

    if not args.deny:
        if mode == "network":
            lines.extend(
                [
                    "[[access.rules]]",
                    'id = "network-allow"',
                    'action = "allow"',
                    'listeners = ["proxy-a", "proxy-b"]',
                    'methods = ["GET", "HEAD", "POST", "CONNECT"]',
                    f"ports = {list_int(sorted(allow_ports))}",
                    "",
                ]
            )
        else:
            http_users = ["alice", "bob"] if args.auth_http == "basic" else []
            lines.extend(
                [
                    "[[access.rules]]",
                    'id = "http-allow"',
                    'action = "allow"',
                    'listeners = ["proxy-http"]',
                    'methods = ["GET", "HEAD", "POST"]',
                    f"ports = {list_int(sorted(allow_ports))}",
                ]
            )
            if http_users:
                lines.append(f"users = {list_q(http_users)}")
            lines.append("")
            if https_enabled:
                lines.extend(
                    [
                        "[[access.rules]]",
                        'id = "https-users"',
                        'action = "allow"',
                        'listeners = ["proxy-https"]',
                        f"users = {list_q(parse_list(args.https_users))}",
                        'methods = ["GET", "HEAD", "POST", "CONNECT"]',
                        f"ports = {list_int(sorted(allow_ports))}",
                        "",
                    ]
                )

    lines.extend(
        [
            "[[access.ip_rules]]",
            'id = "allow-test-networks"',
            'action = "allow"',
            f"networks = {list_q(ip_networks)}",
            "allow_special = true",
            "",
            "[dns]",
            "timeout_ms = 3000",
            "max_in_flight = 4",
            "max_answers = 16",
            "",
            "[transport]",
            "total_timeout_ms = 10000",
            "connect_timeout_ms = 3000",
            "max_connect_attempts = 3",
            "max_connecting = 32",
            "",
            "[http]",
            "max_headers = 100",
            "response_header_timeout_ms = 30000",
            "pool_max_idle = 16",
            "pool_max_idle_per_key = 2",
            "pool_idle_timeout_ms = 15000",
            "",
            "[connect]",
            f"allowed_ports = {list_int(sorted(set(allow_ports)))}",
            "half_close_timeout_ms = 5000",
            "",
        ]
    )

    if mode == "network":
        lines.extend(
            [
                "[[egress]]",
                'id = "egress-a"',
                'mode = "bind_ip"',
                f"bind_ip = {q(args.egress_a)}",
                "",
                "[[egress]]",
                'id = "egress-b"',
                'mode = "bind_ip"',
                f"bind_ip = {q(args.egress_b)}",
                "",
                "[routing]",
                'default_egress = "egress-a"',
                "",
                "[[routing.rules]]",
                'id = "listener-a"',
                'egress_id = "egress-a"',
                'listeners = ["proxy-a"]',
                "",
                "[[routing.rules]]",
                'id = "listener-b"',
                'egress_id = "egress-b"',
                'listeners = ["proxy-b"]',
                "",
            ]
        )
    else:
        lines.extend(
            [
                "[[egress]]",
                'id = "system"',
                'mode = "system"',
                "",
                "[routing]",
                'default_egress = "system"',
                "",
            ]
        )

    if mode == "unbindable":
        # A TEST-NET address is syntactically valid but not assigned to this
        # host, so check passes and serve fails at bind.
        text = "\n".join(lines)
        text = text.replace(
            f'bind = "127.0.0.1:{args.http_port}"',
            'bind = "192.0.2.123:3128"',
        )
        args.output.write_text(text, encoding="utf-8")
        return 0

    args.output.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
