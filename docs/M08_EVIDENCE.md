# M08 — acceptance map and evidence policy

This document is the static map from M08-r1 acceptance items to executable
checks. Actual measurements, failures and rerun reasons are attached to the
implementation PR and the CI run for the tested head; they are not pre-filled
here.

## F01–F11

| ID | Requirement | Check / evidence |
| --- | --- | --- |
| F01 | HTTP/1.1 forward proxy | `cargo test --locked`; systemd stand HTTP 200/upload/download/Range/HEAD; `tests/m08/functional.sh`, `tests/m08/load.py` |
| F02 | CONNECT with IPv4/IPv6/DNS | M04 suite; systemd stand CONNECT to controlled TLS site; wrong CA/name; `tests/m08/functional.sh` |
| F03 | HTTP and HTTPS listeners | systemd stand HTTP 3128 + HTTPS 3129; `tests/m08/functional.sh` |
| F04 | Basic auth and local users | systemd stand correct/wrong/missing credentials, 407/403; secret-marker scan; `tests/m08/functional.sh` |
| F05 | ACL by source/user/domain/IP/port/method | systemd stand allow/deny, origin accept counter; M02–M07 suites; `tests/m08/functional.sh` |
| F06 | Limits and timeouts | M03–M07 resource suites; `tests/m08/overload.sh`; `/proc/<pid>/limits` |
| F07 | TOML and `check` | `angara check` from service UID; invalid config reload; `tests/m08/systemd.sh` |
| F08 | JSON logs and metrics | M07 suite; journal JSON inspection; secret scan; `tests/m08/systemd.sh` |
| F09 | Graceful shutdown and reload | `tests/m08/systemd.sh`; M07 `cli_m07`/`m07_reload`; stop under load |
| F10 | systemd install from separate user | `tests/m08/install.sh`, `systemd.sh`, `boot.sh`; UID/groups/caps/limits |
| F11 | Multiple listeners and egress profiles | `tests/m08/network.sh` two veth/netns, source IP and failure without fallback |

## N01–N09

| ID | Requirement | Check / evidence |
| --- | --- | --- |
| N01 | Default deny | Initial loopback 403 with origin accept counter 0; M02/M03 ACL suites |
| N02 | Bounded resources | M03–M07 limits tests; `tests/m08/overload.sh`; RSS/FD/tasks series |
| N03 | Fault tolerance | Full M01–M07 regression; N03 corpus in CI; `tests/m08/overload.sh` |
| N04 | No secrets upstream/logs | M05/M07 secret tests; systemd journal/origin/artifact marker scan |
| N05 | Build provenance | manifest, external SHA-256, Cargo.lock hash, notices, deny job |
| N06 | Maintainability | task docs, runbook, deterministic script boundaries, review matrix |
| N07 | Predictable Linux behavior | clean/repeat install, start/reload/stop/restart, boot, config/port failures, A→B→A |
| N08 | Multiple CPUs | `tests/m08/load.py` / `workers.sh` with 1/2/4 workers where available; cpuset/quota recorded |
| N09 | Independence from TUI/web | No UI/admin listener added; existing M07 control API and CLI unchanged |

## M08 acceptance IDs

| ID | Check / evidence |
| --- | --- |
| M08-ART-01 | `packaging/build-release.sh`, `verify_manifest.py`, CI release artifact, target install without Rust |
| M08-SUP-01 | `manifest.json`, `THIRD_PARTY_NOTICES.md`, `provenance/ANGARA_PATCH.md`, `cargo deny check` |
| M08-INST-01 | `tests/m08/install.sh`: clean/repeat install, DESTDIR, unsafe path/corrupt archive rejection |
| M08-BOOT-01 | initial 403 + origin accept 0, then allowed request after config |
| M08-SVC-01 | `tests/m08/systemd.sh`: unit verify, PID/UID/groups/caps/sandbox/limits/readiness |
| M08-SVC-02 | `tests/m08/systemd.sh`: stop, restart, crash restart, start limit, config error, occupied port, boot enable |
| M08-REL-01 | `tests/m08/systemd.sh`: journal cursor, accepted/rejected reload, next request, keep-alive |
| M08-STOP-01 | `tests/m08/systemd.sh` + `overload.sh`: active HTTP/TLS/CONNECT, bytes, cgroup, ports, no SIGKILL |
| M08-UPD-01 | `tests/m08/upgrade.sh`: A→B→A, failed preflight, failed start, recovery, config hashes |
| M08-SEC-01 | `tests/m08/functional.sh`: both trust chains, Basic/ACL, UID isolation, secret scan |
| M08-NET-01 | `tests/m08/network.sh`: two veth/netns, origin source IPs, interface counters, removed address failure |
| M08-CPU-01 | `tests/m08/load.py`/`workers.sh`: 1/2/4 workers, cpuset/quota, thread CPU, throughput/latency |
| M08-LOAD-01 | `tests/m08/load.py`: 10/20 clients ≥60 s, mixed HTTP/HTTPS/CONNECT, all outcomes counted |
| M08-SOAK-01 | `tests/m08/soak.py`: 60-minute 20-client run linked to head and archive SHA-256 |
| M08-RES-01 | `tests/m08/streaming.sh` + `load.py` + `overload.sh`: 64 MiB/1 GiB hashes, RSS/FD thresholds, recovery |
| M08-ROB-01 | existing M01–M07 negative corpus + `tests/m08/overload.sh`; bounded time/size |
| M08-CI-01 | `.github/workflows/ci.yml` release/install/systemd/network/load jobs; artifact-to-stand path |
| M08-DOC-01 | this map, `docs/ADMIN_GUIDE.md`, `RELEASE_CHECKLIST.md`, executed commands, owner scenario |

## Load-profile password budget

`tests/m08/load_stand.sh` and `tests/m08/soak_stand.sh` use
`auth.max_verifying = 16` for the synthetic 10/20-client Basic cohorts. The
production default remains `2`; the M05 admission contract and its tests are
unchanged. The larger test-only budget avoids turning the controlled request
rate into artificial 503 responses from the zero-queue Argon2 admission. The
actual outcome counts are attached to the CI run.

## Reporting rules

- Every result names the full head SHA and archive SHA-256.
- A skipped/unavailable systemd, veth, IPv6 or CPU resource is FAIL/BLOCKED,
  not a pass. The reason is recorded in the PR.
- Failed attempts and reruns are listed with their cause.
- Timeouts, environment errors and ignored mandatory checks are not green.
- Numbers are valid only for the described test profile; they are not
  production throughput promises.
