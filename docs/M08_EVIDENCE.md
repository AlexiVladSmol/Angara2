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
| M08-BOOT-01 | initial 403 + origin accept 0, then allowed request after config; `tests/m08/vm_boot.sh` installs/enables in a disposable Ubuntu cloud VM, reboots, verifies autostart and 403 on the second boot |
| M08-SVC-01 | `tests/m08/systemd.sh`: unit verify, PID/UID/groups/caps/sandbox/limits/readiness; `angaractl` readiness is tied to MainPID/exe/listener |
| M08-SVC-02 | `tests/m08/systemd.sh`: stop, restart, crash restart, start limit, config error, occupied port, boot enable |
| M08-REL-01 | `tests/m08/systemd.sh`: journal cursor, accepted/rejected reload, next request, keep-alive |
| M08-STOP-01 | `tests/m08/systemd.sh` + `overload.sh`: active HTTP/TLS/CONNECT, bytes, cgroup, ports, no SIGKILL |
| M08-UPD-01 | `tests/m08/upgrade.sh`: distinguishable A/B unit/helper, TLS/Basic allowed origin traffic, A→B→A, failed preflight, failed start, foreign-listener readiness, recovery, config hashes |
| M08-SEC-01 | `tests/m08/functional.sh`: both trust chains, Basic/ACL, UID isolation, secret scan |
| M08-NET-01 | `tests/m08/network.sh`: two veth/netns, origin source IPs, interface counters, removed address failure |
| M08-CPU-01 | `tests/m08/load.py`/`workers.sh`: 1/2/4 workers, cpuset/quota, thread CPU, throughput/latency |
| M08-LOAD-01 | `tests/m08/load.py`: 10/20 clients ≥60 s, mixed HTTP/HTTPS/CONNECT, all outcomes counted |
| M08-SOAK-01 | `tests/m08/soak.py`: 60-minute 20-client run linked to head and archive SHA-256 |
| M08-RES-01 | `tests/m08/streaming.sh` + `load.py` + `overload.sh`: 64 MiB/1 GiB hashes, RSS/FD thresholds, recovery |
| M08-ROB-01 | existing M01–M07 raw/negative corpus via `cargo test --locked`; `tests/m08/overload.sh`: 100 concurrent auth attempts, 100 idle TCP connections, 50 TLS handshakes, 10 slow clients, 1 s client abort, DNS/connect failures and CONNECT stop under load; bounded inputs, no external network, cleanup asserted |
| M08-CI-01 | `.github/workflows/ci.yml` release/install/systemd/network/load jobs; artifact-to-stand path |
| M08-DOC-01 | this map, `docs/ADMIN_GUIDE.md`, `examples/m08-operations-https-basic.toml`, `RELEASE_CHECKLIST.md`; `tests/m08/admin_guide.sh` checks the shipped example, CA/407/allowed request and backup/restore from the archive |

## Review R1–R9 map

| ID | Defect | Change / executable evidence |
| --- | --- | --- |
| R1 | Archive could be swapped between hash check and extraction; stale release could be reused | `packaging/install.sh` and `packaging/angaractl` copy the archive once into a private 0600 file, verify that copy, and use it for every `tar`/manifest operation. Existing release trees are verified against the incoming manifest and compared byte-for-byte. `tests/m08/install.sh` swaps the source path after the hash check and rejects a modified existing manifest. CI verifies the external archive hash before extracting the installer. |
| R2 | DESTDIR/path escapes and foreign unit/helper/current/bin overwrite | `packaging/install.sh` rejects `..`, parent symlinks, group/world-writable managed directories, and foreign unit/helper/current/bin files before writing. `packaging/angaractl` applies the same checks before metadata activation. `tests/m08/install.sh` covers a parent symlink, a foreign unit/helper, and a `..` prefix. |
| R3 | Over-broad service account/group | `packaging/install.sh` adopts only a dedicated `angara` account with the matching closed group, no supplementary groups, no foreign members, and UID/GID other than 0. `tests/m08/install.sh` exercises fake NSS records for a foreign member, supplementary groups, and a valid account. |
| R4 | Candidate-only wrote active metadata; wrong activation order/rollback hint | `--candidate-only` now writes only `/opt/angara/releases/<id>`; unit/helper/config/symlinks are untouched. `angaractl` switches `current` before installing B metadata and restores A metadata after switching back. Auto-rollback no longer prints `rollback --confirm`; it reports the retry/recover command for the restored state. `tests/m08/upgrade.sh` checks distinguishable A/B unit/helper metadata and a post-switch failure. |
| R5 | Readiness accepted a foreign listener | `angaractl` requires the MainPID to be alive, `/proc/<pid>/exe` to resolve to the selected release, and the selected probe port to be owned by that PID before accepting the HTTP code. `tests/m08/upgrade.sh` places a foreign 407 server on the port and requires the upgrade to fail. |
| R6 | Proxy bypass, wet baseline, peak/soak omissions | `tests/m08/load.py` disables `NO_PROXY`, checks `metrics_summary.http_completed` growth, samples a warmed baseline, and includes peak RSS/FD plus post-load recovery in the pass condition. `tests/m08/soak.py` requires measured duration and all accepted/rejected/recovery reloads. `load_stand.sh`/`soak_stand.sh` set a 1 s metrics interval. |
| R7 | Network check bypassed the installed unit and did not prove DNS/IPv6/no-fallback | `tests/m08/network.sh` drives the installed `angara.service`, checks service UID/exe, resolves `localhost` and reaches an IPv6 origin through a dedicated IPv6 listener, counts real TCP accepts at the origin, and keeps the removed-egress origin reachable via an independent third link while requiring the bind-IP profile to fail. `origin.py` records accepts; `make_config.py` emits the IPv6 listener/egress. |
| R8 | Shutdown checks did not complete a transfer or prove no SIGKILL | `tests/m08/systemd.sh` performs a completable 16 MiB grace-period exchange with client exit/byte/hash checks, then a force-drop test that verifies the client is interrupted, the port is closed, no serve process/cgroup remains, and systemd did not log SIGKILL. The shell-negation `! ss | grep` form is removed. |
| R9 | Incomplete example/documented runbook and no disposable VM boot | `examples/m08-operations-https-basic.toml` is a complete TLS/Basic/ACL document shipped in the archive. `tests/m08/admin_guide.sh` runs it with CA/407/200 checks and backup/restore. `shutdown_timeout_ms` defaults to 5000. `tests/m08/vm_boot.sh` installs/enables the archive in a disposable Ubuntu cloud VM, reboots, and checks autostart plus the initial 403. ROB commands/limits are listed below. |

## Load-profile password budget

`tests/m08/load_stand.sh` and `tests/m08/soak_stand.sh` use
`auth.max_verifying = 16` for the synthetic 10/20-client Basic cohorts. The
production default remains `2`; the M05 admission contract and its tests are
unchanged. The larger test-only budget avoids turning the controlled request
rate into artificial 503 responses from the zero-queue Argon2 admission. The
actual outcome counts are attached to the CI run.

## ROB command and limits

Command on the installed systemd stand:

```sh
sudo --preserve-env=M08_BIN bash tests/m08/overload.sh
```

The check uses bounded synthetic inputs and no external network: 100
concurrent Basic-auth attempts, 100 idle TCP connections, 50 TLS handshakes,
10 slow clients, one client abort after 1 s, DNS/connect failures, and CONNECT
stop under load. Each phase has a finite deadline, the service must remain
responsive afterwards, and cleanup removes temporary clients/configs. A
timeout, unhandled panic, leaked listener or skipped phase is a failure, not a
pass.

## Reporting rules

- Every result names the full head SHA and archive SHA-256.
- A skipped/unavailable systemd, veth, IPv6 or CPU resource is FAIL/BLOCKED,
  not a pass. The reason is recorded in the PR.
- Failed attempts and reruns are listed with their cause.
- Timeouts, environment errors and ignored mandatory checks are not green.
- Numbers are valid only for the described test profile; they are not
  production throughput promises.
