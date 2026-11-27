# Angara 0.1 release candidate checklist

Mark each item only after the command/job has actually run on the stated SHA.
Do not pre-fill results.

## Artifact and provenance

- [ ] `cargo fmt --check`, Clippy `-D warnings`, locked build/test on the head SHA.
- [ ] `cargo deny check` passes.
- [ ] Release binary is `x86_64-unknown-linux-gnu` ELF and runs without Rust/Docker.
- [ ] `manifest.json` has full source/packager SHAs, target, profile, toolchain,
      Cargo.lock hash, binary hash and complete file list.
- [ ] External `SHA256SUMS` matches the tested archive.
- [ ] Third-party notices and local hyper patch description are present.
- [ ] Archive contains no operator config, users/PHC, passwords, private keys,
      tokens or backups.
- [ ] Archive ordering/metadata are deterministic; independent-build equality is
      either measured or explicitly not claimed.

## Install and systemd

- [ ] Clean install on Ubuntu 24.04 x86_64.
- [ ] Repeated install preserves config/users/TLS/drop-ins.
- [ ] `--destdir` install changes only the staging tree.
- [ ] Unsafe path/symlink/corrupt archive/wrong SHA fails before activation.
- [ ] Archive is copied privately and all tar/manifest operations use the verified bytes.
- [ ] Existing release tree is verified against the incoming manifest, not its own stale manifest.
- [ ] Parent symlinks cannot redirect DESTDIR writes; foreign unit/helper/current files are preserved and rejected.
- [ ] Existing `angara` group has no foreign members; service user has no supplementary privileged groups.
- [ ] `systemd-analyze verify` passes.
- [ ] `Type=exec`, `User/Group=angara`, PID/UID/groups/capabilities verified.
- [ ] Sandbox and `LimitNOFILE=16384`/`TasksMax=512` verified from the process.
- [ ] Initial loopback request returns 403 and origin sees no connection.
- [ ] Allowed ACL request works after configuration.
- [ ] Real start/reload/stop/restart and readiness request verified.
- [ ] Accepted and rejected reload observed in journal; PID/ACL preserved on reject.
- [ ] SIGHUP series is coalesced without unbounded tasks.
- [ ] Stop under load returns in the application/systemd deadline, ports free.
- [ ] Forced application close does not require SIGKILL.
- [ ] Restart-on-failure, start limit, config error and occupied port verified.
- [ ] `enable` and boot with systemd PID 1 verified on disposable stand.
- [ ] Disposable Ubuntu cloud VM installs/enables, reboots, and serves 403 before any operator configuration.

## Security and functionality

- [ ] HTTP and HTTPS listeners both work.
- [ ] Wrong/no credentials return 407; authenticated user without ACL returns 403.
- [ ] CONNECT to controlled TLS site works with correct CA/name.
- [ ] Wrong proxy/site CA and wrong name fail certificate verification.
- [ ] ACL deny does not open origin connection.
- [ ] Secret markers absent from journal, diagnostics, origin request and artifacts.
- [ ] `check` from service UID reads config/users/TLS as intended.
- [ ] TLS site remains end-to-end inside CONNECT; no MITM/insecure verifier.

## Upgrade and rollback

- [ ] A from accepted M07 and B from M08 are packaged with separate source SHAs.
- [ ] B check with active config runs as `angara` before A is stopped.
- [ ] Corrupt/wrong-hash/unreadable material fails while A keeps serving.
- [ ] A→B changes `/proc/<pid>/exe`, current release and proxy response.
- [ ] Config, users and TLS hashes survive A→B→A.
- [ ] Distinguishable A/B unit/helper/TLS metadata and an allowed origin request are checked across each transition.
- [ ] B failure after switch produces diagnostics and restores A.
- [ ] Foreign process returning an accepted HTTP code cannot confirm B readiness; readiness is tied to MainPID/exe/listener.
- [ ] Interrupted stop/start is recovered by repeat or explicit rollback.
- [ ] Port-conflict recovery works after the conflicting listener is removed.
- [ ] Previous release remains available until operator cleanup.

## Network, CPU, load and resources

- [ ] Two veth/NIC paths have distinct source addresses observed by origins.
- [ ] Interface counters increase on the selected path.
- [ ] Removing the selected source address causes explicit failure, no fallback.
- [ ] Stand cleanup removes only created namespaces/veths/processes.
- [ ] CPU/cpuset/quota recorded; 1/2 workers compared; 4 when resources allow.
- [ ] Thread activity and throughput/latency recorded.
- [ ] 10 and 20 independent clients, at least 60 s per cohort after warmup.
- [ ] HTTP, HTTPS-to-proxy, CONNECT, upload/download, HEAD/Range covered.
- [ ] All attempts/errors/retries counted; intentional 403/407/503 separated.
- [ ] 64 MiB and at least 1 GiB streaming with size and SHA-256 verified.
- [ ] Client/origin buffers bounded; FD/RSS/tasks return after completion.
- [ ] Overload (auth, connections, TLS, slow clients, DNS/connect errors,
      disconnect, stop under load) has bounded, documented outcomes.
- [ ] RSS peak ≤512 MiB; after close + idle TTL ≤8 FD and ≤64 MiB RSS above
      warmed baseline; hourly series recorded.
- [ ] 60-minute soak on 20 clients with TLS+Basic, accepted and rejected reload.
- [ ] Control request continues to work during soak.

## Documentation and decision boundary

- [ ] F01–F11 / N01–N09 matrix has test/command/evidence/limitation.
- [ ] All 18 M08-ID have evidence and limitations.
- [ ] Complete `examples/m08-operations-https-basic.toml` passes check/serve/TLS/Basic/ACL from the archive.
- [ ] Admin guide backup/restore and CA/407/allowed-request commands were executed on the stand.
- [ ] ROB corpus/command and limits are listed.
- [ ] Failed attempts and rerun reasons are recorded.
- [ ] PR has `Closes #23`, head SHA, archive SHA-256, CI links and owner check.
- [ ] Merge, license choice, first deployment and public v0.1 release remain
      owner decisions.

## M11 control plane (post-v0.1)

- [ ] `angara tui` opens two sessions; closing one does not affect the proxy.
- [ ] `angara-control.service` runs as root; the proxy unit has no write path to `/etc/angara`.
- [ ] `angara` group can read the public socket; only `angara-admin` can add users, change passwords, block or edit ACL.
- [ ] Ordinary UID is denied on the server side, not only by socket mode.
- [ ] Password, PHC, Authorization, private keys and full URLs absent from responses, events, journal, previews and test dumps.
- [ ] Temporary block expires without TOML write, survives a restart after expiry, and existing CONNECT tunnels follow the documented policy.
- [ ] Stale file version is rejected; comments, rule order and unrelated sections survive ACL edits.
- [ ] `restart_required`, invalid candidate and lost-response states are visible and do not claim application.
- [ ] Limits for clients, subscribers, request line, page, event ring and expensive operations are exercised.
- [ ] Wide and narrow TUI screenshots on synthetic data are attached to the PR with the tested SHA.
- [ ] Before rollback to M10, temporary `blocked_until` entries are cleared (users file returns to `version = 1`) or the users file is restored from backup; M10 cannot start on users v2.
