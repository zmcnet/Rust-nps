# tools/interop — real-Go-npc interop harness

Black-box interop test between the **real Go `npc` client** (built from
`resources/nps`, read-only) and the **Rust `npsd` server**.

Write scope: everything here. The Go repo is never modified.

## Provenance of the client binary

`bin/npc.exe` was built with the installed Go toolchain:

```bash
cd /d/Developing/NPS/resources/nps
env HTTP_PROXY=http://127.0.0.1:7897 HTTPS_PROXY=http://127.0.0.1:7897 \
    GOPROXY=https://proxy.golang.org,direct \
    go build -mod=readonly -o ../../tools/interop/bin/npc.exe ./cmd/npc
```

Verified evidence:

| item | value |
|---|---|
| Go toolchain | `go1.27.4 windows/amd64` |
| `npc.exe -version` | `Version: 0.26.10` / `Core version: 0.26.0` |
| size | 19,731,456 bytes |
| sha256 | `6b12e91905049a7e497d9f7af67be9ab04b84262e99939f0cbbbdfb97b181788` |
| source rev | git `ab648d6f0c618c690a7a79948a7ebd686e1cdafc` (`v0.26.10-8-gab648d6`) |

Only the module proxy was set per-command; no global Go/git config was changed
and no file under `resources/nps` was touched (`git status` clean).

## Running the smoke test

Build the Rust server first (`cargo build -p nps-app --bin npsd`, output
`rust/target/debug/npsd.exe`), then:

```bash
python -I /d/Developing/NPS/tools/interop/smoke.py \
    --server-bin /d/Developing/NPS/rust/target/debug/npsd.exe \
    --npc-bin    /d/Developing/NPS/tools/interop/bin/npc.exe
```

`--server-bin` defaults to `<repo>/rust/target/debug/npsd.exe` and `--npc-bin`
to `<script dir>/bin/npc.exe`.

Exit codes: `0` all checks passed, `1` a check failed, `2` npc binary missing,
`3` server binary missing (end-to-end intentionally **not** executed).

Optional browser preview (off by default, max 600 s): after a fully successful
run, keeps the same real npc/npsd/echo environment alive so the management UI
can be checked by hand:

```bash
python -I /d/Developing/NPS/tools/interop/smoke.py \
    --server-bin .../npsd.exe --npc-bin .../npc.exe --preview-seconds 300
```

The test-only admin token and port map are written to
`logs/run-<timestamp>/ui-session.json` (never printed). On timeout or Ctrl+C
the environment is still torn down and all child processes/sockets are
cleaned up.

Every run gets a fresh temp dir `logs/run-<timestamp>/` containing
`npsd.json` (ephemeral random vkey/token inputs), `npsd.log`, `npc.log`,
`npc-restart.log`, `npc-bad-vkey.log`. Logs are kept on success and failure.
The admin token and vkey are generated per run, never printed.

The server is started as `npsd --config <json>` with `NPS_ADMIN_TOKEN` in its
environment only (the npc environment does not inherit it). The npc is the real
binary, launched as
`npc -server=127.0.0.1:<bridge> -vkey=<random> -type=tcp`.

## What is asserted

1. `npc -version` core version is parsed from the real binary; the binary's
   sha256 and size are printed and its version must be exactly
   `0.26.10` / core `0.26.0`.
2. Server binds `bridge_addr` and `web_addr` (poll with timeout).
3. `GET /api/status`: no token -> 401; wrong Bearer -> 401/403; valid Bearer -> 200.
4. `/api/status` must match the **exact** contract: top-level `bridge_addr`,
   `clients[]` rows with `id/name/online/version`, `tunnels[]` rows with
   `id/name/client_id/listen_addr/target_addr/enabled/active_connections/
   bytes_to_client/bytes_from_client/last_error`; types are enforced (no
   string "true", no keyed-map substitute). The tolerant helper is kept for
   diagnostics only.
5. Every admin API response body is scanned: it must not contain the test
   vkey, `md5(vkey)` or the admin token.
6. Raw legacy handshake probe (exact Go framing `TST` + len-prefixed core/full
   versions + 32-byte `md5(core)` + 32-byte `md5(vkey)`):
   - server digest equals `md5(core_version)`;
   - wrong vkey -> 4-byte flag `vkey`;
   - version mismatch is diagnosed (which core versions are accepted).
7. Real `npc` with a **wrong** vkey stays offline and logs
   `Validation key ... incorrect`.
8. Real `npc` with the correct vkey: client id=1 reports `online=true`.
9. Four **concurrent** byte-exact echo streams through the public tunnel:
   4 MiB, 1 MiB, 512 KiB, 300 KiB (all > 256 KiB; 4 MiB crosses the 122550
   initial mux window). Each stream runs a reader and a writer thread
   concurrently, so the test itself cannot fill a socket buffer and deadlock.
10. After the big transfer, tunnel stats must settle: `active_connections`
    returns to 0 and both `bytes_to_client` / `bytes_from_client` are at least
    the total business bytes (6,074,368 bytes = the four stream sizes).
11. npc shutdown -> `online=false`; restart -> `online=true` and a 128 KiB
    transfer succeeds again.
12. `POST /api/tunnels/1/state {"enabled":false}` -> 2xx, status reports
    `enabled=false`, and the public port is **connection-refused** (a listener
    that accepts but does not forward is NOT accepted as proof). On this
    machine a refused loopback connect takes ~2 s, so the probe timeout is
    `--refuse-probe-timeout` (default 6 s); `connected`/`timeout` both fail.
    `{"enabled":true}` -> 2xx, status `enabled=true`, 64 KiB echo resumes.
13. All child processes are terminated (`terminate`, then tree-kill fallback)
    and the four test ports are verified to have no LISTENING socket.

All child stdout/stderr go straight to files (never PIPE), so large output
cannot block a process. Every wait has an explicit timeout and reports failure
instead of hanging.

## Expected server contract used by this test

From the parent's `nps-server`/`nps-web` crates:

```json
{
  "bridge_addr": "127.0.0.1:<port>",
  "web_addr": "127.0.0.1:<port>",
  "clients": [{"id": 1, "name": "legacy-test", "vkey": "<random>"}],
  "tunnels": [{
    "id": 1, "name": "echo-test", "client_id": 1,
    "listen_addr": "127.0.0.1:<port>", "target_addr": "127.0.0.1:<echo port>",
    "enabled": true
  }]
}
```

`GET /api/status` returns:

```json
{"bridge_addr": "...",
 "clients": [{"id": 1, "name": "...", "online": true, "version": "0.26.10"}],
 "tunnels": [{"id": 1, "name": "...", "client_id": 1, "listen_addr": "...",
              "target_addr": "...", "enabled": true, "active_connections": 0,
              "bytes_to_client": 0, "bytes_from_client": 0,
              "last_error": null}]}
```

The script also tolerates keyed maps (`{"clients": {"1": {...}}}`) and textual
`online`/`enabled` values **in the diagnostic helper only** — acceptance uses
strict exact-field checks, so those alternate shapes will fail the test.

## Notes

- The Go core version is `0.26.0` (`GetVersion()`); `0.26.10` is only the full
  `VERSION`. The handshake compares the core version, so the server must expect
  `0.26.0`. (`nps-proto::CORE_VERSION` already is `0.26.0`; a doc comment in
  `nps-legacy/src/handshake.rs` still mentions `0.26.10` and is stale.)
- `Getverifyval` is plain `md5(vkey)` lower-case hex, 32 chars.
- The 122550-byte figure is the initial mux receive window; the 4 MiB stream is
  what forces the window-update path to be exercised.
- Harness self-validation (echo server, streaming transfer, handshake framing)
  was done locally; it is **not** a substitute for the real `npsd` run, which
  awaits the parent's build.
