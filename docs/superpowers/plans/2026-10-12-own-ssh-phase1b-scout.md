# Plan 1b scout: session broker, local IPC, `sshelter connect`, Connect button

Read-only scout, branch `next/own-ssh` at 62662b0, 2026-10-12. Nothing in the checkout was changed; no cargo, pnpm or app run
(Homebrew's rustc is broken on this machine; every fact below comes from reading the sources, `src-tauri/Cargo.lock` and the crate
sources in `~/.cargo/registry`). Three Windows facts come from Microsoft Learn and are marked "MS docs". Spec = 
`docs/superpowers/specs/2026-10-10-own-ssh-client-design.md`; progress = `.superpowers/sdd/2026-10-11-own-ssh-phase1a-engine/progress.md`.

## 0. Answers first

- **Order:** 1b next, with a `HostDirectory` trait, a fake directory for tests and a thin, clearly temporary adapter over today's
  ssh_config + vault slots; 1c replaces the adapter with records. Throwaway is about 300 lines; everything else 1b builds is permanent,
  the broker is fully testable without 1c, and a dev build can connect to the user's real servers at the end of 1b, given a host-key path (§8 item 4) and keys in the vault (§5) (§7).
- **Crates:** no new package in `Cargo.lock`. `Cargo.toml` gains tokio's `signal` feature (its only extra crate, signal-hook-registry
  1.4.8, is already locked) and optionally nix's `term` feature (nix 0.31.3 already locked), or nothing at all if termios goes
  through the `libc` the app already depends on. `windows-sys`'s `Win32_System_Console` feature only if Windows console code is in 1b (§6).
- **Riskiest unknowns:** (1) Windows: the CLI is the GUI-subsystem binary and the pipe is synchronous; (2) the connect-retry state
  machine (host-key window → pin → reconnect; prompts over IPC under the engine's no-waiting rules); (3) session and app lifecycle
  (idle timeout on the IPC server, window close vs quit, hand-over, terminal teardown) (§9).

## 1. Starting the app's host process from a client

Facts:
- `main.rs:2` release builds are `windows_subsystem = "windows"`. `main.rs:5-9` askpass helper mode first (`SSHELTER_ASKPASS`);
  `main.rs:14-16` read and remove `SSHELTER_START_HIDDEN`; `main.rs:18-22` the mode is `args[1]`: `--mcp` → `mcp::run_stdio()`,
  `mcp::HOST_FLAG` (`"--mcp-host"`, `mcp.rs:33`) → `run_desktop(true, hidden)`, anything else → `run_desktop(false, hidden)`.
- `lib.rs:126-138` the single-instance plugin is registered first, **release builds only** (a debug build shares the identifier and runs
  next to the installed app). A second launch calls `on_second_launch` (`lib.rs:117-124`): `second_launch_shows_window`
  (`lib.rs:110-113`) is false only when `args[1] == HOST_FLAG`, and then the running app only calls `mcp::republish_bridge`
  (`mcp.rs:338-346`, rewrites `mcp-runtime.json`). Tests `lib.rs:333-347`.
- `lib.rs:164-179` setup: show the window unless hidden, `mcp::initialize(app, mcp_host)` (keep-alive = started as host,
  `mcp.rs:276-282`), `sync::engine::initialize`, `agent::start`, tray. `lib.rs:192-206` CloseRequested hides instead of quitting when
  `close_to_tray` or `mcp.keep_alive`; `mcp.rs:690` sets keep-alive when an approval arrives. `lib.rs:316` Exit → `mcp::forget_bridge`.
- Client side today (MCP only): `bridge_call` (`mcp.rs:1455-1460`) → `ensure_desktop_bridge` (`1279-1281`) →
  `ensure_started(answering_bridge, take_spawn_locks, start_host, START_WAIT)` (`1304-1329`): look; take the locks; look again; start
  once; poll every 120 ms for 12 s (`1270-1271`); else `NO_ANSWER` (`1273-1274`, "SSHelter didn't answer within 12 seconds. If it is
  open, quit it and open it again."). `answering_bridge` (`1284-1288`) reads `mcp-runtime.json` and pings the TCP bridge (5 s).
  Locks: `SPAWN_LOCK` static mutex for parallel calls of one adapter (`1277`), then an exclusive file lock on
  `<app data>/mcp-spawn.lock` until the deadline (`take_spawn_locks_at` `1346-1363`, `lock_file_until` `1379-1406`; Busy → one more
  look; Unavailable → start without it). `start_host` (`1410-1421`) spawns `current_exe()` with `host_command` (`1425-1435`:
  `--mcp-host`, `SSHELTER_START_HIDDEN=1`, null stdio) detached (`detach_from_adapter` `1439-1453`: `process_group(0)`; Windows
  `CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS`) and reaps a hand-over exit on a thread. Tests with injected closures `mcp.rs:1547-1720`.
- The MCP bridge itself is loopback TCP + token + runtime file (`mcp.rs:291-333`); spec §8.1 (line 245) replaces it in phase 2.

Reusable for `sshelter connect`: `ensure_started` (generic and tested), `SpawnLocks`, `take_spawn_locks_at`, `lock_file_until`,
`start_host`, `host_command`, `detach_from_adapter` — move them unchanged into a module both clients use. Only two things differ:
`answering` (connect to `<app data>/ipc/sock` instead of the TCP ping) and the message (spec §7.3 line 231, §11 line 300:
`SSHelter did not start within 12 seconds.`, exit code 1).

Changes 1b needs: `HOST_FLAG` → `--host` (spec §4 line 77) in `mcp.rs:33`, `lib.rs:111-113` and the tests; keep accepting
`--mcp-host`, because an update's restart reuses the old arguments (`lib.rs:90-92`); the `mcp_host` keep-alive becomes a host
keep-alive; `on_second_launch` must also (re)start the broker listener, not only republish the MCP bridge (spec line 77: after the
hand-over the socket path is the same and the client just retries); `main.rs` gains `Some("connect") => …` before any Tauri code,
like `--mcp`; MCP and connect must share one spawn lock file (today `mcp-spawn.lock`, `mcp.rs:1365-1367`) so they never start two hosts.

## 2. The local IPC server and who uses it

Facts:
- `ipc/mod.rs:1-7` transport only; a guard test forbids `agent` paths inside `ipc/` (`ipc/mod.rs:40-59`).
- `ipc/server.rs`: `Handler = Arc<dyn Fn(Stream, Option<u32>) + Send + Sync>` (`21-22`), `Stream` = `UnixStream` / `File` on Windows
  (`15-19`), `Started::{Running, OtherInstance}` (`24-29`). `listen_unix(dir, handler)` (`86-133`): socket `dir/sock` (`93`),
  `check_socket_path` (`72-84`; 104 bytes macOS, 108 Linux, counting the NUL, `63-65`), `take_lock(dir)` on `dir/lock` (`31-40`; held →
  `OtherInstance`), stale socket removed, bind inside `process::without_spawns` (`103`), mode 0600 (`104`), accept loop on its own
  thread; `peer()` drops other uids and returns the pid (macOS getpeereid + LOCAL_PEEREPID/PEERPID `148-167`, Linux SO_PEERCRED
  `169-182`); every accepted stream gets `IDLE_TIMEOUT` = 300 s read timeout (`67-70`, `128`); `dispatch` caps at `MAX_CONNECTIONS` 64
  and gives each connection a thread (`12-13`, `42-61`).
- Couplings to the sync file layer that 1c deletes: `take_lock` creates the dir with `sync::slot_files::ensure_keys_dir`
  (`server.rs:33`; `slot_files.rs:31-41`), `pipe_windows.rs:32` imports `sync::slot_files_windows::current_user_token`. (The vault also
  writes through `slot_files::write_private`, `vault/store.rs:5,21` — 1c has to move these helpers rather than delete them.)
- Windows: `pipe_windows::listen(dir, name, handler)` (`165-199`): lock in `dir`, owner-only DACL (`34-90`), remote clients rejected
  (`122`), first instance exclusive (`121`); the name comes from `pipe_name()` = `sshelter-agent-<16 hex of SHA-256(SID)>` (`109-113`,
  prefix hard-coded). The pipe is **synchronous**: `open_mode` has no `FILE_FLAG_OVERLAPPED` (`121`), `accept` says so (`145`); the client
  pid via `GetNamedPipeClientProcessId` (`155`); `one_shot` (`159-163`) exists only for Connect's key channel.
- `ipc/peer.rs`: `process_chain(pid)` (`120-124`, up to 64 parents) and `identify(chain)` (`99-118`) → `Program{chain, identity}`,
  skipping system processes and the `SKIP` names (`22-24`: ssh, shells, login, env, sudo). It does **not** strip SSHelter's own
  executable (spec §7.2 line 225 asks for it); for `sshelter connect` `chain[0]` is the CLI itself.
- Listening today: only the agent, at `~/.ssh/sshelter/agent/sock` (`agent/mod.rs:27-34`, `172-193`; Windows pipe `sshelter-agent-…`,
  `190-193`), plus the one-shot sockets under `~/.ssh/sshelter/agent/run/` (`agent/oneshot.rs:401`). Nothing listens on
  `<app data>/ipc/sock` and no code names that path. `fsutil::app_data_root()` = `dirs::data_local_dir()/org.homelab.sshelter`
  (`fsutil.rs:12-16`) works without Tauri, so the CLI can compute the socket path itself.

Conclusions:
- The broker takes its own dir `<app data>/ipc/` (own `lock` and `sock`; on Windows a new pipe name — parameterize the
  `sshelter-agent-` prefix). Agent and broker coexist through 1b; the agent protocol does **not** have to go first; 1c removes the
  agent listener. Broker API: `listen_unix(&app_data_root()?.join("ipc"), handler)`; per connection `stream.try_clone()` for a reader
  and a writer; pid → requester chain only when phase 2 needs it.
- Changes `ipc/` needs: (a) a session connection must not inherit the 300 s idle read timeout — an interactive shell idles longer and the
  reader would error out (clear it after `hello`, or make it a listener option); (b) move `ensure_keys_dir` / `current_user_token`
  out of `sync::slot_files*` (1b or 1c); (c) Windows full duplex: MS docs (CreateNamedPipeW; "Synchronous and Overlapped Pipe I/O")
  describe simultaneous read and write on one pipe handle as an overlapped-mode capability, and both ends here would be synchronous.
  tokio's named pipes are overlapped (`tokio-1.52.3/src/net/windows/named_pipe.rs:2325`, `2586`) and are compiled under the `net`
  feature the app already enables (`tokio-1.52.3/src/macros/cfg.rs:384-392`; `Cargo.toml:56`). Either way it needs a Windows run.
- Cosmetic: thread names `sshelter-agent…` (`server.rs:57,107`; `pipe_windows.rs:171`) and the header (`server.rs:1-2`) still describe the agent.

## 3. Launching a terminal (spec §7.4)

- `detect_terminals`: macOS Terminal + iTerm2 (`connect.rs:100-116`), Windows wt + cmd (`118-136`), Linux `$TERMINAL` + 9 known (`138-179`).
- `build_launch(terminal, alias, new_tab)` = `build_launch_command(terminal, &["ssh", alias], new_tab)` (`connect.rs:222-228`).
  `build_launch_command` (`237-354`) is pure and tested: macOS osascript `do script` / iTerm2 window or tab with `shell_join` +
  `applescript_escape` (`246-299`); Linux argv passed through, except `xfce4-terminal -e "<string>"` (`199-220`, `300-318`,
  `346-352`); wt `[-w 0 nt] argv` (`319-333`); cmd `/c start "" cmd /k argv` (`334-345`). `launch` spawns via `process::spawn` (`521-525`).
  → reuse unchanged with argv `[current_exe(), "connect", alias]`.
- `connect_launch` (`537-587`): `validate_alias` against `state.doc` (`547-553`; charset rejects a leading `-`, `33-43`; must be a Host
  pattern, `45-70`); terminal choice (`555-564`); the one-shot key channel `agent::oneshot::prepare` (`569`) →
  `ssh -o IdentityAgent=<channel> -o ForwardAgent=no <alias>` (`570-575`, `oneshot.rs:118-121`); else password autofill
  (`576-577`: `password_autofill_env` `478-514` sets `SSHELTER_ASKPASS`/`SSH_ASKPASS_REQUIRE=force`; `build_autofill_launch` `420-456`,
  `autofill_ssh_argv` `362-376`, `env_wrapped_argv` `381-386`, `windows_autofill_cmd_string` `395-410`); else plain (`578`); the channel is
  kept after the launch (`583-585`).
- Callers (all through one command, so the switch is Rust-side): `useConnect` (`src/lib/queries.ts:415-436`, invoke at `422`) used by
  HostList `connectTo` (`src/components/HostList.tsx:1059-1066`), HostEditor `onConnect` (`src/components/HostEditor.tsx:564-569`,
  button `603-604`), CommandPalette `doConnect` (`src/components/CommandPalette.tsx:117-128`); the global hotkey only opens the palette
  (`src/lib/global-hotkey.ts:15-24`); the tray is Rust: `on_menu_event` → `quick_connect` (`tray.rs:113-130`, `133-166`: first terminal,
  no tab, one-shot channel, no autofill), menu built from the doc (`tray.rs:15-33`).
- Deleted by the switch (spec line 239): the autofill block (`connect.rs:356-514` and its tests), the one-shot use (`connect.rs:569-585`,
  `tray.rs:150-165`), `agent/oneshot.rs` (1022 lines with tests), `pipe_windows::one_shot` (`159-163`), the `agent://connect-expired`
  listener (`src/lib/sync-events.ts:184`, `src/lib/agent.ts:18-19`). They leave dead code that would warn: `deploy::is_default_config_root`
  (`deploy.rs:471`, used only by connect.rs) and `deploy::openssh_supports_forced_askpass_in_terminal` (`deploy.rs:633`, otherwise tests
  only). `askpass.rs` stays: deploy still uses the helper (`deploy.rs:99-201`, `main.rs:7-9`).
- Windows caveat for the new argv: the exe is GUI-subsystem (`main.rs:2`). MS docs (`start`, remarks): when you run a GUI application,
  `cmd` does not wait for it before returning to the prompt — the `cmd /k <exe> connect` launcher would leave cmd and the CLI reading
  one console. MS docs (AttachConsole, remarks): `ATTACH_PARENT_PROCESS` fails with ERROR_INVALID_HANDLE when the parent has no console
  (whether the parent under `wt.exe` has one is unmeasured). The spec already defers the Windows terminal to phase 3 (§13 line 318,
  §16 line 348).

## 4. Approval and confirmation windows today

1. MCP approval (a dialog in the main window): `run_approved` (`mcp.rs:604-786`) registers `PendingApproval{request, mpsc::SyncSender}`
   (`676-683`), sets keep-alive, shows the main window and emits `mcp://approval-requested` (`690-694`), blocks on `recv_timeout(120 s)`
   (`696-725`, `mcp.rs:39`); `McpApprovalDialog` (`src/components/McpApprovalDialog.tsx:22-40`, mounted `src/App.tsx:288`) polls
   `mcp_status` every 750 ms and answers through `mcp_resolve_request` (`mcp.rs:972-993`, `src/lib/mcp.ts:46`).
2. Agent approval window — the one spec §10 (line 283) says to copy: `agent::prompt::PromptHub` (`prompt.rs:76-156`): `ask(surface,
   request, timeout)` blocks the calling worker thread on a sync channel (`98-118`), `resolve(id, answer)` (`134-141`, answered/expired →
   NotFound), `deny_all` when the window is closed (`143-150`, wired in `lib.rs:180-187`); `PromptSurface` (`63-67`) makes it testable
   with a recorder; `TauriPromptSurface` (`170-213`) builds a separate always-on-top 460×340 window labelled `approval` from
   `index.html` (`186-201`), focuses it only for a new head request (`163-168`, `203-210`), emits the whole list as `agent://approvals`
   (`211`); commands `agent_pending` / `agent_resolve` (`215-227`); 60 s timeout (`prompt.rs:14`). `ask` must run on a worker thread
   (`prompt.rs:100-101`: creating a window from a sync command deadlocks on Windows) — the broker's IPC threads qualify. Frontend:
   `src/main.tsx:16-26` renders `AgentApprovalWindow` (150 lines) when the label is `approval`; `src-tauri/capabilities/approval.json`
   (windows `["approval"]`, `core:default`); fetch/event race guard and a 700 ms arm delay before Allow (`src/lib/agent.ts:88-95`, `127-147`).
3. Sync approvals (`sync/approval.rs`, `sync_pending_approvals` / `sync_approve`, `src/lib/sync.ts:234,289`) review stored remote records;
   no thread waits on them — not a model.
4. Deploy's host-key trust (`deploy.rs:707-768`): the UI sends back only the fingerprint it showed; the backend re-scans and writes only its
   own key, and only if the fingerprint still matches — the pattern for "Trust this key".

A host-key confirmation modelled on (2) + (4): a hub with `HostKeyRequest{id, alias, hostname, port, algorithm, fingerprint,
kind: unknown|changed, pinned_fingerprint, pinned_at}` and answer `{trust, fingerprint}`; the broker's connection thread asks after
`HostKeyUnknown`/`HostKeyMismatch` and pins the key **it** observed when the returned fingerprint matches; meanwhile the CLI gets
`question{kind: host_key_notice}` and prints `Waiting for you to confirm {alias}'s host key in SSHelter.` (spec line 286, line 294).
Either a second request type in the `approval` window or a new label (one capability entry + one routing line). Strings: spec §14
lines 328-329. Without any window, a 1b dev build can never connect to an unpinned host (§8 offers two ways out).

## 5. Where host data comes from today, and a temporary adapter

Facts:
- Hosts are ssh_config text: `SshConfigDoc{files}` → `HostBlock{patterns, body}` (`config/model.rs:37-62`), put into `AppState.doc`
  only when the frontend calls `config_load` (`config/commands.rs:687-726`, stored at `713`; the root path is selectable, `691-696`);
  MCP waits up to 5 s for it (`mcp.rs:564-575`). Synced host records carry the raw block text (`HostPayload{schema, text}`,
  `sync/record.rs:164-169`).
- Effective values come from system `ssh -G` (`config::intel::effective_config`, `intel.rs:23-62`), used by MCP, deploy and the one-shot
  channel; helpers `deploy::endpoint_from_effective` (`deploy.rs:249-262`), `has_proxy` (`411-417`); `intel::jump_chain` follows
  ProxyJump through the doc (`intel.rs:302-340`).
- Keys: SP3 slots, `key_slots: slot id → LocalSlot{file_name, source}` (`sync/state_v2.rs:203-233`), `SlotSource::{Linked, SyncedCopy,
  Vault{fingerprint, public_key, has_passphrase}}` (`260-271`). IdentityFile → slot: `resolve_identity_value` (`sync/slot_rules.rs:170-194`)
  and `agent::oneshot::vault_slot_of(identity_files, state, home)` (`oneshot.rs:106-116`, first IdentityFile that is an
  "Only in SSHelter" slot → its slot id). The vault is keyed by slot id (`vault/store.rs:277-285`; `VaultEntry{private_key (possibly
  passphrase-encrypted), public_key, fingerprint}` `61-70`) and spec §5.2 (line 107) keeps the ids, so **the slot id is the future
  `key_id`**. App-side read: `sync::engine::with_env(app, |env| with_vault(…, |v| v.get(id)))` as `agent/mod.rs:81-88` does
  (`with_env` `sync/engine.rs:132-151`, `with_vault` `vault/store.rs:397-409`). Unlock and sign: `material::open(text, passphrase)`
  (`vault/material.rs:84-95`), `Material::sign(data, flags)` (`125`; RSA flags `12-13`). Remembered passphrases: keychain
  `vault:passphrase:<slot id>` (`agent/broker.rs:27-30`, `217-220`). 1a's `VaultAuth` double (`ssh/testing/doubles.rs:193-240`, RsaHash →
  flag mapping `208-213`) is already the shape of the production `AuthSource`.
- Passwords: keychain service `SSHelter`, account `host:<alias>` (`secrets.rs:8-14`, get/set `31-45`), written by deploy and the
  `secrets_*` commands (`deploy.rs:841`, `846-864`), read by Connect autofill (`connect.rs:482-486`). After migration `host:<host id>`
  (spec §5.5 line 122, §9 line 273).
- known_hosts: a viewer and line remover only (`known_hosts.rs:65-79`, `114-127`, append `238`); hashed `|1|` names are only flagged
  (`known_hosts.rs:96,123`; `discover.rs:21-28` skips them); deploy looks keys up with `ssh-keygen -F` / `ssh-keyscan`
  (`deploy.rs:707-738`); the agent uses known_hosts only to name hosts in its window (`agent/mod.rs:126-150`). No pinning exists.
  Spec §9 (lines 270-274) imports no known_hosts, so after 1c every host is confirmed once (pins sync) — worth a decision in 1c.

Adapter mapping (`Target{hops}`, `Hop` fields `ssh/types.rs:128-191`):

| Hop field | temporary source |
|---|---|
| `id` | `HostId(alias)`; then the AuthSource's final keychain naming `host:<id>` finds today's `host:<alias>` entries |
| alias, hostname, port, user | `ssh -G <alias>`; alias must be a Host pattern (`connect::validate_alias`, `connect.rs:60-70`) |
| `auth` | `Key{slot id}` when `vault_slot_of` finds a Vault slot, else password/keyboard-interactive (see §9.2) |
| `pinned` | a dev pin table keyed by alias (JSON in app data) — or seeded, see §8 |
| timeouts, keepalive | the spec defaults (`types.rs:9-12`); OpenSSH's own defaults differ (no ServerAlive) |
| jump hops | ssh -G `proxyjump` (comma list of `[user@]host[:port]`), each a Host alias resolved by ssh -G (spec decision 8, line 46), cycle check; `proxycommand` refused |

- Works for: hosts on an "Only in SSHelter" vault key; password (saved or typed) and keyboard-interactive hosts; ProxyJump chains through
  saved hosts. Not for: Linked/SyncedCopy slots and plain `~/.ssh/id_*` files (the engine signs only through the vault; the existing
  "Only in SSHelter" / "Move all into vault" commands put such keys there, `sync/engine.rs:668-683`), ProxyCommand, forwarding,
  certificates, other agents (spec non-goals, lines 26-32), and unpinned hosts until a confirmation path exists.
- Cost: about 250-350 lines plus 150 lines of tests (ProxyJump parsing, ssh -G pairs → `Hop`, the pin file are pure); one side effect,
  `ssh -G`, which also runs `Match exec` (MCP and deploy already do) and must stay off the main thread.
- Thrown away in 1c: the adapter and its tests, the dev pin file, the doc-based `validate_alias` gates in `connect_launch`/tray and the
  doc-based tray list. Kept: the directory trait, `AuthSource` (vault by key id, `host:<id>`, passphrase keychain), `HostKeyPolicy` (pins
  carried in `Hop.pinned`), broker, IPC, CLI, launcher. The ProxyJump parser and the IdentityFile → slot mapping are what spec §9 step 1's
  importer needs too, if written as pure functions.

## 6. Raw mode, signals and the lock file

Facts:
- `Cargo.toml:56` tokio 1.52 features `rt-multi-thread, macros, net, io-util, time, sync` — no `signal`, no `io-std`. `Cargo.toml:84-85`
  libc 0.2 (direct, unix). `Cargo.toml:79-80` windows-sys 0.61 features without `Win32_System_Console`. No direct nix or crossterm.
- `Cargo.lock`: tokio 1.52.3 (`6652`) depends on bytes, libc, mio, parking_lot, pin-project-lite, socket2, tokio-macros, windows-sys —
  no signal-hook-registry, so nothing in the graph enables tokio's `signal`. signal-hook-registry 1.4.8 (`5558`) is locked only through
  async-signal (`288`) ← async-process ← zbus, a Linux-only dependency of tauri-plugin-opener, tauri-plugin-single-instance and keyring
  (their target sections) — so today it is built on Linux only. nix 0.31.3 (`3420`; deps bitflags, cfg-if, cfg_aliases, libc) is locked on
  unix via os_info (features `["feature"]`) and russh-cryptovec (`["mman"]`). crossterm, termios, terminal_size, rpassword, clap, ctrlc:
  not in the lock.
- tokio 1.52.3: `signal` = libc + mio features + signal-hook-registry (unix-only target dependency) + windows-sys `Win32_Foundation`,
  `Win32_System_Console`; `SignalKind::window_change()` is `src/signal/unix.rs:224`. nix 0.31.3: `term = []`, `signal = ["process"]`,
  `ioctl = []` — no extra crates. libc 0.2.186 has `tcgetattr`/`tcsetattr`/`cfmakeraw` (`src/unix/mod.rs:2051`, `2315-2319`) and
  `TIOCGWINSZ` (`src/unix/bsd/apple/mod.rs:2404`).

What 1b would add — nothing new to the lock's package list:
- tokio feature `signal` (required for spec §7.3 line 233): one new edge tokio → signal-hook-registry; signal-hook-registry becomes a
  compiled crate on macOS.
- termios: either nothing (libc, already direct; unsafe calls) or `nix = { version = "0.31", default-features = false, features = ["term"] }`
  under `cfg(unix)` (spec line 233 says nix): one new edge, no new package.
- `windows-sys` feature `Win32_System_Console` only if Windows console code lands in 1b (feature flag, no package).
- No argument parser (two forms: `<alias>`, `--id <id>`). Check with 1a's lock-delta rule: the lock diff may only touch dependency lists.

## 7. Order: (a) 1b next with a directory interface vs (b) 1c first

| | (a) 1b next: trait + fake + temporary adapter | (b) 1c first, then 1b |
|---|---|---|
| Throwaway | the adapter (~300 lines + tests) and a dev pin file; nothing else | none in the data model, but between 1c and 1b Connect either keeps the old path (system ssh + agent + one-shot channel — so 1c cannot delete `agent/` yet) or does not work at all; a temporary system-ssh launcher over records would be throwaway too |
| Testability | broker fully testable now: `FakeEngine` (`ssh/fake.rs`, `#[cfg(test)]`, `ssh/mod.rs:11-12`) + fake directory + fake host-key hub + fake CLI prompter; end-to-end with the real engine against the scratch sshd (`ssh/testing/`, `ssh/mod.rs:14-15`); CLI with a fake terminal (spec §12 line 308) | 1c alone is testable (fixed ssh_config samples, `FakeRelay`, spec line 307); 1b later is the same as (a) |
| Dev build at the end | `sshelter connect` and the Connect button reach the user's real servers with the new engine (vault keys, keychain passwords, 2FA, jumps). Read-only toward user data, so safe next to the installed 0.17. The engine meets real servers early (spec §16 lines 348-349: other sshd versions, long sessions, rekey) | imported hosts appear, but nothing connects with the new engine. Migrating the real `sync-state.json` to schema 3 makes the installed 0.17 and the second machine read-only ("needs update", spec lines 114, 274), so trying 1c on the daily machine needs a scratch data dir or a test account |
| Interface risk | the directory trait is designed before records — small, §5.1 fixes the fields | the broker's needs (pin write path, alias/id resolution, where the public key comes from) are found only after the model is fixed |

Recommendation: **(a)**. Nothing ships between plans (spec §9 line 269), the throwaway is small and isolated, every permanent piece of 1b is
exercised against real servers well before the 1.0 beta, and 1c gets a consumer that defines exactly what records must answer.
Dev-trial caveats (existing behavior, not new): a debug build has no single-instance plugin and shares `org.homelab.sshelter` with
the installed app (`lib.rs:131-138`, `fsutil.rs:12-16`); started second, its sync engine is read-only (`sync/engine.rs:368-393`), its
agent reports another instance, and its MCP bridge overwrites `mcp-runtime.json` while it runs (`mcp.rs:291-298`; only its own file is
removed at exit, `350-360`). The broker's `<app data>/ipc/` is unused by 0.17, so no conflict there.

## 8. Recommended 1b scope

In (macOS and Linux; Windows only as far as it compiles and keeps today's behavior):
1. `ipc/`: the §7.1 framing (`u32 length | u8 type | payload`, JSON control, raw data) as a codec with a size cap and tests; the broker
   listener at `<app data>/ipc/{lock,sock}` started in setup next to `agent::start` (`lib.rs:176`) with its status recorded like
   `AgentStatus` (`agent/mod.rs:48-58`); idle timeout cleared for sessions; lock-dir helper moved out of `sync::slot_files`. A
   protocol version in `hello` (CLI binary and running app can differ after an update). Messages: `hello`, `open_shell`, `data`,
   `window_change`, `answer`, `close` → `opened`, `data`, `question`, `event`, `exited`. `exec`/`exec_result` wait for phase 2.
2. `session/` broker (spec §4 line 69): session table; one `RusshEngine` for the app (`russh_engine.rs:96`), sessions dropped before it;
   per connection a reader thread (demultiplexes `answer`/`data`/`window_change`/`close`) and a locked writer; the connect-retry state
   machine (§9.2); last window size replayed after `shell` returns (spec line 226); shell output pump (`ShellChannel::read` → `data`;
   the engine's bounded queue already handles a paused terminal, `ssh/channel.rs`); `exited`/`event` with the §11 sentences (the
   broker composes `{n}` and "while the command was running", 1a plan line 34); IPC EOF → close the shell and session from that
   std thread.
3. Directory and auth (permanent): `HostDirectory` (alias or id → `Target` with pins in `Hop.pinned`; `pin`/`replace_pin`; duplicate
   alias → "use --id", spec line 217) + a fake; `AuthSource` over vault + keychain (keys unlocked **before** `connect`, passphrase from
   `vault:passphrase:<id>` or a CLI question, up to three tries like `PASSPHRASE_ATTEMPTS`, `agent/broker.rs:24`; `password(hop)` =
   keychain `host:<id>` or a secret typed earlier in this attempt; `interactive` → CLI questions within the deadline); `HostKeyPolicy`
   comparing with `Hop.pinned`. Copy, don't import, what `agent/` has (passphrase account name, `vault_slot_of`) — 1c deletes `agent/`.
4. Host-key confirmation: the Rust hub + Tauri commands + event + the CLI notice. Either pull a **minimal** window forward from 1d
   (bare view routed by label, modelled on `AgentApprovalWindow`; 1d does the final strings, mismatch polish, "Forget pinned key") — my
   recommendation, because the fail → ask → pin → reconnect loop is the riskiest broker logic and should run on a dev build in 1b — or,
   if the window stays in 1d, let the temporary adapter seed pins read-only from `~/.ssh/known_hosts` (throwaway, and hashed names
   need `ssh-keygen -F` like `deploy.rs:732-736` or an HMAC-SHA1 match).
5. Starting the host: §1's code moved out of `mcp.rs`; `--host` (old flag accepted); keep-alive while sessions are live (window close
   hides, `lib.rs:192-206`); hand-over restarts the broker.
6. CLI `sshelter connect <alias> | --id <id>`: `main.rs` arm before Tauri; start-and-wait (12 s, exact sentence); a `Terminal` trait
   with a fake (raw mode in/out, echo-off prompts, size); termios via libc/nix; SIGWINCH via tokio `signal`; restore on every exit path
   including panic (guard + panic hook, explicit restore before `process::exit`); `$TERM` default `xterm-256color`; exit with the
   remote code.
7. Connect button, palette and tray: argv `[current_exe, "connect", alias]` through the unchanged `build_launch_command`; resolve the host
   first so a refusal (ProxyCommand, key not in vault) is a toast, not a terminal; delete autofill, the one-shot channel, its event
   listener and the dead deploy helpers (§3). On Windows keep `ssh <alias>` until phase 3, or say "not on Windows yet" (decide).
8. The temporary `SshConfigDirectory` adapter (§5), in its own module marked for deletion in 1c.

Out: `exec`, MCP, approval modes, the session log and requester display (phase 2, spec lines 317, 265); the session list and Windows
console (phase 3, line 318); records, import, migration (1c); host editor and pinning UI beyond the minimal window (1d).

## 9. Risks and open questions (most dangerous first)

1. **Windows.** The CLI would be the GUI-subsystem binary (`main.rs:2`): no console unless attached; `cmd` does not wait for GUI
   programs and `AttachConsole(ATTACH_PARENT_PROCESS)` fails without a parent console (MS docs, §3). The broker transport is a synchronous
   named pipe while a shell relay needs concurrent read and write on one handle (MS docs, §2). Probably needs a separate console-subsystem
   helper (or another trick) plus tokio's overlapped pipes. Unmeasured; spec §16 line 348 already lists it. Decide 1b's Windows
   stance up front.
2. **The connect-retry state machine** (the core of 1b), shaped by the engine's rules:
   - an unknown or changed key fails `connect` at once (`ssh/traits.rs:14-21`); the broker asks the window, pins, reconnects
     (spec line 194);
   - a password-first hop's password is fetched **before** the connection and before the host-key check (`russh_engine.rs:398`;
     `fake.rs:22-24`), so first contact asks twice unless the typed password is kept across the retry (progress:160);
   - the fallback password after a refused key is called during the login and must be quick (`ssh/traits.rs:95-98`; a person typing
     there makes russh spin, `russh_engine.rs:18-22`), so it answers from the keychain or returns `None`, and the broker then asks and
     reconnects password-first (progress:152). `AuthFailed` carries only `tried` and `reason` (`ssh/error.rs:23-25`,
     `russh_engine.rs:779`), but the engine calls `password()` during login only when the server offers it (`russh_engine.rs:667-669`,
     `710-715`), so the AuthSource can record that call;
   - remember a cancelled password, because keyboard-interactive follows on servers that offer it (progress:160);
   - which method a host with no key and no saved password starts with (password-first asks before connecting; KI-only servers then ask
     again) is a design decision; one-time codes cannot survive a reconnect;
   - `SessionError::Timeout` is not a dead connection (progress:108); always go through `SshEngine::connect`, which attaches the
     watcher (progress:144); the policy runs on the thread that called `connect`, so the broker must not hold a lock the policy takes
     (progress:31).
3. **Session and app lifecycle.** The IPC server's 300 s read timeout would end idle shells (`server.rs:67-70,128`); window close only
   hides for `close_to_tray`/MCP keep-alive (`lib.rs:192-206`); hand-over only republishes the MCP bridge and exists only in release builds
   (`lib.rs:117-138`); a closed terminal tab kills the CLI (SIGHUP), and the broker must close the session from a std thread (may block
   ~3 s per hop on a dead link; progress:122,127,146) without stranding a server process when a shell is closed before its prompt
   (progress:118); app quit ends every session (spec line 79). Each is simple alone; together they need a manual checklist on both
   platforms.

Also worth deciding: how `sshelter` reaches the user's PATH for typing `sshelter connect` by hand (spec §1 goal 2 assumes it; nothing
installs it; the Connect button uses the absolute path); Linux AppImage's `current_exe()` is the temporary mount path; `identify()` must
drop SSHelter's own executable before phase 2 shows requesters; `HostId` is unvalidated (16-hex is the record layer's rule, progress:31);
validate `keepalive_secs` > `connect_timeout_secs` in the importer/editor (progress:127); `FakeEngine` may need a "disconnect now" hook for
broker tests (progress:50); the queue's per-chunk overhead and gap notice were deferred to 1b (progress:38,52); `ssh/mod.rs:46-67`
fails the build if any file but `russh_engine.rs` names `russh::` or `use russh`, comments included.
