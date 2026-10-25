# Developing Lunport

Lunport uses Tauri 2, Rust, React, TypeScript and Vite, with Tailwind, shadcn/ui, TanStack Query and Zustand. Privileged file access and SSH operations run in Rust; the WebView has no filesystem or shell-execution permission. The Records workspace uses the built-in SSH engine; Legacy retains OpenSSH configuration tooling.

## Local setup

Install Rust through mise or rustup, Node and pnpm. macOS needs Xcode Command Line Tools. Linux needs the Tauri platform dependencies, including `libwebkit2gtk-4.1-dev`, `build-essential`, `libssl-dev` and `librsvg2-dev`.

With mise, run `mise install` for the project's Rust toolchain. Prefix commands with `mise exec --` when mise is not active in your shell.

```bash
pnpm install
pnpm tauri:dev
pnpm build
pnpm test
cd src-tauri
cargo test --locked
```

Some backend tests need a scratch OpenSSH server or platform-specific facilities; credential-service tests can touch the OS keychain. The safe suite and platform-specific checks are defined in [the SSH engine workflow](../.github/workflows/test-engine.yml) and [the Windows workflow](../.github/workflows/test-windows.yml).

## Test feedback time

For an edit to one component or Rust module, run its tests first, then leave the complete platform suites to CI:

```bash
pnpm test src/components/HostEditor.test.tsx
cd src-tauri
cargo test --locked --lib sync::central::server_change -- --test-threads=2
```

Development/test builds optimize the existing OpenSSH PEM/base64 parsers as well as the crypto primitives. Application code keeps debug assertions and overflow checks; fixture sizes and validation remain unchanged. CI runs the actual Production and Development release-library boundaries in parallel with the complete debug suites. Windows runs each migration/publication/console test once in the complete suite; the separate Win32 handle/DACL probe remains.

## Isolated Development profile

`pnpm tauri:dev` runs **Lunport Dev**. `pnpm tauri:build:dev` builds a release-mode Development bundle. The Development profile uses `org.homelab.sshelter.dev`, the `SSHelter Development` credential service and a sandbox home under its data directory. It can run beside Production. Writes remain in that sandbox; updater and login integration are disabled. Selected external import sources are read and copied, preserving the originals.

Development refuses Legacy system-SSH evaluation, Connect, deployment and MCP execution before spawning OpenSSH. Records connections use the built-in engine. A build whose configured product name or identifier disagrees with its compiled profile refuses initialization.

An ordinary `pnpm tauri build` uses the Production profile. Keep the two profiles separate when validating existing data.

## SSH forwarding

`ssh/forward.rs` defines the engine-neutral forwarding contract. The existing russh connection owns TCP listeners, remote forwarding registrations and SOCKS5 CONNECT relays, including jump chains, cancellation and bounded stream concurrency. `session/tunnels.rs` keeps human-started runtime handles outside persistent state and joins the broker's quit barrier. The main-window commands reuse the existing connector, native authentication and host-key policy; this feature adds no agent forwarding, MCP tool or credential delivery to the WebView.

Each definition is an optional account `meta` record named `tunnel:<16-hex-id>`, with payload `{schema: 1, rule: ...}`. Host and account protocol schemas stay unchanged. Separate records give unrelated definitions independent LWW revisions; UI mutations compare the complete displayed rule. Newer opaque revisions block edits and starts. Older clients retain these envelopes without changing their contents. Local definitions live in `local.tunnel_rules`; local state format **6** protects that field from downgrade. Joining an account publishes local definitions after an authenticated baseline, while leaving remaps preserved host IDs. Code rotation re-encrypts the existing metadata through the generic rotation path. Live listeners, ports, errors and active connection counts never sync or persist.

For a native Development preview, run `python3 scripts/preview-ssh.py --forwarding`, import its disposable host/key and use the printed HTTP destination as a tunnel target. The fixture remains loopback-only and stops its SSH sessions on Ctrl-C.

Validation: `cargo test --locked --lib ssh::engine_tests::forward` uses disposable OpenSSH servers for all three forwarding types, binary traffic, TCP half-close, active-stream cancellation, occupied ports, denied remote requests, remote auto-port allocation, DNS via SOCKS and a two-hop chain. `scripts/validate-group-order-compat.sh` runs an injected test against the unmodified published v1.2.0 merger to check opaque rules and tombstone retention. The normal Rust suite also covers rule merge, future versions, account detach, runtime isolation and quit barriers; frontend tests cover independent starts, missing hosts, remote changes and routes.

## Google Cloud IAP transports

`src-tauri/src/gcp/` holds everything Google: `relay.rs` is the SSH Relay v4 wire format and `iap.rs` the WebSocket tunnel with the reconnect rule gcloud documents for its `_OnClose` (a failure without a Close frame, or close code 4004, is reconnected by session id for up to 15 minutes, every attempt bounded; any other Close frame ends the tunnel, and the engine repeats the reason), pumping each direction independently, both ported from gcloud 590's `iap_tunnel_websocket*.py` under the Apache License 2.0 recorded in `gcp/NOTICE.md`; `auth.rs` reads gcloud's credential files and refreshes tokens without running gcloud; `oslogin.rs`, `pam.rs` and `rest.rs` are the REST calls the broker makes before connecting. The engine's `Hop::transport` chooses TCP or a tunnel for the first hop only (`russh_engine.rs` hands the tunnel stream to its existing handshake), and `HostDirectory::prepare` runs the PAM grant check and OS Login between the resolve and the connect, outside the directory lifecycle lock.

A transport is a device-local `Meta` record `transport:<host-id>` in `local.transports` (`sync/transports.rs`), gated by state version 9; it is cleared by the initial central projection and re-keyed on leaving an account, and is not published yet. The record keeps the envelope tunnel rules use, so syncing it later is additive. Design and plan: `docs/superpowers/specs/2026-10-25-gcp-iap-oslogin-design.md`.

Validation without Google: `gcp::testing::FakeRelay` speaks the relay subprotocol in front of a TCP target and can refuse, close with a code, cut the socket or stall; `cargo test --locked --lib -- gcp:: ssh::engine_tests::iap` runs the codec, credential, tunnel and engine tests (the engine ones use the scratch sshd), `session::record_directory::tests::gcp_transport` the OS Login and PAM decisions with a scripted client, and `pnpm test src/components/records/transport.test.tsx` the Google Cloud panel (`TransportsPanel.tsx`, `TransportFields.tsx`). The live check against a real jump box is manual.

## Embedded SSH terminal

Choose **Lunport (in app)** in **Settings → Connections** or the Records connection menu. The choice, terminal text size and cursor preference persist locally through the existing settings store and settings export/import. New installations default to the app terminal; existing terminal preferences are preserved. Records connections use stable host IDs and Legacy connections use saved aliases through the same broker. Unsupported Legacy directives are refused by the existing adapter; Development still refuses external OpenSSH evaluation.

Double-click a ready host or use Quick connect. Library and session tabs stay mounted when switching. Tab metadata is transient; raw data, credentials and live handles never enter persistent settings. Closing a running/connecting tab asks before ending its session; ended tabs close immediately. The workspace supports up to eight tabs, adjacent-tab selection on close, Ctrl+Tab switching, terminal Find and text-size shortcuts. A workspace reload revokes pending opens before ending its existing sessions.

The renderer is `@wterm/dom` with `@wterm/ghostty`, both pinned to 0.5.4. Vite bundles the Ghostty WASM asset locally, including in release builds; no external terminal, WebSocket server, Bun or Zig toolchain is needed. Rust connects to the existing protocol-1 broker, preserving the SSH engine, native password/passphrase prompts, host-key verification, jump hosts and quit lifecycle. The WebView receives ordered binary packets through a Tauri channel, with a 256 KiB acknowledged output window and bounded input. Raw terminal bytes and keystrokes never enter React state or application logs. Remote clipboard writes and image storage are disabled. App appearance updates terminal colors without reconnecting.

For a disposable real SSH target on macOS or Linux:

```bash
python3 scripts/preview-ssh.py
```

Keep that process running. It prints a loopback port, a temporary SSH config and a throwaway private key. Import the printed config into **Lunport Dev**, explicitly select its optional key copy, then double-click `terminal-preview`. Verify the host fingerprint against the printed fingerprint. The remote shell uses an empty temporary HOME. Ctrl-C stops the fixture and its sessions, then removes its files; its imported host/key can be removed from the Development library afterward. Production data is not involved.

Validation: `pnpm test` includes terminal transport ordering, binary data, input limits and cancellation races. `cargo test --locked --lib session::embedded::tests` includes a real scratch OpenSSH shell, ANSI/Unicode output, remote PTY resize, exit status and cleanup, using only disposable keys, for both ID and alias queries. The SSH engine's existing bounded overflow notice still applies if a producer outruns the renderer; the preview does not claim lossless output under sustained overload. Splits and remote process restoration are not implemented; reconnect starts a new shell.

## Brand assets and compatibility

The mark geometry lives in [lunport-mark.json](../src/brand/lunport-mark.json); [product.json](../src/brand/product.json) supplies the About copy. Regenerate native and web icons from the canonical geometry with:

```bash
node scripts/generate-brand-icons.mjs
```

Use Lunport for visible product copy and `ysya/lunport` for current repository links. Bundle IDs, credential services, executable names, SSH paths and persisted storage keys intentionally retain their SSHelter identities. See [installer compatibility](../src-tauri/installers/README.md) before changing any of them. New MCP setup and protocol metadata use `lunport`; automatic setup preserves an existing owned `sshelter` alias and its settings rather than creating a duplicate. Historical releases, validation records and signatures retain their original names.

The macOS pre-runtime migration in `macos_install.rs` renames only the running legacy app bundle, preserves its parent and leaves a relative compatibility symlink. It uses no-overwrite moves, a bounded installation lock and a recovery journal. Permission repair elevates the system interpreter with a fixed Foundation file-operation program and literal validated paths. It does not execute the mutable application binary as root, start Tauri or read user credentials. Development can exercise migration only inside its existing write sandbox. Login repair changes only an existing `SSHelter` entry whose old command resolves to this installation.

MCP client setup in `mcp_setup.rs` uses the existing stdio adapter and grants no host access. Codex TOML edits preserve comments; Claude JSON edits preserve unrelated values. Existing files are backed up with owner-only permissions, managed symlinks are refused and concurrent changes are checked before replacement. Cursor/VS Code URLs are generated in Rust from a fixed client enum and this installation's command; the WebView receives no new filesystem or general execution capability. Development writes client fixtures only under its sandbox home and does not open external install links. Linux AppImage setup records the persistent AppImage path rather than its temporary inner executable.

The 2.11.2 runtime has a narrow [context ownership patch](../src-tauri/vendor/tauri-runtime-wry/LUNPORT_PATCH.md). Preserve its provenance and run the handle-only, native tray and actual GUI regressions before updating or removing it. The patch keeps worker handle clones from copying a non-atomic native event-loop reference count.

## Central account builds

Central sync is enabled in normal macOS, Windows and Linux desktop builds through the default `central-sync` feature. Windows uses pinned native filesystem handles, owner-only ACLs, bounded source capture and write-through atomic publication; Unix permission tests remain platform-specific while migration and synchronization fixtures run on every supported platform. The old `central-sync-preview` name remains a compatibility alias. Release CI injects `SSHELTER_RELAY_URL` into the native build; fresh account setup uses that HTTPS service while an existing pinned account keeps its original service. Self-hosted builds may leave it unset and enter a service in Sync.

The ordinary-library `app_profile_build` integration test checks the shipped capability outside `cfg(test)`. Central tests use isolated in-memory credentials; never run credential-service tests against a real user Keychain as a general release check.

## Release workflow

Stable releases use release-please. A push to `main` opens or updates a release PR; merging that PR creates the version tag and GitHub Release, then builds the platform installers and updater assets. Review the version, changelog and checks before merging a release PR. An ordinary feature or documentation merge does not itself publish an installer.

For each release, check the README, user guide and installer names against the actual packages and verify both update channels. Historical SSHelter releases and their assets remain intact. Native runtime changes require a failing baseline reproduction, repaired regression checks and full platform validation before publication.

For a beta, run **publish beta** in GitHub Actions with a new `X.Y.Z-N` version, using a numeric suffix. The workflow stamps the version, creates the prerelease, builds the platforms and updates the `updater-beta` manifest. Beta-channel devices can receive Stable releases too.

If a build fails, use **Re-run failed jobs** on that run to keep the same source and inputs. Do not use `build-platform.yml` for a beta: it does not stamp the beta version or update that channel. Use a new version for changed release content; preserve published tags, installers and signatures.

The **update beta channel** workflow can reconcile the Beta manifest with an existing release. It checks that the release manifest is complete, never moves the channel backwards and leaves an already current channel alone.

Before promoting a release, the channel script maps updater URLs to that release's public download assets and updates its `latest.json` if needed. GitHub REST asset URLs consume an [unauthenticated API quota](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) and can return HTTP 403. This metadata repair preserves versions, platform aliases, installer bytes and signatures; it does not require rebuilding or retagging a release.

The Windows bundle workflow separately validates helper placement and old-version installer upgrades. It supports verified candidate reuse for installer-only diagnostics; see [installer documentation](../src-tauri/installers/README.md). These unsigned CI artifacts are not published releases.

## License

Lunport is licensed under [PolyForm Noncommercial 1.0.0](../LICENSE), Copyright © 2026 Frank Sung. Included third-party installer templates retain their separate [MIT notice](../src-tauri/installers/LICENSE_TAURI_MIT).
