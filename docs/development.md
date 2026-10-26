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

`src-tauri/src/gcp/` holds everything Google: `relay.rs` is the SSH Relay v4 wire format and `iap.rs` the WebSocket tunnel with the reconnect rule gcloud documents for its `_OnClose` (a failure without a Close frame, or close code 4004, is reconnected by session id for up to 15 minutes, every attempt bounded; any other Close frame ends the tunnel, and the engine repeats the reason), pumping each direction independently, both ported from gcloud 590's `iap_tunnel_websocket*.py` under the Apache License 2.0 recorded in `gcp/NOTICE.md`; `auth.rs` reads gcloud's credential files and refreshes tokens without running gcloud; `oslogin.rs`, `pam.rs` and `rest.rs` are the calls the broker makes before connecting (reqwest for OS Login, Google's client library for Privileged Access Manager, below). The engine's `Hop::transport` chooses TCP or a tunnel for the first hop only (`russh_engine.rs` hands the tunnel stream to its existing handshake), and `HostDirectory::prepare` runs the PAM grant check and OS Login between the resolve and the connect, outside the directory lifecycle lock.

Privileged Access Manager goes through Google's Rust client library, `google-cloud-privilegedaccessmanager-v1`, with `google-cloud-auth`, `google-cloud-gax` and `google-cloud-wkt`: `gcp/credentials.rs` implements the library's `CredentialsProvider` over Lunport's own token source, so the gcloud sign-in files and the account rules stay Lunport's and the library only adds the `Authorization` header. `gcp/pam.rs` holds the grant model and `request_and_wait`, the one request flow the connect (`session/record_directory.rs`) and a host's Access grant and Request grant (`session/transports.rs`: `transports_pam_status`, `transports_pam_request`) share. A connection that needs a grant asks for it through a question of its own kind, `QuestionKind::Grant` (`session/protocol.rs`), which the authentication window shows as the Request-a-grant form (`AuthenticationWindow.tsx`, a five-minute deadline); connections that need the same grant at once share a gate (`session/grants.rs`), and a tunnel IAP refuses with 4033 within two minutes of the grant becoming active is retried (`session/connect.rs`). In tests the library client is built `with_endpoint(server.url())` against mockito; the library sends enums as numbers and `$alt=json;enum-encoding=int`, so PAM mocks match `callerRelationship=1` and otherwise take any query. Design and plan: `docs/superpowers/specs/2026-10-25-pam-grant-request-design.md`, `docs/superpowers/plans/2026-10-25-pam-grant-request.md`. The MCP tools `update_host`, `set_transport` and `remove_transport` (`mcp/management.rs`) build a change on a snapshot, show it in the approval window as rows of `old → new` under a proposal `kind`, and save on consent against the host's revision or the transport as it was; design and plan: `docs/superpowers/specs/2026-10-26-mcp-edit-hosts-transports-design.md`, `docs/superpowers/plans/2026-10-26-mcp-edit-hosts-transports.md`.

`session/transports.rs` holds the commands behind the host editor, a host's details and the Google Cloud page (`GoogleCloudPanel.tsx`: Google sign-in, Access grants and Hosts through IAP; it edits no route). `transports_oslogin_profile` backs **Use OS Login username**, `transports_pam_status` and `transports_pam_request` a host's Access grant and Request grant (the request takes an optional `entitlement` the route lists, answers with that entitlement and remembers the justification and length in the device-local grant memory), `gcp_accounts` lists the accounts gcloud holds credentials for (`legacy_credentials/*/adc.json` under its config directory, read without writing there) and checks each sign-in through the token source (the editor's account picker reads the same answer), `gcp_pam_grants` answers one row per entitlement the routes name, and `transports_iap_probe` is **Check through IAP**: it opens an IAP tunnel to the route's instance and the host's port, closes it at once, is bounded at 20 s, shares the port check's limit of four checks at once and asks for no grant and no sign-in. `transports_save` and `transports_delete` are gone: the host editor sends a route with its host, as the optional `route` argument (`RouteChange`: the route as displayed, `expected`, and the one to save, `kind`) of `records_host_create` / `records_host_update`, applied in the same edit (`transports::apply_route_change`), and deleting a host removes its route in that edit (`transports::remove_route`). MCP writes through `transports::set` itself.

A route is a `Meta` record `transport:<host-id>` with the payload `{schema: 1, transport: ...}` (`sync/transports.rs`), the envelope tunnel rules use. In a library that uses central sync (`transports::central_library`: this device has cut over and keeps the library's rows in its account) the route is the library's. `transports::set` writes a dirty `transport:` row of the account under the tunnel rules' write gate, and the capture publishes it in the Catalog's `transports` field (`sync/central/projection_local.rs`, `sync/central/payload.rs`): a `Vec<HostTransport>` declared like `tunnels`, omitted when empty so that a library without routes serializes as it always did and stays readable by every release, with at most one route per host, at most 256 (`MAX_ROUTES`), each passing `HostTransport::validate` with `pam.justification` null. The initial and delta projections (`sync/central/projection_cache.rs`, `sync/central/projection_delta.rs`) rebuild the rows from the Catalog, and `transports::get` and `view` read the account row when there is one, else the `local.transports` entry. The Catalog is one sync record of at most `MAX_PLAINTEXT_BYTES` (64 KiB) shared with collections, group orders and tunnel rules, so every write that changes it (`transports::set`, tunnel saves, MCP `set_transport`, the adoption merge) builds the candidate Catalog and is refused when it would not fit, with the "This library has no room for more routes or tunnels" sentence (`NO_ROOM`); removing a route or a tunnel is never checked. What a grant request taught the device, the last justification and length, is not part of the route: it is the device-local `LocalState.transport_grants` (`GrantMemory`), so requesting a grant never edits the synced library. Local state version **10** (`TRANSPORT_SYNC_STATE_VERSION`) is raised by synced route rows or by that grant memory, and a 1.12 build refuses to open it; version **9** (`TRANSPORT_STATE_VERSION`) still covers device-local routes, and an initial projection that keeps a device's routes is written at 10 as well. Routes saved before central sync stay in `local.transports` through first publication and adoption (`sync/central/initial_projection.rs`, `keep_routes`; adoption re-keys them with the hosts' new ids, `transports::follow_hosts`), and one publish step moves them into the library: the capture's Catalog (`catalog_of` with `local_routes`) takes each one whose host the library has, while it fits, and a route that does not fit stays local, which the Google Cloud page says. Chain-mode and account-less libraries keep routes in `local.transports` only. Leaving a chain-mode account (`sync/record_leave.rs`) keeps the routes of the hosts that stay as local ones (`transports::preserve_on_leave`); a library that uses central sync has no leave path yet, so a later one must call it with the state from before the account's rows are dropped. Design and plan: `docs/superpowers/specs/2026-10-26-iap-connect-via-design.md`, `docs/superpowers/plans/2026-10-26-iap-connect-via.md`; the record's first design: `docs/superpowers/specs/2026-10-25-gcp-iap-oslogin-design.md`.

Validation without Google: `gcp::testing::FakeRelay` speaks the relay subprotocol in front of a TCP target and can refuse, close with a code, cut the socket or stall; `cargo test --locked --lib -- gcp:: ssh::engine_tests::iap` runs the codec, credential, tunnel and engine tests (the engine ones use the scratch sshd), `session::record_directory::tests::gcp_transport` the OS Login and PAM decisions with a scripted client, `session::connect::tests` and `session::grants` the grant question, the gate and the IAP grace with fakes, `session::transports` the commands behind the Google Cloud page and a host's details (grant state and requests, gcloud's accounts, the grant rows, and the probe over `FakeRelay`), `sync::transports` the route records, their room in the Catalog and the grant memory, and `sync::central::projection_local`, `sync::central::projection_delta` and `sync::central::adoption` the Catalog's routes, both projections and the move of a device's routes into the library. `pnpm exec vitest run src/components/records/google-cloud.test.tsx src/components/records/connect-via.test.tsx src/components/records/markup.test.tsx src/components/records/trust-and-probe.test.tsx src/components/AuthenticationWindow.test.tsx` runs the Google Cloud page (`GoogleCloudPanel.tsx`), the editor's Connect via (`IapRouteFields.tsx`), a host's card and details, Check through IAP and the grant request (`GrantRequestDialog.tsx`), and the Request-a-grant form. The interface preview shows the Google Cloud page, the host editor's Connect via, and the cards and details, with fakes of these commands in their real shapes: `pnpm exec vite`, then `http://localhost:1420/dev-preview.html?scenario=iap`. The live check against a real jump box is manual.

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
