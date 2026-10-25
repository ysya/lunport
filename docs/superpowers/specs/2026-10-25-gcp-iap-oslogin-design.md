# Google Cloud IAP tunnels and OS Login in the built-in SSH engine

Frank's team is moving its GCP jump boxes (`jumpbox` in `eng-dev-396409` asia-east1-b for dev, and in `knowknow-prod`) behind Identity-Aware Proxy TCP forwarding with OS Login (KNOW-529, KNOW-596). Today that needs `gcloud compute ssh --tunnel-through-iap`, which Lunport's engine cannot express: `ProxyCommand` is unsupported on purpose, and spawning `gcloud` would hand the connection to a program Lunport does not control. This design gives a saved host a **transport**: instead of a TCP connection to `hostname:port`, the first hop is reached through an IAP WebSocket tunnel opened by Lunport itself, logged in with the Google account's credentials that `gcloud auth login` left on disk, as the OS Login POSIX user, after an optional check that a Privileged Access Manager grant is active. Everything else (host keys, vault keys, passwords, jump chains, tunnels, the in-app terminal, MCP) stays as it is.

Author's standing: Frank was away while this was written. The decisions below marked **(my call)** were made by the author from the codebase and the brief; the rest come from the brief or the code. Frank reviews the branch before anything lands.

## Goals

- Connect to a saved host whose first hop is a GCE instance through IAP TCP forwarding, with no `gcloud` process: the SSH Relay v4 WebSocket protocol as gcloud speaks it, including reconnects by session id.
- Log in with OS Login: take the POSIX username from the account's login profile, and register the host's vault key with OS Login when it is not there yet.
- Before connecting to a production host, optionally confirm an active PAM grant exists and say so plainly when it does not, instead of a bare `4033` from IAP.
- Use the Google account Frank already signed in with `gcloud auth login` (the key for `frank@retower.io`, OS Login user `frank_retower_io`, is registered) by reading gcloud's credential files; a route may name which account.
- Work from `sshelter connect`, the in-app terminal, saved SSH tunnels and MCP, because they all go through the broker and the engine.
- Keep every existing client's library readable: no change to the host payload schema or to account protocol schemas.

## Non-goals (this round)

- Syncing transports between devices. The record shape is sync-ready (the same `LocalRecord` envelope and `transport:<host-id>` wire id tunnel rules use), but publication, merge and central projection are a follow-up, see "Storage".
- HTTP proxies and mTLS (context-aware access, enterprise certificates) for the WebSocket; BeyondCorp host-based tunnels (`--host`/`--dest-group`); Cloud Run tunnels. The URL builder keeps the fields so these can be added.
- Service-account JSON credentials (JWT flow). Only `authorized_user` credentials (refresh tokens) are read.
- Requesting a PAM grant from Lunport. A grant emails the admins, so it stays an explicit action outside Lunport (`scripts/prod-access.sh`); Lunport only checks and points there.
- Importing `ProxyCommand gcloud compute start-iap-tunnel …` lines from `~/.ssh/config` into transports. The import review keeps showing them as unsupported directives.
- Compute API calls (listing instances, resolving external IPs). The user types project, zone and instance.

## Anti-goals

- Never run `gcloud`, never read `credentials.db` or `access_tokens.db` (sqlite), never write anything under gcloud's config directory.
- No access token, refresh token, client secret or OS Login profile in logs, errors, settings exports or sync.
- No new filesystem, network or shell capability for the WebView: all of this runs in Rust behind existing commands.

## Constraints and sources

- Protocol source of truth: gcloud's `googlecloudsdk/api_lib/compute/iap_tunnel_websocket.py`, `iap_tunnel_websocket_utils.py`, `iap_tunnel_websocket_helper.py` (Google Cloud SDK 590.0.0, Apache License 2.0). The Rust port keeps the Apache notice in a `NOTICE.md` next to the module. `cedws/iapc` (Go, MIT or GPL-3.0 at the user's choice) is a cross-check only; nothing is copied from it.
- Crates (my call): `tokio-tungstenite 0.30` with the `rustls-tls-native-roots` feature (rustls 0.23, tokio-rustls 0.26 and rustls-native-certs 0.8 are already in the lockfile through reqwest), the existing `reqwest 0.13` for REST and token refresh, `serde_json`, `zeroize`. No `gcp_auth`: it shells out to `gcloud` for user credentials and only reads the ADC file otherwise; what we need is a few hundred lines and testable with mockito.
- `ssh/russh_engine.rs` stays the only file that names russh. The tunnel is an `AsyncRead + AsyncWrite` stream handed to the existing `handshake`.
- The engine's rules hold: every wait is bounded, nothing waits for a person inside a callback, liveness is read from the connection's state.
- Dev jumpbox: `eng-dev-396409`, zone `asia-east1-b`, instance `jumpbox`, port 22, interface `nic0`. The IAP firewall rule (`vpc-1-iap-tunnel-fw`, tag `iap-tunnel`, source `35.235.240.0/20`) exists in both projects. Prod needs an active `prod-operate` or `prod-admin` grant (`roles/iap.tunnelResourceAccessor` comes from the grant) and IAP can take about 1½ minutes after activation to honour it. Angus has not applied OS Login to dev yet; the live test waits for him.

## What gets built

### Storage: a transport record per host

A host's transport is an optional record beside the host, not a field of it. `HostPayload` is `deny_unknown_fields` and `decode_host` accepts schemas 2 and 3 only, so a new field or schema would make every older client's whole snapshot fail. Tunnel rules solved the same problem with `Meta` records named `tunnel:<id>`; transports follow that shape.

- Module `sync::transports` (my call on the name: "route" already means a jump chain in `record_repository`, "via" is the engine's previous hop). Wire id `transport:<host-id>`, one per host. Payload `{ "schema": 1, "transport": HostTransport }`.
- `HostTransport { host_id, kind }` with `kind` a tagged enum; this round has one variant:

  ```
  gcp_iap {
    project: String,            // project id, e.g. eng-dev-396409
    zone: String,               // e.g. asia-east1-b
    instance: String,           // instance name
    interface: String,          // default "nic0"
    account: Option<String>,    // Google account email; None = gcloud's active account
    os_login: bool,             // take the username from OS Login; register the key
    pam: Option<PamCheck>,      // { entitlements: Vec<String>, location: String }
  }
  ```

  Validation: host id format; project `[a-z][a-z0-9-]{4,28}[a-z0-9]` or a project number; zone and instance as GCE names; interface `nic[0-7]`; account a plausible email; entitlement ids as GCP resource ids; location defaults to `global`.
- Stored in `local.transports: BTreeMap<String, LocalRecord>` in `SyncStateV3`, gated by `TRANSPORT_STATE_VERSION = 9` exactly as `tunnel_rules::STATE_VERSION = 6` gates `local.tunnel_rules`: saving the first transport raises the local state version, and an empty map leaves the version alone. An older Lunport on the same machine then refuses to open the library at all (its startup probe reports a newer format and blocks every write; it does not archive or rewrite the file), the same as after the tunnel-rules and central versions. Validation in `records_v3/state.rs` mirrors the tunnel checks. The map is local to the device whatever the host's scope (local or space).
- Host ids are not forever, so the device-local map follows the two existing places where tunnel rules are re-keyed, and nowhere else: leaving an account (`record_leave`) carries a preserved host's transport to its new local id and drops the others; the initial central projection (`central/initial_projection.rs`), which replaces `local.hosts` and clears local tunnel rules and credential approvals, clears `local.transports` too (it also forces the state version to 8, so a populated map would otherwise fail validation and block adoption). After adopting central sync the person enters the transport again, once; the editor shows "Direct" until then. Central library migration on another device never sees transports, because they are not in the account. This is the deliberate v1 trade: Frank sets the transport once per device. The follow-up that syncs them adds `publish_local`, merge recognition and central projection the way tunnel rules have them, with no change to this record shape.
- Commands (`session/transports.rs`): `transports_get(host_id)`, `transports_save(transport, expected)`, `transports_delete(expected)`, main window only, compare-and-set against the displayed value like tunnels. Bindings through ts-rs as `ForwardSpec` and `TunnelRule` are.
- `RecordDirectory::resolve_material` looks the first hop's transport up in the same snapshot and sets `hop.transport`. A transport on a host that is not the first hop of the chain fails with a host error: "`<alias>` connects through Google Cloud IAP and cannot be reached through a jump host." (IAP replaces the client's TCP connection; it cannot ride a `direct-tcpip` channel.)

### Engine: `Transport` on a hop

- `ssh/types.rs`: `Hop.transport: Transport`, `enum Transport { Tcp, GcpIap(IapTarget) }`, `Hop::new` sets `Tcp`. `IapTarget { project, zone, instance, interface, account: Option<String>, url_override: Option<String> }`; `url_override` is for tests (gcloud has the same knob) and never comes from a record.
- `check_chain` refuses `GcpIap` on any hop but the first (`BadJumpChain`).
- `connect_hop`, `via == None`, `GcpIap`: open the tunnel inside the hop's connect-timeout budget, then run the existing `handshake` over it. The handshake's `SocketGuard` has a tunnel counterpart: the guard owns an abort handle on the tunnel's pump task; dropped before `release` (a handshake that ran out of time) it aborts the pump, russh's task reads end-of-file and ends. `nodelay` does not apply.
- `EngineOptions.gcp_tokens: Option<Arc<dyn gcp::auth::TokenSource>>`. `EngineOptions::default()` installs the file-backed store (below), so every `RusshEngine::new()` in the app and the CLI has it; a hop with `GcpIap` and `None` fails as `Unreachable` ("Google Cloud credentials are not configured"). Tests install a static token. `EngineOptions` keeps `Debug` by hand (the source is printed as a tag).
- Errors are a new `ConnectError::Tunnel { hop, text }` whose `Display` is the text itself, one sentence each (see "Error texts"); `Unreachable` would wrap them in "Could not reach `hostname:port` (…)", which names an address IAP never uses. `connect.rs`'s `hop_of`/`failure_of` treat it like `Unreachable` (failure kind `connect`, said through the jump host when it is one). A tunnel that ends after the login is a lost connection like any other (`DisconnectKind::ConnectionLost`).

### `gcp` module (new, `src-tauri/src/gcp/`)

`gcp/relay.rs`, the protocol, pure functions and a state object, no I/O:

- URLs: `wss://tunnel.cloudproxy.app/v4/connect?project=…&port=…&newWebsocket=True&zone=…&instance=…&interface=…` and `/v4/reconnect?sid=…&ack=…&newWebsocket=True&zone=…`; `url_override` replaces scheme, host and path root.
- Frames, big-endian: `u16 tag`; `CONNECT_SUCCESS_SID 0x0001` + `u32 len` + sid bytes; `RECONNECT_SUCCESS_ACK 0x0002` + `u64 ack`; `DATA 0x0004` + `u32 len` + bytes, at most 16 384 bytes of payload per frame; `ACK 0x0007` + `u64 ack`. Unknown tags are ignored; trailing bytes after a frame are dropped, as gcloud does.
- Bookkeeping: bytes received and acked; an ACK is owed when `received - acked > 2 × 16 384`; sent frames stay in an unconfirmed queue until the server's ACK covers them; an ACK that goes backwards or beyond what was sent is a protocol error that ends the tunnel; `RECONNECT_SUCCESS_ACK` confirms up to its ack and the rest is resent first.
- Headers: `Authorization: Bearer <token>`, `Origin: bot:iap-tunneler`, `Sec-WebSocket-Protocol: relay.tunnel.cloudproxy.app`, `User-Agent: lunport/<version>`.

`gcp/iap.rs`, the tunnel: `Tunnel::open(target, tokens, user_agent, deadline) -> (Stream, Guard)`.

- A pump task owns the WebSocket and the relay state; the `Stream` is the other end of two bounded byte pipes and implements `AsyncRead + AsyncWrite + Unpin + Send + 'static`. Writes are cut into ≤16 KiB DATA frames. At most five unsent frames are queued; a full queue applies back-pressure to the writer instead of growing.
- Open: fetch a token, connect, wait for `CONNECT_SUCCESS_SID` within the deadline (gcloud allows 60 s; here the hop's remaining connect budget). A close during the open is a connect failure with its code.
- Reconnect, exactly as gcloud 590 decides it (`iap_tunnel_websocket_helper.py` `_OnClose`): a WebSocket that fails without a close frame (the link broke, end of stream, a TLS or I/O error) or that the relay closes with code `4004` ("reauthentication required") is reconnected with a fresh token on `/v4/reconnect`, backing off 1.5 s × 1.1 up to 20 s per try and at most 15 minutes in all; unconfirmed frames are resent after `RECONNECT_SUCCESS_ACK`. Any other close frame, whatever its code, ends the tunnel: the relay closed the session on purpose (`4003`, `4033`, `4010`, a normal `1000`, …). The SSH side sees nothing but a pause during a reconnect; russh's keepalives keep the IAP session active (IAP drops idle sessions after an hour). Credential errors that need a person (`invalid_grant`) end the tunnel too; transient token failures retry within the same budget.
- Close: dropping the `Stream` or the writer sends a WebSocket close and ends the pump.

`gcp/auth.rs`, credentials without `gcloud`:

- `trait TokenSource { fn access_token(&self, account: Option<&str>) -> Result<Secret, AuthError> }`, implemented by `FileStore` and by a static source in tests.
- `FileStore` resolves gcloud's config directory as gcloud does: `$CLOUDSDK_CONFIG`, else `~/.config/gcloud` on macOS and Linux, `%APPDATA%\gcloud` on Windows. For a named account it reads `legacy_credentials/<account>/adc.json` (type `authorized_user`: `client_id`, `client_secret`, `refresh_token`, `account`). Without a named account it is gcloud's active account that counts, as the editor promises: the legacy file of `active_config` → `configurations/config_<name>` → `[core] account` comes first, and only when there is none do `$GOOGLE_APPLICATION_CREDENTIALS` and then `application_default_credentials.json` serve as fallbacks (`gcloud auth application-default login` writes those, possibly for another identity). The account email always comes from the file's `account` field, because the OS Login path and every sentence need it; an `authorized_user` file without one is refused with a sentence asking to name the Google account in the transport. A `service_account` file is reported as unsupported with the file named. The IAP tunnel and the OS Login calls of one connection use the same credentials file, so they are one identity.
- Refresh: `POST https://oauth2.googleapis.com/token` with `grant_type=refresh_token`; the access token is cached in memory per credential file and refreshed when under five minutes of life remain. `invalid_grant` becomes "Google sign-in for <account> has expired or was revoked; run `gcloud auth login <account>` and connect again." Network failures are retryable (the tunnel's reconnect loop retries them). Secrets are `Zeroizing`.

`gcp/oslogin.rs`: `login_profile(account, project) -> LoginProfile` from `GET https://oslogin.googleapis.com/v1/users/{account}/loginProfile?projectId=…` (`posixAccounts[]` with `username`, `primary`, `operatingSystemType`; `sshPublicKeys` keyed by fingerprint with `key`), and `import_ssh_public_key(account, project, key_line)` as `POST …/v1/users/{account}:importSshPublicKey?projectId=…` with `{"key": "<algorithm> <base64>"}`. The username is the primary POSIX account's, else the first Linux one; a profile without one is an error naming the account. A key is imported only when no entry's `key` has the same algorithm and blob (comments ignored).

`gcp/pam.rs`: `active_grants(project, location, entitlement) -> Vec<Grant>` from `GET https://privilegedaccessmanager.googleapis.com/v1/projects/{project}/locations/{location}/entitlements/{entitlement}/grants:search?callerRelationship=HAD_CREATED&pageSize=50`, filtered here to states `ACTIVE`, `ACTIVATING`, `SCHEDULED` (the API's `filter` is server-side AIP-160 and gcloud's `--filter` is client-side, so no filter is sent). A grant carries `state`, `requestedDuration` and `auditTrail.accessGrantTime`.

All REST calls use one `reqwest::blocking::Client` with a 20 s timeout, the bearer token from `TokenSource`, and map `401/403` to a permission sentence that names the API and the account.

### Broker: preparing a target before it connects

The username stays where it is for every other host: in the host record. `resolve` does not change for an IAP host, and nothing mutates the `Target` after it: `checked_host`, `credential_approval::identity`, `record_pin::confirm` and the MCP and deployment `ApprovedTarget` all compare the hop's user against the record, and a user swapped in at connect time would fail every one of them (or weaken them if they were relaxed). OS Login's POSIX username is a stable property of the Google identity (`frank_retower_io`), so it is entered once: the editor's **Use OS Login username** button asks the backend for the login profile (`transports_oslogin_profile`, a command that needs no host) and fills the Username field.

`HostDirectory` gains a default no-op `prepare(&self, target: &Target, public_key: &dyn Fn(&str) -> Option<String>, cancel: &CancelToken) -> Result<(), DirectoryError>` (it reads the target and talks to Google; it changes nothing); `Connector::connect_within` calls it right after `resolve`, before `unlock`. The wrappers that forward `HostDirectory` by hand forward it too: `FormatDirectory` (outside the lifecycle lock `with_active` takes, because the call may wait on the network for up to 20 s), `PublicDirectory` in the MCP adapter and deployment, `ProbeDirectory` in verification. `RecordDirectory` implements it when built `with_gcp(Box<dyn GcpClient>)` (a builder like `with_password_reader`, so no struct literal changes), for a first hop with `Transport::GcpIap`:

1. PAM, when `pam` is set: no in-flight grant for any listed entitlement → `DirectoryError::Denied` with "No active Privileged Access Manager grant for `<entitlements, joined by " or ">` on `<project>`. Request one (for example `gcloud pam grants create --entitlement=<first entitlement> --requested-duration=30m --justification=\"…\" --location=<location> --project=<project>`) and connect again." A grant active for under two minutes is allowed through; if IAP then answers `4033`, the engine's sentence adds "the grant became active moments ago; IAP can take about 1½ minutes to see it".
2. OS Login, when `os_login` is set: fetch the profile. As `gcloud compute ssh` does, when the hop logs in with a vault key and the profile has no POSIX account or does not list the key, import the key (`importSshPublicKey` creates the account) and use the profile the import returns. Then the profile's username must equal the hop's user; otherwise `Denied` with "OS Login names `<account>` `<posix user>` on `<project>`, but the host is saved with user `<user>`; update the host (Use OS Login username)." A profile that still has no POSIX account → `Denied` with "OS Login has no POSIX account for `<account>` in `<project>`; the project may not have OS Login enabled." `public_key` is the broker's `KeyStore` lookup. API failures are `Denied` with the API's sentence.

`DirectoryError::Denied(String)` is new ("the account may not connect as saved"); the broker reports it with failure kind `auth`. The calls block on the broker's thread (plain threads by design) with the 20 s timeout and check `cancel` between steps.

### UI

A **Google Cloud** panel in the Library sidebar, beside **Tunnels** (Frank's call, 2026-10-25: the first draft put this in the host editor, which read oddly next to the host's own fields). The panel lists the hosts that have a transport (alias, tunnel, account, checks) with **New transport**, edit and remove; it is empty with "No host uses a Google Cloud IAP tunnel yet", and says "Add an SSH host first" when there are no hosts. The editor dialog chooses a saved host (hosts that already have a transport are not offered) and shows Project, Zone, Instance, Network interface (`nic0`), Google account (placeholder: "gcloud's active account"), **OS Login** (a checkbox: register this host's key with OS Login when needed and check the username before connecting) with a **Use OS Login username** button that fetches the profile for the entered account and project and saves the username into the host record, and **Require an active Privileged Access Manager grant** with an entitlements field (empty, placeholder `prod-operate, prod-admin`) and location (`global`). Lunport is a public product: no team's entitlement names or scripts are built in. Saving sends the displayed value as `expected`; removing deletes the record and the host is reached at its saved address again. The host editor has nothing about transports; the host's details show "Connect through: Google Cloud IAP · `project` / `zone` / `instance`". Transports are saved per device (a note in the panel says so).

### CLI and MCP

No new CLI commands. `sshelter connect <alias>` and MCP connections go through the broker. A CLI diagnostic (`sshelter gcp whoami`) is a possible follow-up, not part of this. The app gets three commands: `transports_save`, `transports_delete` (both return the record overview, which carries `transports`) and `transports_oslogin_profile` (the POSIX username, and whether a given vault key is registered, for the editor's button).

### Error texts

One sentence each, printable, no secrets, shown as written (no backticks in the product text; they mark values here). Engine sentences travel in `ConnectError::Tunnel`:

- WebSocket handshake `401`/`403`/`404` (gcloud's "Handshake status 40x"): "Google Cloud IAP refused the tunnel to `<instance>` (HTTP `<code>`): check that `<account>` has roles/iap.tunnelResourceAccessor on the instance, and for production that a PAM grant is active."
- Close `4003`: "IAP could not reach port `<port>` on `<instance>`: nothing is listening, or the firewall does not allow 35.235.240.0/20."
- Close `4033`: "`<account>` is not authorized to tunnel to `<instance>` through IAP." plus the recent-grant note above when it applies.
- Close `4004` during open: "IAP asked for a fresh sign-in and the new token was refused."
- Any other close during open: "IAP closed the tunnel to `<instance>` (`<code>`: `<reason>`)."
- Token refresh `invalid_grant`: "Google sign-in for `<account>` has expired or was revoked; run `gcloud auth login <account>` and connect again."; other HTTP errors: "Google's token service answered `<code>`."
- Reconnect exhausted: the session ends; `DisconnectReason.detail` says "the IAP tunnel could not be reconnected within 15 minutes".
- Credentials missing: "No Google Cloud credentials for `<account>` were found under `<config dir>`; run `gcloud auth login <account>`." An ADC file without an account email: "`<path>` names no Google account; name the account in the host's transport."
- No token source in the engine: "Google Cloud credentials are not configured."

### Documentation

`docs/usage.md` gets a "Google Cloud IAP and OS Login" subsection under "Connect in Lunport or an external terminal" (what to fill in, where credentials come from, that transports are per device for now, the PAM note). `docs/development.md` gets a paragraph on the `gcp` module, the fake relay used by tests and the Apache notice.

## Testing

- `gcp::relay` unit tests: every frame encodes and decodes as gcloud's `struct` formats say; URL building for connect and reconnect; the ACK threshold; confirmation arithmetic including a frame confirmed in two halves; backwards and oversized ACKs are errors.
- A fake IAP relay for tests (`gcp/testing/fake_relay.rs`): a tokio-tungstenite server that checks the subprotocol, `Origin` and bearer header, answers `/v4/connect` with a sid and bridges DATA frames to a TCP target, honours `/v4/reconnect` with `RECONNECT_SUCCESS_ACK`, and can be told to drop the socket after N bytes, close with `4004`, `4003` or `4033`, or refuse the handshake with `403`.
- `ssh::engine_tests::iap`: through the fake relay to the scratch sshd: a shell works and `exec` output is intact across a forced drop (the reconnect resends what the server had not acked); a `4003`, a `4033` and a `403` produce the sentences above; a tunnel that never sends `CONNECT_SUCCESS_SID` times out as `Phase::Tcp`; a transport on a second hop is `BadJumpChain`.
- `gcp::auth`, `gcp::oslogin`, `gcp::pam` with mockito: config-dir resolution with `CLOUDSDK_CONFIG`, legacy and ADC files, `invalid_grant`, caching and refresh, profile parsing, key import only when missing, grant filtering by state, `403` mapping. Fixtures are made-up credentials.
- `sync::transports` tests mirror `tunnel_rules_tests`: validation, compare-and-set, state version gating, a populated map at version 8 failing validation, re-keying on leave, and the central adoption fixture proving the map is cleared.
- `session::record_directory_tests`: `prepare` imports a missing key and accepts a matching username, refuses a differing one, imports when the profile has no POSIX account, through a fake `GcpClient`; the PAM refusal text; the jump-host refusal; the directory wrappers forward `prepare`.
- Frontend: the Google Cloud panel (the hosts listed, the empty states, the New transport button), the IAP fields with the PAM fields shown only when a grant is required, the Use OS Login username outcomes, and that the host editor has no transport section while the host details show the tunnel.
- Live validation (Frank, after Angus applies OS Login to dev): connect to the dev jumpbox in the app, confirm the OS Login user, drop Wi-Fi for 20 s and see the shell survive, then prod with and without a grant. Recorded in a validation note under `docs/`, as earlier features did.

## Security notes

- Tokens are read from files gcloud wrote with owner-only permissions; Lunport never writes them back, caches access tokens in memory only, and zeroes them on drop.
- The WebSocket verifies TLS against the system roots (`rustls-native-certs`); there is no "ignore certs" switch.
- The OS Login key import sends the public key only, for the account's own profile.
- The PAM check reads the caller's own grants only (`HAD_CREATED`).

## Left to the builder

Exact struct and module names inside `gcp`; how the pump task and the byte pipes are split; the fake relay's API; the editor's field layout within the existing `RecordField` components; test names; the validation note's shape. Anything in gcloud's reconnect logic not named here (queue sizes, timers) follows gcloud's constants.

## Questions for Frank

1. Per-device transports for this round (the local-only storage above), with sync as a follow-up: acceptable, or should sync be in before you use it? Adopting central sync clears them once.
2. Google account per transport, defaulting to gcloud's active account: right, or do you want an app-wide default account in Settings instead?
3. PAM check only, never requesting a grant from Lunport: right?
4. The transport lives in the host editor rather than its own panel, and the OS Login username is filled into the ordinary Username field by a button rather than resolved at every connect: right?

Frank's answers (2026-10-25): 1 and 2 as proposed; 3 "whatever is most convenient and robust", settled as check-only (Lunport never requests a grant: a request needs a justification and an approver, which belong in the person's own tooling; the refusal says how to request one); 4 a panel of its own, which the UI section above now describes, with the username still saved into the host record by the button.

A design review by a second reader (2026-10-25) changed four things from the first draft: the username stays in the host record (the identity checks depend on it), reconnects follow gcloud's rule exactly, device-local transports are cleared at central adoption and re-keyed on leave, and no team-specific entitlement names or scripts are built into the product.

## References

- gcloud 590.0.0: `lib/googlecloudsdk/api_lib/compute/iap_tunnel_websocket.py`, `iap_tunnel_websocket_utils.py`, `iap_tunnel_websocket_helper.py`, `iap_tunnel_lightweight_websocket.py`; `lib/googlecloudsdk/command_lib/compute/iap_tunnel.py`; `lib/googlecloudsdk/api_lib/oslogin/client.py`; `lib/googlecloudsdk/core/config.py` (config dir, legacy credentials); generated clients for `oslogin` v1 and `privilegedaccessmanager` v1 (Apache License 2.0).
- SSH Relay v4 protocol: <https://chromium.googlesource.com/apps/libapps/+/HEAD/nassh/docs/relay-protocol.md> (corp-relay-v4).
- `cedws/iapc`: <https://github.com/cedws/iapc> (reference only).
- knowknow-pulumi `docs/prod-access.md`, `components/resources/gce-jumpbox.ts`; knowknow-workspace `scripts/prod-access.sh`, `scripts/cloudsql-tunnel.sh`.
- Lunport: `docs/development.md` (SSH forwarding, tunnel rules as the record precedent), `src-tauri/src/sync/tunnel_rules.rs`, `src-tauri/src/ssh/russh_engine.rs`.
