# Connect via: a host's Google Cloud IAP route, edited with the host and synced with it — design

2026-10-26. Revises the UI of the Google Cloud IAP transports design (`2026-10-25-gcp-iap-oslogin-design.md`) and adds the sync that design left as a follow-up. Branch `claude/google-tunnel-ui-design-c3a057`. Frank approved the direction on a clickable mockup: a throwaway spike in that worktree (`dev-preview.html?scenario=iap`). The spike shows the intended screens; it is not the implementation. Frank also decided (2026-10-26) that routes live in the shared central Catalog and sync without asking about older releases; both are marked where they apply.

Words: the **route** is what the code calls a transport (`sync::transports`, wire id `transport:<host-id>`); the UI calls the choice **Connect via**. MCP tool names (`set_transport`, `remove_transport`) stay as they are.

## Intent

Frank set up IAP routes for his jump hosts and found the result awkward. The route lives on its own Library page ("Google Cloud", beside Tunnels) instead of with the host, so one host takes two places to set up: the host editor, where Hostname is required although this device never dials it, and the panel's New transport dialog. Nothing on the host shows the route: every card says "SSH · user", the details pane leads with the unused address, and **Check port** probes that address (`connection_probe.rs:121`), not the route. And routes are device-local by design, so on his second computer the same host arrives with its saved IP and Lunport dials it.

All of this comes from one decision: the route was modelled as a device-local add-on beside the host. This design makes "how to reach this host" part of the host. The host editor gets a **Connect via** choice, **Address** or **Google Cloud IAP**, in the place of the address field; the route is saved with the host and syncs wherever the host syncs; the host's card and details show it; and the Google Cloud page becomes the place for what really is per computer: this computer's Google sign-in, and the access grants the hosts require.

Success: on one computer Frank opens his prod jump host, switches Connect via to Google Cloud IAP, types the instance, project and zone, and saves. The card shows IAP at once. On his other computer the same host shows IAP and connects through IAP as soon as that computer's gcloud is signed in, which its Google Cloud page tells him. **Check through IAP** says whether the route works before he connects, and the host's details say whether the prod grant is active and let him request it.

## Goals

1. One place to say how a host is reached: the host editor's Connect via, Address or Google Cloud IAP. The instance takes the address's place beside the port; project and zone sit under it; the rest folds into Google Cloud options.
2. The route syncs with its host: in a library that uses central sync, the same host has the same route on every device. Where hosts do not sync centrally, routes stay on each computer as today, and the editor says so.
3. The route shows where hosts are shown: an IAP marker on cards, the IAP target in the details pane, and a connection check that tests the route itself.
4. The Google Cloud page answers "can this computer use these routes": the gcloud accounts on this computer and whether each sign-in works, the grants the hosts require and whether each is active (with Request grant), and the hosts that connect through IAP.
5. Nothing to type again: routes already saved on a device move into the library once, on upgrade.

## Non-goals

- Listing or importing Compute Engine instances (the Compute API). The person still types instance, project and zone.
- Other route kinds (AWS SSM, Azure Bastion, Cloudflare Access). Connect via is a choice of kinds, so one can be added later.
- Syncing Google sign-ins, tokens or gcloud configuration. Sign-in stays per computer.
- Changes to the connection itself: the IAP tunnel, OS Login, the PAM check and the grant request at connect time, reconnects, the broker and the engine.
- Routes in the hosts export, in SSH config export, or recognised by import.
- A "Needs attention" entry for hosts whose Google sign-in expired (possible later).

## Anti-goals

- A route the UI says is synced that does not apply on another device.
- A host saved without its route, or a route without its host: one save, one outcome.
- Google credentials, tokens or OS Login profiles in sync, logs or errors (unchanged from the IAP design).
- Losing a device's routes on upgrade, on adopting a library, or on leaving sync.
- A release that makes older devices stop syncing without saying so in its changelog and the usage guide (see "Older releases on other devices").
- A library that stops syncing because its Catalog outgrew one record (see "Room in the Catalog").
- Requesting a grant editing the synced library.

## Constraints

- `HostPayload` stays as it is (schemas 2 and 3, `deny_unknown_fields`), so older clients keep decoding every snapshot. The route stays its own `Meta` record `transport:<host-id>` with the payload `{ "schema": 1, "transport": HostTransport }`, unchanged.
- The host record still needs a valid hostname: older clients, the editor's checks and the port check read it.
- `transports::get` keeps its meaning, the route that applies to this host on this device, whatever it reads underneath: the engine (`RecordDirectory`), MCP and the session commands find routes through it.
- Every Google call is bounded (20 s, as the OS Login and PAM calls are) and never waits for a person. MCP and the identity probe never ask.
- Lunport is a public product: no team's names, projects or entitlements are built in.
- Central sync has one metadata record, `meta/catalog` (`central/payload.rs:34`), holding collections, group orders and tunnels (`payload.rs:162-169`). It is `deny_unknown_fields`, one unreadable record fails a whole page of history (`library_page.rs:81-83`), and there is no version negotiation an older client understands (it only checks service protocol 2, `central/api.rs:352`). The relay sees records encrypted, so the Catalog's content needs no service change.
- The older chain-mode account sync is retired by central cutover (`record_round.rs:84-90`). It keeps unknown `Meta` records sealed instead of failing (`record_merge.rs:877-892`).
- Prerequisite, fixed on its own before this work: `transports_pam_status` and `transports_pam_request` check the host id with `transports::is_id` (`session/transports.rs:237,252`), which wants the `transport:` prefix, while the UI sends the bare host id, so both always answer "Invalid host identity." The panel's grant line and Request grant have never worked; the Access grant section and the Google Cloud page rely on these commands. The fix checks `records_v3::is_host_id` and adds a test with a real host id.

## How it works (decided)

### The route syncs with its host

**Where routes sync.** In a library that uses central sync every host syncs (local-scope hosts are published too, `central/projection_local.rs:53`), and so does every route. Without central sync, that is with no account or with the older chain-mode account, routes stay on each computer exactly as today, and the editor's Connect via description says "Saved on this computer only." instead of the synced sentence. `RecordOverview` tells the UI, per route, whether it syncs.

**On the wire.** Routes join the Catalog as `transports: Vec<HostTransport>`, declared like `tunnels` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`): at most one per host id, each checked by `HostTransport::validate` in `Catalog::validate`, and `pam.justification` always `null` (see "Grant requests" below). A Catalog without routes serializes exactly as today, so a library without routes stays readable by every release. The record shape inside Lunport (`transport:<host-id>`, `{ "schema": 1, "transport": … }`) does not change.

**Inside Lunport, routes take tunnel rules' central path:**

- Central to local: the initial and delta projections (`projection_cache.rs:118-130`, `projection_delta.rs:139-165`) rebuild the `meta:transport:<host-id>` rows of `account.records` from `catalog.transports`, removing rows the Catalog no longer has, as they do for `tunnel:` rows.
- Local to central: `transports::set` writes a dirty account row when the library uses central sync, as `tunnel_rules::set` does (`tunnel_rules.rs:172-210`), under the same write gate (`tunnel_rules.rs:139-143`); `public_rows` (`projection_local.rs:165-199`) gathers those rows into `catalog.transports`, so the existing capture (`projection_capture::public_candidate`) publishes the changed Catalog. Its other arms (`projection_local.rs:82-133`) gain the `transport:` case.
- Reading: `transports::get` and `transports::view` return the account row when there is one, else the `local.transports` entry, as `tunnel_rules::view` merges its two maps (`tunnel_rules.rs:80-110`).
- Removing a route removes it from the Catalog (the Catalog keeps no tombstones; a projection drops what is gone).

**Existing routes move in, once, by one step.** A device's routes are never dropped silently, and there is one way in for all of them: they stay in `local.transports` until a publish step moves them into the library.

- First publication of a library to central and adoption of an existing library keep the device's routes in `local.transports` instead of the initial projection clearing them (`initial_projection.rs:141`). Adoption re-keys them with the host id rewrite it applies to the hosts (`central/adoption/merge.rs`, `host(operation, scope, id)`, as it re-keys tunnel host ids at lines 212-221). The migration source inventory, its journal and the rebase code do not change. Note the version constraint: the initial projection forces state version 8, and `validate_state` refuses a populated `local.transports` below 9 (`records_v3/state.rs:372-374`; `record_import/central_stage/initial_publish.rs:75` expects exactly 8), so keeping routes through it means raising the version once the projection is done. The builder works out the order.
- A device already on central sync holds the routes it saved with 1.12 in the same map.
- The publish step publishes every route in `local.transports` whose host the library has, once, and removes it from the local map. It runs on every device without asking. A route whose host the library does not have, or that does not fit (see "Room in the Catalog"), stays local.

**Leaving sync** keeps the routes of the hosts that stay on this device, as local routes under the hosts' new ids, extending `preserve_on_leave` (`record_leave.rs:794`) from the local map to the synced rows.

**Deleting a host** removes its route in the same edit; today nothing does (`record_repository.rs:913-935`). Projections and the Google Cloud page ignore a route whose host is missing, as the Catalog's tunnels tolerate orphans (`payload.rs:188-196`, `adoption/merge.rs:218`).

**Grant requests.** Today every request writes the justification and the duration back into the route (`session/app.rs:164`, `transports::remember_grant_request`, without a revision check). Synced, every grant request would edit the Catalog, and a concurrent Catalog edit elsewhere would become a conflict the person has to resolve. So the last justification and length used stay on this computer, beside the synced route; the request dialog offers them, else the route's own default length (`pam.duration_secs`, the editor's "Default grant", which does sync). Where they are stored is the builder's choice, within "Local state version".

**Conflicts.** Routes share the Catalog with tunnels, collections and group orders, so concurrent edits of any of them meet in one record and are reviewed in Central conflicts (one whole version is kept), as tunnel edits are today. There is no new conflict UI. Replaced by `2026-10-27-catalog-conflict-merge-design.md`: different items merge, and only items both devices changed are reviewed.

**Local state version.** A state holding synced route rows, or the device-local grant memory, raises the local state version to 10. This is the mechanism versions 6 and 9 use: the two match lists and validation in `records_v3/state.rs`, `record_repository::validate_header`, the fixtures written as `<NEWEST>_STATE_VERSION + 1`, and the `has_data` guards in `record_runtime.rs` (`persist_candidate`, `commit_migration_candidate`). A 1.12 build on the same computer then refuses to open the library rather than meet rows it cannot publish (`projection_local.rs:82-133` rejects unknown rows).

**Room in the Catalog.** The Catalog is one record, and a record's plaintext is at most 64 KiB, on the client (`central/wire.rs:5`, `MAX_PLAINTEXT_BYTES`) and on the relay (`relay/src/v2/protocol.ts:5`). Routes share that room with up to 256 collections, 256 tunnels and the group orders, and nothing checks the total today. A Catalog that does not fit fails the whole capture (`projection_capture::public_candidate`), so nothing in the library syncs any more, hosts included. A typical route takes 200–300 bytes encoded, and up to about 1.2 KB with long names and eight entitlements. So:

- `Catalog::validate` allows at most 256 routes, as it allows 256 tunnels.
- Every write that changes the Catalog builds the candidate Catalog and refuses one whose encoding would not fit in `MAX_PLAINTEXT_BYTES`. That covers the combined host save with a route, MCP `set_transport`, tunnel saves (they share the room now) and the adoption merge. The refusal reads: "This library has no room for more routes or tunnels: together they would exceed what one sync record holds. Remove a route or a tunnel, then try again." Removing a route or a tunnel never fails this check.
- The publish step publishes routes while they fit and leaves the rest local. The Google Cloud page lists those as "Saved on this computer only: the library has no room for this route".

**Older releases on other devices (Frank, 2026-10-26: sync without asking).** A device on 1.12 or earlier cannot read a Catalog that holds routes. Its sync then fails every round with "Invalid central sync protocol data." until it is updated, because history cannot be skipped; its own data stays intact. Nothing in central lets a newer device tell it to update. Lunport does not ask before the first route syncs. The changelog and the usage guide say that devices on 1.12 or earlier stop syncing a library once it holds a route, until they are updated. Routes are decoded strictly, so a later route kind or a new route option will have the same effect on 1.13 and needs the same note (Frank chose the Catalog over separate route records knowing this).

### Host editor: Connect via

The Connection section reads, top to bottom: Group; Alias beside Username; then a bordered **Connect via** block with a one-line description and a two-option control, **Address** and **Google Cloud IAP** (a radio group in behaviour and accessibility; the spike used tabs).

- **Address**: Hostname or IP (two thirds) beside Port (one third), today's fields. Description: "The hostname or IP address this host is dialed at."
- **Google Cloud IAP**: Instance (two thirds) beside Port, so switching keeps both where they were; Project beside Zone under them; then a collapsed **Google Cloud options** disclosure whose summary line shows the account, OS Login, and the PAM entitlements. Inside: Google account; OS Login (a switch); Require a Privileged Access Manager grant (a switch) with Entitlements (full width), Location and Default grant (minutes); Network interface; and the firewall sentence ("The instance's firewall must allow 35.235.240.0/20 to this port."). Description: "Saved with the host, so it syncs wherever the host does.", or "Saved on this computer only." where routes do not sync (see "Where routes sync").
- **Google account** is a select of the accounts gcloud has on this computer (`gcp_accounts`): "gcloud's active account (address)" first, which saves `null`, then each account, an expired sign-in marked. An account the route names that this computer does not have stays selected, marked "not signed in on this computer". When gcloud's accounts cannot be read, the field is the free-text input it is today.
- **Hostname in IAP mode** is not shown. An existing host keeps its saved hostname untouched. A new host saved with IAP stores the instance name as its hostname, so the record stays valid. Switching back to Address shows the saved hostname again.
- **Use OS Login username** sits under Username while the route uses OS Login. It fetches the login profile for the route's account and project (`transports_oslogin_profile`) and fills the Username field; the username is saved with the host like any other edit (today the panel writes the host at once, before Save). Its note ("OS Login username: …", and whether the key is registered yet) appears below it. It is disabled while the host inherits its username from its Group, with today's sentence.
- **Saving** sends the host and its route in one command (see Commands); one outcome for both. Saving with Address removes the route; nothing remembers the old IAP settings. **Discard changes** and **Reload saved settings** restore the saved route with the host. The editor's dirty state, its validation sentence and the Save button cover the route, with `transportProblem`'s sentences.
- **New IAP host**, from the Google Cloud page, opens a new host with Google Cloud IAP chosen. An untouched new route shows no validation sentence yet, as a new host's empty fields do not.
- **Duplicate host** copies the route.

### Host list and details

- A card's second line is `IAP · user` with a cloud icon for a host with a route (`SSH · user` otherwise); its tooltip names `Google Cloud IAP · project / instance`.
- The details pane shows, under the alias, a cloud icon and `project / instance` instead of the hostname. The Connection list shows Connect via (Google Cloud IAP), Instance (`instance · zone`), Project, Google account (or "gcloud's active account") and, when either applies, Checks (`OS Login · PAM grant`); then Username, Port and Group. An IAP host's details do not show Address.
- For a route that requires a grant, an **Access grant** section shows the entitlement holding a grant and "Active until HH:MM", "Activating…" or "No active grant" (read when the pane opens and every minute, through `transports_pam_status`), the required entitlements, and **Request grant…**, which opens today's request dialog and is disabled while a grant is active.
- The connection check of an IAP host says **Check through IAP** (next section).

### Check through IAP

`transports_iap_probe(host_id)` opens a tunnel to the route's instance and the host's port with the route's account (`gcp::iap::open`, which returns once the relay answers the connect with success), closes it at once, and answers `{ status, latency_ms, elapsed_ms, checked_at_ms, message }`:

- `reachable`: the relay connected to the instance's port.
- `denied`: IAP refused the account: the handshake refused with HTTP 403, or the tunnel closed with 4033 "not authorized" (no IAM binding, or no active grant for a PAM-gated binding). The sentence says so and, for a route that requires a grant, points to Request grant.
- `unreachable`: anything else that ended the open, notably 4003 "failed to connect to backend" (usually the firewall), with the relay's reason.
- A credentials error (`AuthError`, e.g. `SignInExpired`) answers `denied` with its sentence (`gcloud auth login <account>`).

The probe is bounded by 20 s, shares the port check's limit of four checks at once, never asks for a grant or a sign-in, and attempts no SSH (no host key, no login). The pane's description: "Check whether this computer reaches the instance's port through IAP with its Google sign-in. Login and server identity are verified separately."

### Tunnels through a host that needs a grant (added 2026-10-26, Frank)

Starting a saved tunnel already goes through the grant check a terminal connection uses (`session/tunnels.rs` `run` → `Connector::connect` → `prepare_granted`, `session/connect.rs:365-381`), so the "Request a grant" window appears when the tunnel's first hop needs a grant and none is active. Two additions make it visible:

- **The grant on the row.** In the Tunnels panel, a tunnel whose first hop (the tunnel's host, or its first jump host when it has jump hosts: the only hop an IAP route applies to) has a route with a PAM check shows that grant's state on its row, read when the panel opens and every minute through `transports_pam_status` for the first hop: "<entitlement> · Active until HH:MM", "Activating…", "Needs a grant: <entitlements, comma-separated>" when none is active, or the API's sentence when the check fails.
- **A clear stop reason.** When a running tunnel's SSH connection ends because IAP refused the first hop's account (the relay's 4033 "not authorized" close, or an HTTP 403 handshake refusal on reconnect) and that hop's route has a PAM check, the tunnel's error reads: "The Privileged Access Manager grant this tunnel needs has ended. Start the tunnel again to request a new one." Every other ending keeps today's text. The engine already records why an IAP hop ended (`ssh/russh_engine.rs`, `tunnel_ended`); the SSH session exposes it to the tunnel.

### The Google Cloud page

The Library sidebar keeps **Google Cloud** (without a count). The page has a header ("Google sign-in and access grants on this computer. A host connects through IAP when its Connect via is set to Google Cloud IAP.") with **New IAP host**, and three sections:

- **Google sign-in**, from `gcp_accounts`: each account gcloud has credentials for on this computer, with a state dot (signed in, sign-in expired, could not be checked), a "gcloud active" badge, and how many routes use it (a route without an account counts for the active one). An expired sign-in shows `gcloud auth login <account>`. A route that names an account this computer lacks adds a row "Not signed in on this computer" with the same command. Without gcloud's directory: "gcloud was not found on this computer. Install the Google Cloud CLI, then run `gcloud auth login`." Description: sign-ins are per computer and are not synced.
- **Access grants**, shown when a route requires a grant, from `gcp_pam_grants`: one row per entitlement the routes name (an entitlement is the account, project, location and entitlement id together), with `project · location`, the state ("Active until HH:MM", "Activating…", "No active grant", or the API's sentence), the hosts that require it, and **Request grant**, disabled while a grant is active. It asks for that entitlement through the request dialog. Read when shown and every minute. Description: "Privileged Access Manager grants your hosts require. A grant ends on its own; Lunport never revokes one."
- **Hosts through IAP**: each host with a route (alias, `project / instance · zone`, account); a row opens the host editor. Empty: "No host connects through IAP yet. Open a host and choose Google Cloud IAP under Connect via, or create one with New IAP host."

Nothing on this page edits a route: the panel's editor dialog, its table and Remove are gone.

### Commands

- `records_host_create` and `records_host_update` take an optional route change: the route as the editor displayed it (`expected`) and the route to save (`kind`, `null` to remove). It is applied in the same `edit` closure as the host, checked against `expected` as `transports::set` checks it; a mismatch fails the whole save with "The host's route changed while you were editing; reload and try again." Omitted, the route is untouched (every other caller). On create, the route takes the new host's id inside the same closure.
- `gcp_accounts` (new): `{ config_found, active, accounts: [{ account, state: "signed_in" | "expired" | "unknown", message }] }`. It lists `legacy_credentials/*/adc.json` under gcloud's config directory (the directory names as `auth::legacy_credentials_path` spells them, `authorized_user` files only), reads the active account with `auth::active_account`, and checks each sign-in through the existing token source: a token in hand or refreshed is `signed_in`, `AuthError::SignInExpired` is `expired`, anything else is `unknown` with its sentence. Bounded; it never writes under gcloud's directory and never reads `credentials.db` or `access_tokens.db`.
- `gcp_pam_grants` (new): the rows of the Access grants section, from `GcpClient::grants` once per distinct entitlement (a route's `null` account resolved to the active one), with the in-flight logic `pam_status` uses (`pam::in_flight`, an `ACTIVE` grant's end) and the ids of the hosts whose routes name it.
- `transports_pam_request` takes an optional `entitlement`, which must be one the route lists; omitted, it asks for the first, as the connect does. The answer names that entitlement. It remembers the justification and length on this computer only (see "Grant requests"); the connect-time grant question does the same.
- `transports_iap_probe` (new), as above.
- `transports_save` and `transports_delete` are no longer used by the UI and go; MCP writes through `transports::set` itself.
- `transports_oslogin_profile` and `transports_pam_status` stay as they are.

### MCP

`set_transport`, `remove_transport` and `get_host` keep their shapes, words and approval window; they read and write through `transports::get` and `transports::set`, so a route an AI saves syncs exactly as one saved in the editor. A synced route obeys the library's write block, so a proposal for a host in a blocked library is refused with the sentence tunnel edits get, and a route that would not fit in the Catalog is refused with the "Room in the Catalog" sentence. The AI's view of a route still never shows a justification (`mcp/records.rs:1017`).

### Documentation

`docs/usage.md`'s Google Cloud IAP section (lines 67–75) is rewritten for Connect via, sync, Check through IAP and the Google Cloud page; its sentences about device-local transports and adopting central sync go, and it says what happens to devices on older releases. `docs/development.md:58` describes the synced rows, the Catalog field and version 10. The changelog entry names the older-release effect.

### Tests

- Rust, sync, mirroring the tunnel rules tests (`tunnel_rules_tests.rs`, the central projection and adoption tests): a Catalog without routes serializes byte-for-byte as before; routes round-trip through capture and both projections; a removed route leaves the Catalog and the rows; first publication keeps the device's routes and adoption keeps them re-keyed, both still local; the publish step publishes `local.transports` once, only for hosts the library has, and leaves local a route that does not fit; a 257th route, and a route or tunnel that would push the encoded Catalog past `MAX_PLAINTEXT_BYTES`, is refused with the sentence while removing one always succeeds; leaving keeps preserved hosts' routes as local ones; deleting a host removes its route; a grant request changes no synced row; version 10 is raised by synced rows or the grant memory and refused by validation below it; a library whose writes are blocked refuses a route edit; chain-mode and account-less libraries keep routes local.
- Rust, the rest: the PAM commands accept a real host id (the prerequisite); the combined save (a route that fails validation or `expected` leaves the host unsaved; create gives the route the new id); `gcp_accounts` over a temporary gcloud directory (signed in, expired, two accounts, no directory, the active account); `gcp_pam_grants` aggregation over a fake `GcpClient` (two routes naming one entitlement give one row); `transports_pam_request` with an entitlement (listed, not listed); the probe over `gcp::testing::FakeRelay` (success, handshake 403, close 4033, close 4003).
- Frontend: the host editor (switching keeps the port; the hostname is hidden in IAP mode; a new IAP host; Use OS Login username fills the draft and writes nothing; Discard restores the route; Save sends the route change), cards and details (marker, target, Access grant, Check through IAP), the Google Cloud page (each account state, grants and Request grant per entitlement, the hosts list, the empty states, New IAP host). `transport.test.tsx` is replaced. The interface preview keeps an `iap` scenario with fakes of the new commands in their real shapes.

## Left to the builder

- The control behind Connect via (a radio group or segmented control component), and the names of new types and arguments.
- Wording beyond the sentences quoted here, and the CSS.
- Whether `gcp_accounts` checks sign-ins in parallel, and how long the page caches its answers.
- How the editor shows a route conflict (the "This host changed or became unavailable" banner is the expectation).

## Calls I made (for Frank to check)

1. Routes sync only through central sync. With no account, or with the older chain-mode account (retired by central cutover), routes stay on each computer and the editor says so. Chain mode could carry them the way it carries tunnel rules; I left it out because it is on its way out.
2. A new host saved with IAP stores the instance name as its hostname; in IAP mode the hostname is neither shown nor edited.
3. Saving with Address removes the route; nothing remembers the old IAP settings.
4. The Google account syncs with the route; empty means each computer's gcloud active account. A computer without the named account shows "not signed in on this computer".
5. The default grant length syncs with the route; the last justification and length you used in a request stay on each computer, so requesting a grant never edits the synced library.
6. The Google Cloud page lists grants per entitlement and requests the one you click; connecting still asks for the first entitlement, as today.
7. Check through IAP only opens and closes a tunnel; it never requests a grant or signs in.
8. The panel's editor and Remove are gone; routes are edited in the host editor (and by MCP).
9. Routes saved on a device before this release move into the library once, for hosts the library has.
10. Deleting a host deletes its route.
11. The sidebar keeps "Google Cloud", without a count.
12. Routes enter a library by one publish step after the device is on central (first publication, adoption and upgrade alike), not inside the migration, so the migration inventory, journal and rebase code stay as they are. For that moment the routes are still local, and still work on their device.
13. A route that does not fit in the Catalog stays local and the Google Cloud page says why. Tunnel saves get the same size check, since they share the room.
14. A tunnel shows the grant of its first hop. Its stop reason names the ended grant only for an IAP refusal on a route with a PAM check; an IAP refusal for another reason on such a route (access removed in Google Cloud) reads the same.
