# Cloud: gcloud accounts managed in Lunport, and Privileged Access Manager on its own — design

2026-10-27. Revises the Google Cloud page of the Connect via design (`2026-10-26-iap-connect-via-design.md`, "The Google Cloud page") and the grant memory of the same design ("Grant requests"). Builds on the PAM grant request design (`2026-10-25-pam-grant-request-design.md`) and the Catalog merge (`2026-10-27-catalog-conflict-merge-design.md`). Branch `claude/busy-edison-m78qbs`, from `origin/main` at `3b6d7567` (PR #94). Frank decided the questions marked "(Frank)" on 2026-10-27.

Words: a **route** is a host's Google Cloud IAP transport (`sync::transports`). An **entitlement** is one PAM entitlement, named in full by its parent (`projects/<id>`, `folders/<number>` or `organizations/<number>`), its location and its id; with the account that requests it, it is one row of the PAM area. A **search scope** is a parent, a location and an optional account where Lunport asks Google which entitlements the account may request. The **grant memory** is the justification and length last used for an entitlement.

## Intent

Frank's words, looking at the Google Cloud page after dropping a stale account by hand (`gcloud auth revoke <account>` in a terminal): "現在pam管理應該是獨立的介面對嗎？看起來他應該要是獨立的", then "有沒有辦法把這些功能加進去介面啊，然後把PAM獨立管理，會比較合邏輯嗎？".

Two things are wrong with the page today:

1. **Accounts are read-only.** Google sign-in lists gcloud's accounts and says which sign-ins expired, but every cure is a command to copy into a terminal (`gcloud auth login <account>`). Lunport has no local shell, so the person leaves the app for every sign-in, every removal and every change of gcloud's active account.
2. **PAM hangs off hosts.** A grant belongs to the Google account: PAM adds time-conditioned role bindings for the requester on the entitlement's resource, so every tool that uses that account (`kubectl`, the Cloud SQL proxy, Terraform) has the roles until the grant ends. Yet the page's Access grants rows are only the entitlements some route names, shown only while a host names them; Request grant goes through the row's first host (`askFor`, `row.host_ids[0]`); and the remembered justification is per host (`LocalState.transport_grants`). An entitlement Frank uses only for `kubectl` cannot be requested from Lunport at all.

Frank also wants the Cloud area shaped so a second provider (AWS) can join it later.

Success: on the Google Cloud page Frank sees that `frank@example.com`'s sign-in expired, presses **Sign in again**, finishes in the browser, and the row reads Signed in, with no terminal. He removes a stale account with one confirmation. On the Access tab he adds the project `acme-dev-654321` (no host there), sees its self-service entitlement, requests a 30-minute grant with last time's justification, and `kubectl` works. On his second computer the same entitlement offers the same justification.

## Goals

1. **Account actions in the app**, each confirmed in words that say it changes gcloud for every tool on this computer: sign in again, add an account, remove an account (`gcloud auth revoke`), make an account gcloud's active one.
2. **Lunport finds gcloud** although a macOS GUI app does not get the login shell's `PATH`, and says plainly what to do when gcloud is not installed.
3. **PAM on its own**: the Access tab lists every entitlement the person may request, from the projects the routes use and from search scopes the person adds (projects, folders, organizations), with each grant's state and **Request grant** straight on the entitlement, hosts or not.
4. **Search scopes and the grant memory sync** with the library (Frank), the memory one per entitlement.
5. **Entitlements that need an approver can be requested** (Frank): the request is sent and the row shows "Awaiting approval" until the approver acts.
6. **The host editor suggests entitlements** found in the route's project (Frank); typing stays possible.
7. **A Cloud section** in the sidebar that holds one row per provider, Google Cloud first, so AWS can be added as a sibling (Frank).
8. The page's double dividers go (and `ImportPanel`'s).

## Non-goals

- AWS itself. Only the shape that lets it join.
- Revoking, withdrawing or ending a grant early (unchanged: a grant also serves other tools; it ends by itself).
- Approving grants, or waiting for an approver inside a connection: the connect-time question keeps ending with "Lunport does not wait for an approver" (design 2026-10-25).
- Service accounts, workload or workforce identity federation, `--cred-file`, `gcloud auth application-default`. Accounts stay what `gcp_accounts` lists: `authorized_user` credentials named by an email.
- gcloud configurations beyond the active one (creating, switching, naming them).
- Installing or updating gcloud.
- Listing projects through Resource Manager (Frank chose route projects plus added scopes).
- MCP tools for accounts, scopes or the memory. The AI never sees a justification (unchanged, `mcp/records.rs`).
- A local shell or terminal.

## Anti-goals (what would make this a failure)

- A gcloud change without the person's say-so: every action that writes under gcloud's directory is a button press followed by a confirmation, except signing in again to an account whose sign-in already failed (the browser is the confirmation there).
- A command line assembled from text: gcloud is spawned with an argument list, and every account argument is an email (`transports::is_email`), checked before spawning.
- A hang: every gcloud run is bounded and cancellable, and ends with a sentence.
- A grant requested without the person's say-so, or a justification sent anywhere but PAM and the library's end-to-end encrypted sync (the memory now syncs; Frank, overturning call 5 of the Connect via design). Never in logs, MCP views or errors.
- Team names, projects or entitlements built into the product.
- A library that stops syncing because its Catalog outgrew one record.
- Older releases breaking without the changelog and the usage guide saying so.

## Constraints

- gcloud CLI 570 (checked on this machine):
  - `gcloud auth login [ACCOUNT] [--no-activate] [--force] [--brief]`. It sets the logged-in account active unless `--no-activate`; it re-uses an account's stored credentials unless `--force`; it starts a localhost server and opens the browser itself, printing the URL to stderr; the browser flow needs no TTY. It writes `credentials.db`, `access_tokens.db` and `legacy_credentials/<account>/adc.json`.
  - `gcloud auth revoke ACCOUNT`: "revokes the user account token on the server. If the revocation is successful, or if the token has already been revoked, this command removes the credential from the local machine." There is no local-only flag. Whether revoking at Google also ends the same account's gcloud sign-in on other computers is not documented; a Google answer on its developer forum says tokens are tied to the user's grant, so it may. Unverified; the confirmation says it may.
  - `gcloud config set account ACCOUNT` writes `[core] account` of the active configuration (`configurations/config_<active_config>`), which is what `auth::active_account` reads.
  - `--quiet` (`CLOUDSDK_CORE_DISABLE_PROMPTS`) turns prompts into their defaults.
- gcloud's config directory: the child inherits Lunport's environment, so `CLOUDSDK_CONFIG` means the same directory to both (`auth::config_dir`).
- PAM v1 (`google-cloud-privilegedaccessmanager-v1` 1.16, already a dependency): `search_entitlements` (`GET /v1/{parent}/entitlements:search`, `callerAccessType=GRANT_REQUESTER`, paged) exists on v1 for `projects/*/locations/*`, `folders/*/locations/*` and `organizations/*/locations/*`. An `Entitlement` carries `max_request_duration`, `requester_justification_config` (unstructured or not mandatory), `approval_workflow` (present means an approver is needed) and `privileged_access.gcp_iam_access` (the resource and role bindings). Grants (`grants:search`, `grants` create and get) take the entitlement's full name, so folder and organization entitlements work the same way.
- The Catalog (`central/payload.rs:166`) is `deny_unknown_fields` and strictly decoded by every release; a record's plaintext is at most `MAX_PLAINTEXT_BYTES` (64 KiB), shared with collections, group orders, tunnels and routes (`payload::catalog_fits`).
- `LocalState` is `deny_unknown_fields`; a state version a release does not know is refused when the state is opened (`records_v3::state::decode_state`). Release 1.13.0-1 (beta) knows versions up to 10 (`TRANSPORT_SYNC_STATE_VERSION`).
- Every Google call stays bounded (20 s per call, as today) and never waits for a person in a non-interactive path.

## Design

### The Cloud section and the Google Cloud page

The Library sidebar keeps hosts, keys and tunnels. Under them, a new heading **Cloud** lists one row per provider from one list in the frontend (`src/lib/cloud.ts`: id, label, icon, panel). Today the list has one entry, **Google Cloud** (the existing `transports` panel). An AWS provider later adds an entry with its own page; nothing else in the navigation changes. The collapsed sidebar shows the provider icons as it shows the others.

The Google Cloud page keeps its header (title, description, **New IAP host**) and splits its content into three tabs (`components/ui/tabs`), remembered per session:

- **Accounts**: gcloud on this computer and its Google accounts (below).
- **Access**: Privileged Access Manager (below).
- **IAP hosts**: today's Hosts through IAP list, unchanged.

The header description becomes: "Google accounts, access grants and IAP hosts on this computer."

### Finding gcloud

`gcp::cli::locate()` answers the path of the gcloud executable, or none. It looks, in order, and takes the first regular, executable file:

1. Each directory of Lunport's own `PATH`.
2. Known install places: `/opt/homebrew/bin`, `/usr/local/bin`, `/opt/homebrew/share/google-cloud-sdk/bin`, `/usr/local/share/google-cloud-sdk/bin`, `/opt/homebrew/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin`, `/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin`, `~/google-cloud-sdk/bin`, `/usr/lib/google-cloud-sdk/bin`, `/usr/share/google-cloud-sdk/bin`, `/snap/bin`, `/usr/bin`; on Windows `%LOCALAPPDATA%\Google\Cloud SDK\google-cloud-sdk\bin`, `%ProgramFiles(x86)%\Google\Cloud SDK\google-cloud-sdk\bin` and `%ProgramFiles%\Google\Cloud SDK\google-cloud-sdk\bin` (`gcloud.cmd`).
3. Not on Windows: the login shell, once: `$SHELL -i -l -c 'command -v gcloud'` (interactive too, since gcloud's installer adds itself to `PATH` in `.zshrc` or `.bashrc`) (`$SHELL` must be an absolute path to an executable file; `/bin/sh` otherwise), with stdin closed and a 5-second bound. Its answer is taken only when it is one absolute path to an executable file named `gcloud`.

The answer is cached for the app's run. It is looked up again when the cached file is gone, and when the person presses **Check again** on the Accounts tab.

### Running gcloud

`gcp::cli::run(path, args, bound, cancel)` spawns gcloud with an argument list (never a shell; on Windows `gcloud.cmd` through `std::process::Command`, whose batch-file argument escaping applies, and without a console window), stdin closed, stdout and stderr captured, the inherited environment plus `CLOUDSDK_CORE_DISABLE_PROMPTS=1`. Every account argument is checked with `transports::is_email` first. It ends with:

- success (exit code 0);
- failure: the last non-empty line of stderr that starts with `ERROR:`, else the last non-empty line, cut to 300 characters, as `gcloud could not <action>: <line>`;
- cancelled (the child is killed);
- timed out (killed): `gcloud did not finish within <n> minutes.`

One gcloud action runs at a time; a second answers "Another gcloud action is still running." Output is never logged. After any action, the token source forgets what it cached for the accounts involved (`FileStore` cache), and the page reads `gcp_accounts` again.

### The Accounts tab

**gcloud** comes first, one line: "gcloud found at `/opt/homebrew/bin/gcloud`" with **Check again**, or, when `locate` found nothing: "Lunport could not find gcloud on this computer. Install the Google Cloud CLI (link to `https://cloud.google.com/sdk/docs/install`), then press Check again." Without gcloud the account actions are disabled and each row keeps today's command text, so a person whose gcloud lives somewhere Lunport does not look can still copy it.

**Google accounts**: today's rows (state dot, Signed in / Sign-in expired / Could not be checked / Not signed in on this computer, the `gcloud active` badge, the route count), with actions on each row:

- **Sign in again** (shown for an expired or missing sign-in; in the row's menu otherwise): `gcloud auth login <account> --force --no-activate --brief`, bounded by 5 minutes. No confirmation: it signs in the account the row names and changes nothing else. A dialog says "Finish signing in to <account> in your browser." with **Cancel**; when gcloud printed a sign-in URL (the first `https://accounts.google.com/` URL on stderr, streamed as it comes), it adds "Browser did not open? **Open the sign-in page**". If the person signs in as a different account, gcloud refuses, and its sentence is shown.
- **Make gcloud's active account** (row menu, not on the active one): a confirmation: "Make ops@example.com gcloud's active account? gcloud, kubectl, Terraform and every other tool on this computer that uses gcloud's active account will use ops@example.com. Routes that name no account connect as it too." Buttons **Make active** / **Cancel**. Runs `gcloud config set account <account>`, bounded by 30 s.
- **Remove…** (row menu; not on a "Not signed in on this computer" row): a destructive confirmation: "Remove frank@example.com from gcloud on this computer? gcloud revokes this sign-in at Google and deletes its credentials here. Every tool on this computer that uses gcloud loses this account, and the routes that use it (2) cannot connect until you sign in again. Google may also end this account's gcloud sign-in on your other computers." For the active account it adds: "gcloud will have no active account until you choose one." Buttons **Remove account** (destructive) / **Cancel**. Runs `gcloud auth revoke <account>`, bounded by 60 s. A revoke that fails at Google with an already revoked token still removes locally (gcloud's behaviour), so an expired account can always be removed.

**Add account** (the section's action): a confirmation-free dialog, like Sign in again, running `gcloud auth login --no-activate --brief`, bounded by 5 minutes. It ends with "Signed in as <account>." (the account `gcp_accounts` newly lists, else gcloud's "You are now logged in as [...]" line) and the list refreshes. The new account is not made active; the row's menu does that.

When gcloud's directory is missing but gcloud is found (never signed in), the section says "gcloud has no Google account on this computer yet." with **Add account**.

Section description: "Accounts come from gcloud on this computer and are not synced. Changes here change gcloud for every tool on this computer."

### The Access tab (Privileged Access Manager)

Description: "Privileged Access Manager grants for your Google accounts. A grant gives its roles to every tool that uses the account until it ends; Lunport never ends one early."

**Where Lunport looks** (a section, collapsed to one summary line when it has no error): the search scopes, each a row:

- **From routes** (automatic, not removable): one per distinct account (a route's `null` account resolved to gcloud's active one), project and location among the routes with a PAM check, showing "Used by <aliases>".
- **Added** (synced): `projects/acme-prod-123456 · global · frank@example.com`, with **Remove**. **Add scope…** opens a dialog: Kind (Project, Folder, Organization), ID (project id, or the folder's or organization's number), Location (default `global`), Google account (the account picker the host editor uses; empty is gcloud's active account). It is checked locally (format) and saved; Lunport does not need the search to succeed to save it.
- A scope whose search failed shows the API's sentence on its row ("Privileged Access Manager denied frank@example.com…").

**Entitlements**: one row per (account, entitlement full name), from every scope's search (`callerAccessType=GRANT_REQUESTER`, every page) and from the entitlements routes name (a route-named entitlement is listed even when its scope's search found nothing or failed, as today). A row shows:

- the entitlement id; `parent · location · account`;
- what it gives, when the search returned it: the roles of `gcp_iam_access` (`roles/container.developer on projects/acme-prod-123456`), and the most a request may ask for ("Up to 1 hour");
- "Needs approval" when the entitlement has an approval workflow;
- "Used by <aliases>" when routes name it;
- the state: "Active until HH:MM", "Activating…", "Awaiting approval", "No active grant", or the API's sentence;
- **Request grant**, disabled while a grant is active, activating or awaiting approval (PAM refuses a second request in the same scope).

Request grant opens today's dialog (`GrantRequestDialog`) on the entitlement instead of a host: Justification and Duration prefilled from the grant memory of that entitlement, else the default length of a route that names it, else 30 minutes; the duration field is capped by the entitlement's maximum when known. For a self-service entitlement the request waits up to 60 s for `ACTIVE`, as today. For one with an approval workflow it does not wait: the answer is the new grant's state, the dialog says "Requested. The grant becomes active once an approver approves it.", and the row reads "Awaiting approval". The tab reads the states when shown and every 60 s, so an approved grant turns into "Active until HH:MM" by itself.

Empty: "No entitlement found. Add a scope where your Google account can request a grant, or require a grant in a host's Google Cloud options."

### The PAM commands

- `gcp_pam_overview()` replaces `gcp_pam_grants`: `{ scopes: [PamScopeView], entitlements: [PamEntitlementView] }`. Scopes are searched at once, at most four calls in flight; each entitlement's grants are then searched the same way; every call keeps the client's 20 s timeout and the whole command is bounded by 60 s (a scope or entitlement not answered by then shows the timeout sentence). `PamEntitlementView { account, parent, location, entitlement, name, max_duration_secs, needs_approval, roles: [{ role, resource }], state, active_until_ms, message, host_ids, memory: { justification, duration_secs } | null }`. States: `active`, `activating`, `approval_awaited`, `none`, `error`.
- `gcp_pam_request(account, name, justification, duration_secs)` requests on the entitlement `name` (full name) as `account`. It must be an entitlement the overview would list (in an added scope, a route scope, or named by a route), checked on the backend. It remembers the request (below) and answers a `PamStatusView` whose state may now be `approval_awaited`.
- `gcp_pam_scope_save(scope)` and `gcp_pam_scope_remove(id)` edit the added scopes.
- `gcp_pam_suggestions(account, project, location)` answers the entitlement ids the account may request there, for the host editor. Bounded by one search; failure answers no suggestions.
- `transports_pam_status` (host details, Tunnels) and `transports_pam_request` (host details' Request grant) stay; the latter now remembers per entitlement.

`GcpClient` gains `search_entitlements(account, parent, location) -> Vec<EntitlementInfo>`, and its grant calls take an entitlement's full name in place of project/location/id, so folder and organization entitlements go through the same code. `pam::Entitlement` becomes `{ account, name }` with the parts parsed from the name where needed.

`pam::Grant::is_final` stays as it is for the connect. A new `pam::pending` (`APPROVAL_AWAITED`) is what disables Request and makes the `approval_awaited` state; a grant awaiting approval never counts as access (`pam::in_flight` is unchanged).

### Routes

A route keeps only what the connection needs: its PAM check (`entitlements`, `location`, the default length `duration_secs`). No route field changes.

- The connect gate (`RecordDirectory::prepare`, `session/grants.rs`) reads the grant memory of the entitlement it will request (the route's first), then, as a fallback, the host's memory an earlier release kept (`local.transport_grants`), then the route's default length.
- The host editor's Entitlements field offers the suggestions of `gcp_pam_suggestions` for the route's account, project and location (a `datalist`-style list under the field, the comma-separated text stays editable), read when the PAM switch is on and the project is set.
- Host details' Access grant section and the Tunnels rows are unchanged, apart from the memory they prefill from.

### Search scopes and grant memory in the library

**Records.** Two new kinds of `Meta` records, kept the way tunnel rules are (`sync::tunnel_rules`): one encrypted record each, account rows under central sync, `local` rows otherwise.

- `pam_scope:<16-hex id>`, payload `{ "schema": 1, "scope": PamScope }`, `PamScope { id, parent, location, account: Option<String> }`. `parent` is `projects/<project id>` (6–30 characters, lower-case letters, digits and hyphens, optionally after a `domain:` prefix), `folders/<digits>` or `organizations/<digits>`; `location` is `global` or a region name (lower-case letters, digits, hyphens, ≤ 63); `account` an email. One scope per (parent, location, account).
- `pam_request:<16-hex id>`, the id being the first 16 hex digits of SHA-256 of the entitlement's full name; payload `{ "schema": 1, "request": GrantRequestMemory }`, `GrantRequestMemory { name, justification, duration_secs }`. The memory is per entitlement, for every account (a justification describes the work, not the account). `validate` checks the name, that the id is its hash, and today's `GrantMemory` rules.

**On the wire.** The Catalog gains `pam_scopes: Vec<PamScope>` and `pam_requests: Vec<GrantRequestMemory>`, both `#[serde(default, skip_serializing_if = "Vec::is_empty")]`, so a Catalog without them serializes as today. `Catalog::validate` allows at most 64 scopes and 32 memories, each validated. The projections, `public_rows`/`catalog_of` and the publish step gain the two row kinds as they have the `tunnel:` and `transport:` ones.

**Writes.**

- Scopes: `pam_scopes::save` and `remove` write a dirty account row under central sync (under the library's write gate, as tunnel edits), else the `local` map. A save whose Catalog would not fit is refused with "This library has no room for more search scopes: together with routes and tunnels they would exceed what one sync record holds. Remove a scope, a route or a tunnel, then try again." Removing never fails the check.
- Memory: every grant request (the Access tab, host details, the connect-time question) writes the memory of the entitlement it requested, after the grant was created, and removes the host's legacy memory entry, if any. The list keeps the 32 most recently written memories: writing one beyond that drops the least recently written (the Catalog's order is the order of writing). A memory write that would not fit drops the oldest memories until it fits, and is skipped if even alone it does not; a memory write never fails a grant request, and a library whose writes are blocked skips it.

**Merge** (`catalog_merge`): scopes are items keyed by id with the existing rule, and a collision is reviewed like a tunnel's ("Search scope projects/… · global"). Memories are items keyed by name with the existing rule, except that a collision never goes to review: the synced version wins (a remembered justification is a convenience; review for it would be noise). The Central conflicts row's plain words gain the scope kind.

**Local state version 11** (`PAM_STATE_VERSION`). A state that holds a `pam_scope:` or `pam_request:` row (account or local) raises the version to 11, through the mechanism versions 9 and 10 use (the match lists and validation in `records_v3/state.rs`, `record_repository::validate_header`, the fixtures, the `has_data` guards in `record_runtime.rs`). `LocalState` gains `pam_scopes` and `pam_requests` maps for libraries without central sync, valid only from version 11. `local.transport_grants` stays readable (version 10) and is emptied as requests write per-entitlement memory; it is not migrated eagerly (it may name a host whose route changed its entitlements since).

**Leaving sync, adoption, first publication**: the rows follow the tunnel rules' path (kept as local rows on leave; carried by adoption; published by the first publication), since none of them names a host.

**Older releases (Frank: ship this in 1.13.0).** A device on 1.13.0-1 or earlier cannot read a Catalog that holds a scope or a memory: its sync fails every round with "Invalid central sync protocol data." until it is updated (its data stays intact). Because a grant request writes a memory, this happens at the first grant requested from the new release in a central library. A 1.13.0-1 build on the same computer refuses to open the version 11 state. Frank decided to hold the 1.13.0 release (release-please PR #92) until this merges, so only beta devices are affected; the changelog and the usage guide say so.

### Sentences

- gcloud missing: "Lunport could not find gcloud on this computer. Install the Google Cloud CLI, then press Check again."
- Signing in: "Finish signing in to <account> in your browser." / "Finish signing in to the new account in your browser." / "Browser did not open? Open the sign-in page" / "Signed in as <account>."
- Make active and Remove confirmations: as quoted above.
- gcloud failures: "gcloud could not sign in: <line>", "gcloud could not remove <account>: <line>", "gcloud could not change its active account: <line>"; "gcloud did not finish within <n> minutes."; "Another gcloud action is still running."
- Access: "Awaiting approval", "Needs approval", "Up to <duration>", "Used by <aliases>", "Requested. The grant becomes active once an approver approves it."
- Scope room: as quoted above. Scope format: "Enter a project ID, or a folder or organization number."

### The double divider

`.app-review-list` draws a top and a bottom border, and the next `.app-form-section` draws its own top border across the `space-y-6` gap, so two lines meet between sections (`src/styles/app-layout.css:47,60`; the same in `ImportPanel.tsx`). Not fixed on main as of `3b6d7567`. A list that ends its section drops its bottom border when another section follows (`.app-form-section:has(+ .app-form-section) > .app-review-list:last-child { border-bottom-width: 0 }`); `ImportPanel`'s sections get the same treatment.

### Documentation

`docs/usage.md`'s Google Cloud section describes the Cloud section, the Accounts tab's actions and what they change, finding gcloud, the Access tab and its scopes, approval entitlements and the synced memory, and the older-release effect. `docs/development.md` describes `gcp::cli`, the two record kinds, the Catalog fields and version 11.

## Testing

- Rust, `gcp::cli`: `locate` over a temporary tree (found on `PATH`, in a known place, from a fake login shell script, nothing found, a non-executable file skipped, a shell answer that is not an absolute path ignored); `run` with a fake gcloud script (success, the `ERROR:` line, the timeout kills it, cancel kills it, the URL is streamed, a non-email account is refused before spawning, a second action while one runs is refused). Unix-only where it needs shell scripts.
- Rust, account actions: the argument lists of sign in again, add, remove and make active; the token cache is dropped after each.
- Rust, PAM: `search_entitlements` over mockito (pages, `callerAccessType`, folder and organization parents, the entitlement's duration, approval and roles); the overview aggregation over a fake client (route scopes resolved to the active account, added scopes, route-named entitlements kept when the search fails, one row per account and name, `approval_awaited`); `gcp_pam_request` refuses an entitlement the overview would not list, does not wait for an approval entitlement, waits for a self-service one, and writes the memory; the connect gate reads the entitlement's memory, then the host's.
- Rust, sync: scopes and memories round-trip through capture and both projections; a Catalog without them serializes byte for byte as before; 65 scopes or 33 memories are refused by validation; the memory list keeps the 32 latest and drops the oldest on room; a scope save that does not fit is refused, removal always succeeds; a memory collision takes the synced version without review, a scope collision is reviewed; version 11 is raised by either row kind and refused below; libraries without central sync keep the rows local; leaving keeps them.
- Frontend: the Cloud section; the tabs; the Accounts tab (gcloud found and missing, each action's confirmation words, the sign-in dialog with and without a URL, the disabled actions without gcloud); the Access tab (scopes from routes and added, Add scope validation, each entitlement state, Needs approval, Request grant disabled while pending, the dialog's prefill and cap, the approval answer); the editor's suggestions; the double divider (one line between two sections). The interface preview's `iap` scenario gains fakes of the new commands.
- Live (Frank), not verifiable here: Sign in again and Add account open the browser from the packaged app on macOS (Finder-launched, no shell `PATH`) and on Windows; Remove of an expired account; whether Remove ends the same account's gcloud sign-in on another computer; Make active as seen by `kubectl`; folder or organization scopes; an approval entitlement turning Active after approval; the synced memory on the second computer.

## Left to the builder

The tab component's details; the names of new types; how the sign-in dialog streams the URL (a Tauri event or a poll); the exact list of known install places beyond those quoted; how the overview bounds its parallel calls; the dialog for Add scope; whether `gcp::cli` shares `CHECKS`-style limits; CSS.

## Calls I made (for Frank to check)

1. Sign in again has no confirmation (the browser is one); Add account, Make active and Remove do, and Remove is worded as destructive.
2. Signing in never changes gcloud's active account (`--no-activate`); making one active is its own action.
3. The memory is one per entitlement, for every account, and keeps the 32 most recent; a memory both computers changed keeps the synced one without asking.
4. Route scopes are only the projects of routes with a PAM check, with the route's account and location.
5. The host's old memory is a fallback, emptied as you request, not migrated up front.
6. The Access tab lists an entitlement routes name even when Google's search does not return it.
7. MCP gets none of this.

## Changes made while building

- The Access tab shows **Entitlements** first and **Where Lunport looks** under it (the entitlements are what the tab is for), always expanded.
- The Accounts tab has its own **gcloud** section above **Google accounts**, with where gcloud is and **Check again**; every row shows **Sign in again**, **Make active** (not on the active account) and **Remove…** (not on an account only a route names) as buttons rather than a menu.
- The login shell is asked as `$SHELL -i -l -c` (interactive too), since gcloud's installer adds itself to `PATH` in `.zshrc` or `.bashrc`.
- "Least recently written" memories are by each row's local write time (`updated_at_ms`); rows read from the library count as written when read. A merge that does not fit drops memories in the Catalog's order.
- The records module is `sync/pam_records.rs` (the plan called it `pam_library`); the Access commands live in `session/pam.rs`, the account actions in `session/gcloud.rs`.
- A host's own Request grant (host details) also accepts an entitlement that needs an approver, and says so, as the Access tab does; the connect-time question still does not wait for one.
- Two scopes from two devices that look in the same place merge to the synced one.
