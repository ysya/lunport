# Requesting a Privileged Access Manager grant from Lunport

Date: 2026-10-25. Builds on `2026-10-25-gcp-iap-oslogin-design.md` (Google Cloud IAP transports), which made the PAM check "check only": a connection to a host whose transport requires a grant is refused when no grant is in flight, and the refusal quotes the `gcloud pam grants create` command.

## Intent

Frank's prod access went behind PAM. Today a prod session is: `gcloud pam grants create … --justification="…"`, wait, check with `gcloud pam grants list`, connect, then wait another minute and a half for IAP to notice the grant, and do it all again when the grant ends. Frank wants Lunport to make that one click: **press Connect; if a grant is needed, answer one question; the rest is Lunport's job.** The entitlements he uses are self-service (no approver, a justification required, 30 minutes to an hour), so the whole flow can run inside the connect.

Success: connecting to a PAM-protected host from Lunport, with no grant in flight, takes one prompt and no terminal. A later connect while the grant is active asks nothing. The Google Cloud panel shows how long the grant has left, and can request one without connecting (Frank also uses the same grant for `kubectl` and the Cloud SQL tunnel).

## Goals

1. At connect time, when the transport requires a grant and none is in flight, ask the person for a justification (prefilled with the last one), request the grant, wait until it is active, and go on connecting, in the in-app terminal and in an external terminal alike.
2. Absorb IAP's delay: a tunnel refused with 4033 right after a fresh grant is retried, with a notice, instead of failing.
3. In the Google Cloud panel: show the transport's grant state and remaining time; a **Request grant** action with the same justification/duration dialog.
4. Use Google's official Rust client library for the PAM calls, with Lunport's own credential source (gcloud's sign-in files) plugged in, so the account rules and sentences of the first design stay.

## Non-goals

- Entitlements with an approval workflow: Lunport never waits for an approver. A grant that lands in `APPROVAL_AWAITED` ends the connect with a sentence.
- Revoking or withdrawing grants (a grant also serves `kubectl`; it ends by itself).
- Requesting a grant on behalf of a non-interactive caller: MCP, the verification probe, deployment. They get today's refusal.
- Migrating the OS Login calls to the SDK (a follow-up; this round changes only PAM).
- Syncing the stored justification or duration across devices (the transport record is device-local).

## Anti-goals (what would make this a failure)

- A grant requested without the person's say-so (no silent requests, no "remember my answer and never ask again"): PAM is an audit trail, and every grant has a justification the person typed or confirmed.
- A justification sent anywhere but PAM, or logged.
- A connect that hangs: every wait is bounded and cancellable, and every end has a sentence.
- Team names baked into the product (the placeholder stays a placeholder).

## Constraints

- PAM v1 REST: `POST /v1/projects/{p}/locations/{l}/entitlements/{e}/grants` with a `Grant` body (`requestedDuration: "1800s"`, `justification.unstructuredJustification`) answers the `Grant` directly (not a long-running operation; gcloud 590's generated client confirms). `GET …/grants/{id}` for polling; `…/grants:search?callerRelationship=HAD_CREATED` for the in-flight check, every page. Grant states: `ACTIVATING → ACTIVE`, or `APPROVAL_AWAITED`, `DENIED`, `EXPIRED`, `ENDED`, `REVOKED`, `WITHDRAWN`, `ACTIVATION_FAILED`. `auditTrail.accessGrantTime` is set when access is given; the end is `accessGrantTime + requestedDuration`.
- Frank's entitlements: `maxRequestDuration = 3600s`, unstructured justification, no approval workflow. The product does not assume those limits: PAM's own refusal (an HTTP 400 with a message) is the limit.
- SDK: `google-cloud-privilegedaccessmanager-v1` 1.16 (Apache-2.0, Rust ≥ 1.91; the project builds with 1.99), async over tokio with an HTTP/JSON client (reqwest 0.13, rustls with aws-lc-rs: the same stack the app already has). Credentials: `google_cloud_auth::credentials::Credentials::from(provider)` for any `CredentialsProvider + Send + Sync + 'static` (`headers(extensions) -> CacheableResource<HeaderMap>`, `universe_domain() -> Option<String>`). The docs present that trait as a mocking hook; it is public API and the only way to keep Lunport's token source, so it is used, with a note in the code. Fallback if a future SDK release closes it: `user_account::Builder::new(json)` fed with the legacy credentials file's contents.
- The broker's question channel: `Owner::ask(kind, text, echo, deadline)`. Every connection a person drives (an in-app terminal tab, including its automatic reconnects; `sshelter connect` in an external terminal; a saved tunnel started from the Tunnels panel; a key deployment) answers questions through `SessionOwner` → `NativeOwner`: the question is shown in Lunport's own window, and the terminal prints a waiting line meanwhile. `NoInteraction` (an MCP request without a person) answers `Cancelled`; the verification probe asks nothing. The broker's notice channel (today `host_key_notice`) shows a line without an answer.
- The connect runs on the broker's plain thread with the 20 s per-call HTTP timeout; polling and waiting happen there, checking `cancel` between steps.

## Design

### The connect-time flow

`RecordDirectory::prepare` keeps doing the PAM check, but a missing grant is no longer a bare `Denied`: it is `DirectoryError::GrantNeeded(GrantNeed)` with everything the broker needs to ask and request: `project`, `location`, `entitlement` (the first listed on the transport; the person orders them), `duration` (the transport's stored duration, default 30 minutes), `justification` (the transport's last one, if any), `account`. The non-interactive paths (MCP `NoInteraction`, the verification probe, deployment) turn `GrantNeeded` into today's refusal sentence, so nothing changes for them.

`Connector::connect_within`, right after `prepare` returns `GrantNeeded`:

1. Asks the person through a question of its own kind, `QuestionKind::Grant`, carrying a `GrantPrompt { project, entitlement, minutes, justification }` (the transport's stored duration and last justification). Lunport's window shows it as **Request a grant**, not as a server prompt: the sentence `No active Privileged Access Manager grant for prod-operate on knowknow-prod.`, a **Justification** field prefilled with the stored one, a **Duration** field in minutes prefilled with the stored default (30 at first), and **Request** / **Cancel**; focus starts in the justification field and Enter requests. The terminal (in-app or external) prints `Waiting for you to request a Privileged Access Manager grant in Lunport.` meanwhile. The answer carries both fields back (the encoding is the builder's). Cancel, a closed window, an empty justification, or no answer within 5 minutes cancels, and the connect fails with today's refusal sentence (the one that quotes the gcloud command). This is a new question kind rather than the existing keyboard-interactive one because that window is built to keep a server's text apart from Lunport's own, starts empty, focuses Cancel and gives up after 120 seconds, all wrong for this question; the kind travels through `AuthRequest` (a ts-rs binding) to the window and to `mcp-flow.ts`.
2. Re-checks the in-flight grants once (another connection or the panel may have requested one meanwhile; PAM refuses a second request with the same scope), then calls `HostDirectory::request_grant(&need, &answer, cancel) -> Result<GrantReceipt, DirectoryError>`: the directory creates the grant through the SDK, stores the justification and duration as the transport's defaults (device-local), then polls `get_grant` every 2 seconds for up to 60 seconds until the state is `ACTIVE`. `GrantReceipt { entitlement, active_until: SystemTime, granted_at: SystemTime }`. A state that cannot become active (`APPROVAL_AWAITED`, `DENIED`, `ACTIVATION_FAILED`, …) ends with a sentence naming it.
3. Tells the person, through the notice channel: `Requested a 30-minute prod-operate grant on knowknow-prod; active until 11:07.`
4. Runs `prepare` again (it now finds the grant; `Prepared.recent_grant` is true and `Prepared.granted_at` is set) and connects.

**One question for all the connections that need the same grant.** Several connections often need the same grant at once: the in-app terminal reconnects every prod tab when the network returns or a grant has ended, a saved tunnel and a tab may start together, and the panel's Request grant may be pending while a tab asks. The broker keeps one gate per `(account, project, location, entitlement)`: the first connection to need the grant asks and requests; the others wait on the gate (bounded by the same 5 minutes + 60 seconds, cancellable) and then run `prepare` again. When the first is cancelled or the request fails, the waiting connections fail with the same sentence and ask nothing themselves: the person said no once.

**Which connections may ask.** Every connection a person drives may ask: terminal tabs, their automatic reconnects included (the person is at the app and can cancel; an unanswered question cancels after 5 minutes), `sshelter connect`, saved tunnels and key deployments. MCP requests and the verification probe never ask: they get the refusal sentence, as today. (My call: the alternative, tagging automatic reconnects so they never ask, changes the broker protocol and makes a tab die quietly at the moment the person most wants it back.)

### IAP's delay

A `ConnectError::Tunnel { code: Some(4033) }` while the grant is younger than two minutes (`Prepared.granted_at`, whether the grant was just requested or found already fresh) no longer ends the connect: the broker says once `IAP has not seen the grant yet; retrying for up to two minutes.` and tries the tunnel again every 10 seconds until two minutes after the grant was given, then fails with the first design's note sentence. Cancellation and the owner going away stop the retries. The retries do not count against the connect's round limit.

### The Google Cloud panel

- Each row with a PAM check shows the grant state as a short line under the checks, from a new command `transports_pam_status(host_id)`, which searches every listed entitlement (every page each; the connect accepts a grant on any of them, so the panel must agree): `prod-admin · active until 11:07` (the entitlement that holds the grant, the earliest-ending one when several do), `prod-operate · activating…`, or `no active grant`. The panel loads it when it opens and after a request; while the panel is visible it refreshes every 60 seconds; a failure shows the API's sentence in place of the state and never blocks the panel.
- A **Request grant** button on the row (and in the transport editor's PAM section) opens the same dialog as the connect-time question: Justification (prefilled with the stored one), Duration (minutes, the stored default), Request. It calls `transports_pam_request(host_id, justification, duration_secs)`, which requests the first listed entitlement (the person orders them), stores the justification and duration on the transport, waits up to 60 seconds for `ACTIVE`, and answers the receipt; the dialog shows `Active until 11:07` or the failure sentence. The button is disabled while any listed entitlement has a grant in flight.
- The transport editor's PAM section gains **Default duration** (minutes, 1–480, default 30). The justification is not edited there; it is whatever was last used.

### Records

`PamCheck` gains two optional, device-local fields: `duration_secs: u32` (default 1800, serde default) and `justification: Option<String>` (≤ 512 characters, printable, no newlines; `validate` enforces). The transport record's schema stays 1: both fields have defaults, the record is device-local and the feature has not shipped. `transports::set` keeps the compare-and-set; the broker's write of the last justification goes through a dedicated `transports::remember_grant_request(host_id, justification, duration)` that does not require the displayed value (the panel may be open meanwhile).

### The SDK and Lunport's credentials

- `gcp/rest.rs` keeps `GcpClient` and the OS Login calls as they are, and gains `create_grant(account, project, location, entitlement, duration, justification) -> Result<Grant, GcpError>` and `get_grant(account, name) -> Result<Grant, GcpError>`; `grants` (the search) moves to the SDK too. The three PAM methods go through a `PrivilegedAccessManager` client from `google-cloud-privilegedaccessmanager-v1`, built once per account and cached, on a single-thread tokio runtime owned by `RestClient` (the calls block, as before).
- `gcp/credentials.rs`: `BearerCredentials { tokens: Arc<dyn TokenSource>, account: Option<String> }` implements `CredentialsProvider`: `headers` asks the token source (on the blocking pool) and answers `Authorization: Bearer <token>` as `CacheableResource::New` with a fresh entity tag each time (the source caches tokens itself); `universe_domain` is `None`. The token stays `Zeroizing` until it is written into the header value, which is marked sensitive.
- `gcp/pam.rs`: `Grant` gains `name`, `justification` and `until()` (`accessGrantTime + requestedDuration`), and converts from the SDK's `Grant` (`From`), so the broker and the directory keep using Lunport's small type; `parse_grants` stays for the fixtures. `GrantNeed`, `GrantReceipt` live here.
- Errors: the SDK's `google_cloud_gax::error::Error` maps to `GcpError`: HTTP 401/403 → `Denied` (the existing sentence names the API and the account), 400 → a new `Refused { api, message }` ("Privileged Access Manager refused the request: <message>.", with the API's own message, which is how a too-long duration or a missing justification reads), 429/5xx → `Http`, transport failures → `Network`.
- Tests keep mockito: the SDK client is built `with_endpoint(server.url())`, so the existing style (one mock per path, exact query matching) covers `grants:search` pages, `create_grant`'s body and `get_grant` polling.

### Sentences

One sentence each, shown as written:

- The window: title `Request a grant`; `No active Privileged Access Manager grant for <entitlement> on <project>.`; fields `Justification`, `Duration (minutes)`; buttons `Request`, `Cancel`. The terminal meanwhile: `Waiting for you to request a Privileged Access Manager grant in Lunport.`
- Notice after the request: `Requested a <n>-minute <entitlement> grant on <project>; active until <HH:MM>.`
- IAP delay: `IAP has not seen the grant yet; retrying for up to two minutes.`
- A grant that will not activate: `The <entitlement> grant did not become active (state: APPROVAL_AWAITED); Lunport does not wait for an approver.` / `… within a minute (state: ACTIVATING); try connecting again.`
- PAM's refusal: `Privileged Access Manager refused the request: <API message>.`
- Cancelled prompt: today's sentence (`No active Privileged Access Manager grant for … Request one (for example gcloud pam grants create …) and connect again.`).
- Panel state: `active until 11:07`, `activating…`, `no active grant`, or the API's sentence.

Times are shown in the device's local time, hours and minutes.

### Documentation

`docs/usage.md`'s PAM paragraph describes the prompt, the panel's Request grant and remaining time, and that Lunport never requests for AI or automated connections. `docs/development.md` names the SDK, the credentials adapter and the mockito endpoint override.

## Testing

- `gcp::rest`: `create_grant` sends the parent, duration and justification PAM expects and returns the grant; a 400 answers `Refused` with PAM's message; `get_grant` reads a grant by name; `grants` still reads every page through the SDK.
- `gcp::credentials`: the provider answers a bearer header from the token source and surfaces its errors as `CredentialsError`.
- `gcp::pam`: `until()` arithmetic; conversion from the SDK's grant.
- `session::record_directory`: `prepare` answers `GrantNeeded` with the transport's entitlement, duration and last justification; `request_grant` creates, stores the justification, polls to `ACTIVE`, and names a state that will not activate; the non-interactive wrappers turn `GrantNeeded` into the refusal sentence.
- `session::connect`: the question carries the stored justification and duration; a cancelled question fails with the refusal sentence and requests nothing; a request followed by a connect; the gate: two connections needing the same grant ask once and both connect, and both fail when the one question is cancelled; the in-flight re-check before creating; a 4033 within the grace window is retried and then connects; the grace runs out with the note sentence; cancellation stops the retries; `NoInteraction` never asks.
- `session::auth_window` and the window component: a `Grant` question renders the Request-a-grant form with its prefilled fields, Enter requests, the answer carries both fields, the 5-minute deadline; the terminal's waiting line.
- `sync::transports`: the new fields' defaults, validation and `remember_grant_request`.
- Frontend: the panel's state line for each state, the Request grant dialog's fields and defaults, the editor's Default duration field, the disabled button while active.
- Live (Frank): prod jumpbox with no grant → one prompt → connected; the panel's remaining time; `kubectl` with the grant Lunport requested.

## Left to the builder

The exact shape of `GrantNeed`/`GrantReceipt`/`GrantPrompt` and how the window's answer carries two fields through `Reply`; how the connect's retry loop separates the IAP grace from the round limit; the gate's data structure; the notice channel's name (reusing `host_key_notice` or a new `notice` with a default implementation); how the panel schedules its 60-second refresh; how the stored justification is written while the transport editor may be open (a refresh after the request, or a compare that ignores the remembered fields); how a grant still `ACTIVATING` without a grant time starts the IAP grace (from now); local-time formatting; test names.

## Calls made after the builder check (2026-10-25)

A second reader planned from this document and asked four things; none needs Frank, so they are settled here for him to check:

1. The connect-time question is a question kind of its own with its own window (the keyboard-interactive window labels the text as a server's, starts empty, focuses Cancel and gives up after two minutes). Because the window is Lunport's, the duration is asked there too, prefilled; the earlier question of whether to ask the duration every time is answered by that.
2. Connections that need the same grant at the same time ask once and share the outcome (PAM refuses a second request with the same scope).
3. Every person-driven connection may ask, automatic terminal reconnects included; MCP and the verification probe never do. The alternative (tagging automatic reconnects so they never ask) changes the broker protocol and makes a tab die quietly when the person most wants it back.
4. The panel's state and its Request grant button consider every listed entitlement, as the connect does.
5. A grant is left alone when the session that requested it ends (it serves `kubectl` too); Lunport never revokes.
