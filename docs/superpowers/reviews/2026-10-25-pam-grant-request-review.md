# Requesting a PAM grant from Lunport: review record

The plan `docs/superpowers/plans/2026-10-25-pam-grant-request.md` (design `docs/superpowers/specs/2026-10-25-pam-grant-request-design.md`) was executed in eight tasks on the branch `claude/project-thread-whbjuy`, each with its tests written first, and the whole range (`16bd837e..bdaf6e2c`, twelve commits) was then read by a fresh reviewer against the spec, the plan and the executor's rulings. The reviewer ran the grant, gate, connect, directory, panel and window tests (171 Rust, 31 frontend, all green) and checked the client library's defaults in its source. Verdict: ready with fixes; no Critical findings.

## Fixed

| Finding | Fix | Test |
|---|---|---|
| The library's PAM calls had no timeout and retried ten times over a minute; the spec bounds every call by 20 seconds, and a hung socket would hold a session thread and the grant gate. | The client is built with the 20-second attempt timeout and no retries of its own (the broker's loops repeat and look at `cancel`). | `gcp::rest::tests::a_pam_call_that_does_not_answer_in_time_fails_at_once_as_a_network_error` |
| The Google Cloud panel built a new client, and minted an access token, for every grant read, every minute per host. | One `RestClient` in `AppState` serves the connections, the panel and the OS Login lookup; the panel keeps one read in flight per host. | the compiler and the command tests (Tauri wiring) |
| The window and the dialog let Request go with a tab or another control character in the justification, which the broker refuses, so the connect ended with the gcloud refusal sentence. | `justificationAcceptable` applies the broker's rule in both forms. | `grant questions` (`mcp-flow.test.ts`), `asks for a justification and a duration` (`transport.test.tsx`) |
| Five `bool_assert_comparison` clippy warnings in the directory's PAM tests. | Plain asserts. | — |
| The panel's request had no test that a grant already in flight is used, not requested again (Review Focus 1). | A test pins it. | `session::transports::tests::pam_request_takes_a_grant_already_in_flight_and_requests_nothing` |

## Calls made

- No Request grant button in the transport editor's PAM section (the spec names one beside the row's): the editor edits a draft that may differ from the saved transport, so which entitlement and account to request against is unsettled there. Cost if wrong: one click.
- `SCHEDULED` grants count as in flight, as the first design had it: the connect passes, the panel says activating, a request waits a minute and times out.
- A lead whose own connection is cancelled leaves every waiting connection the refusal sentence, rather than handing the question to the next one: the person said no once.
- The panel names the entitlement whose active grant lasts longest and shows that end (the plan said the earliest): a connection passes while any entitlement holds a grant.
- A grant question that reaches a terminal client with no window (none in the app) is cancelled at once, so the connect fails with the refusal instead of waiting five minutes.
- The bearer header's intermediate string is not zeroized, as on the existing OS Login path; the header is marked sensitive.
- Cancellation is seen within one poll of the grant (two seconds); the narrow race between a connection's check and another's request asks once more, and the re-check prevents a second request.
- The in-app terminal does not reconnect after a refusal, so a cancelled question is not asked again by itself (verified by the reviewer).

## Left for later

- The Request-a-grant dialog in the panel cannot be closed while a request is in flight (now bounded: 20 seconds per call, a minute of polling).
- An ACTIVE grant whose end has passed counts as none in the panel but as in flight for the connect's check; PAM marks such grants ENDED promptly.
- The terminal notice says "Requested a N-minute grant" even when the connect took a grant another request made a moment ago; the end time is right.
- Gates keep "gcloud's active account" and the same account named explicitly apart, so two transports could ask twice; the second request reuses the first grant.
- The second check after a request trusts the grant search at once; a laggy search would show the refusal right after the notice (not seen live).
- After a request from the panel, the dialog's prefill waits for the records to refresh.
- The live check on a production host (the question, the IAP grace, the panel's state) is still to be done by hand.
