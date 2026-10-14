# Records UI Ledger

Pre-flight: inspected App legacy hook tree, queries/terminals, existing themes/components, exact ImportPreview serde, React19/Vitest SSR/action testing conventions. Root owns all backend changes.
Ruling: public query cache only; direct async secret RPCs/component state — avoids retained mutation variables/results — cost if wrong: secret forms require local busy/error state.
Ruling: revision-bearing editor is keyed only by stable selection ID; dirty refresh preserves base revision and input — no silent optimistic-version update — cost if wrong: user must explicitly reload after a remote conflict.
Ruling: paused Legacy remains a landing with explicit use-existing; import confirmation is active Records only until migration activation RPC exists — prevents implicit data conversion — cost if wrong: migration landing needs a future dedicated command.

Ruling: native create-account partial success carries words plus public pending operation; words stay only in component state, pending error is shown, and recovery uses direct optional-code RPC. Joined/pending relay cannot change; cost if wrong: users must resume setup before other shared changes.
Ruling: import confirmation consumes its preview token; on failure, keep review visible but require a new preview or resume a public pending import. Cancel clears only native memory cache; cost if wrong: a failed confirmation cannot blindly resend an expired token.
Finding: original queryFn evaluated the cache before awaiting status. Deferred-reply RED test reproduced an older response replacing a mutation's newer generation. Corrected cache read to occur after the reply; focused test GREEN.
Verification: 48 focused tests, 58 files/901 full frontend tests, tsc and Vite production build GREEN. Logs in /private/tmp/sshelter-records-ui-{final-focused,full-vitest-final,build-final}.log. Browser/native-app acceptance and account leave/rotation are distinct pending integration checks; no user filesystem/vault/relay/credentials exercised.
Tooling: formatter CLI extracted to /private/tmp from an existing npm cached tarball after SHA512 integrity and version verification; no project dependency or lockfile changes.

Ruling: Account key authority names public metadata, not private-key publishing intent or relay receipt. KeyView.synced is authoritative: false permits opt-in again, true offers stop, null disables both toggle and an open confirmation. Metadata availability still does not prove material exists. Cost if wrong: runtime must supply authenticated status before toggle becomes usable.
Ruling: show persisted last_sync_ms independently from last_error; invalid/out-of-range dates produce an unavailable label instead of a RangeError. Queued sync wording avoids treating cached intent as server delivery.

Follow-up verification: six focused RED cases reproduced authority-based toggles/missing sync time. Final 55/55 records frontend tests and tsc GREEN; /private/tmp/sshelter-records-sync-dto-final.log. Public DTO test preserves false/null and last-sync/error values. No full Vitest rerun, backend edit, live credential or relay call.
