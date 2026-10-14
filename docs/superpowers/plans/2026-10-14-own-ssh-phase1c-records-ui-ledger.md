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
