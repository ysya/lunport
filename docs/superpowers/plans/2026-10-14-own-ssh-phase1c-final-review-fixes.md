# Own SSH phase 1c final review fixes

> **For agentic workers:** Execute inline using systematic-debugging, receiving-code-review, test-driven-development and verification-before-completion. Do not spawn further agents.

**Goal:** Correct the two accepted immutable review findings without expanding phase 1c.

**Architecture:** Select startup state after the cross-process lock succeeds, before credential derivation or activation. Reject winning authenticated opaque Host authority at the immutable repository mutation boundary, using the same LWW predicate as readiness, while keeping ordinary imported review repair available.

**Tech Stack:** Existing Rust/Tauri runtime, filesystem locks, record merger and unit test fixtures; no new dependencies.

**Spec:** docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md. Existing active runtime plan and authority-shadow ledger remain binding.

## Constraints

- Preserve legacy source bytes and paused startup, format exclusivity and durable-save-before-memory activation.
- Keep unsupported envelopes and typed inspection cache/local material intact; do not create recovery copies or unknown-trust workflows.
- Keep VerifiedPublicIdentity type/privacy/legacy Own1 rules unchanged.
- Temporary fixture data only; no OS Keychain, real relay, SSH, UI or actual user migration.
- Preserve all other edits; no push, merge or release.

## One coherent fix wave

- [x] Extract the current startup probe/lock selection into a narrow production-used seam without changing behavior. Add deterministic old-lock-holder source-write tests: newer records retained through first candidate save, missing-to-record creation and legacy-to-record cutover. Observe behavioral RED.
- [x] Reprobe after successful lock acquisition; derive/activate only this selection. Keep the early read-only probe on lock failure with writes blocked. Run focused startup tests.
- [x] Add authenticated opaque mutation tests for update, move, delete and pin (including idempotent pin), duplicate creation, restart preservation, older LWW evidence, supported replacement and imported-review repair. Observe behavioral RED.
- [x] Add a shared canonical authority check before repository mutations. Run focused repository/record tests.
- [x] Run one integrated safe Rust suite after final fixes; record exact commands, counts and logs in the fix ledger. Check only owned diffs and commit Conventional Commit under the shared index flock.
