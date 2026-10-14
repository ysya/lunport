# Records Workspace UI Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans and test-driven-development. The written migration design and active-runtime plan are approved; autonomous implementation is already authorized.

**Goal:** Deliver a records workspace that edits stable host IDs without mounting legacy file hooks, and keeps secret inputs and unsaved edits private to their components.

**Architecture:** A mode query chooses records, paused legacy or blocked before rendering LegacyApp. Only public status/overview enters QueryClient. New components use direct IPC mutations, local secret state and a pure revision-bound editor reducer. The backend owns identity allocation, durable writes, pin verification and generation.

**Tech Stack:** Existing React 19, TanStack Query 5, Tauri invoke, shadcn components/theme, Vitest and SSR/action tests. No new dependency.

**Spec:** docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md; docs/superpowers/plans/2026-10-14-own-ssh-phase1c-active-runtime.md. Native RPC contract supplied by root on 2026-10-14.

## Global Constraints

- Ownership only src/lib/records.ts/tests, src/components/records/**/tests, narrow App.tsx old-shell rename and outer mode choice; root owns backend.
- Generation, record version and updated_at_ms stay decimal strings; no Number conversion.
- Dirty editor retains its original revision and input across refresh/errors; explicit reload is required to accept a newer host.
- Connect uses host ID; cross-scope aliases never substitute for an ID.
- New hosts start Local and without a pin. Existing pin fields cannot be forged in an edit.
- Import key copies default unselected; only explicitly checked IDs are confirmed. No cancellation write.
- Private text and sync words stay in component/direct-call memory; never query/mutation cache, settings/localStorage or logs. Clear on success/cancel.
- Existing legacy config/vault/sync hooks never mount in Records/Blocked/paused mode.
- NeedsReview requires an explicit Reviewed settings checkbox before dropping blocking unsupported entries.
- Native services are still being implemented by root; mocked contract verification does not claim live API acceptance.

## Review Focus

- A late public overview response cannot replace a newer generation.
- A host deleted or changed remotely while dirty keeps the user's draft and stale revision for explicit conflict handling.
- Duplicate global IDs cannot arbitrarily select one row even if an alias is unique.
- Sensitive native command results/variables must not enter a QueryClient mutation cache.
- Account/device and import copy confirmation controls remain explicit when shared writes are gated.

### Task 1: Native client, editor state and consent

**Files:** src/lib/records.ts/tests; src/components/records/editor.ts/tests and fixtures.

- [x] Write RED tests for exact IPC args, large revision strings, public cache ordering, failure/input retention, reviewed imports, and per-key opt-in.
- [x] Implement typed direct client and editor state helpers; run focused GREEN.

### Task 2: Host workspace and mode boundary

**Files:** src/components/records/HostEditor.tsx, HostList.tsx, WorkspaceGate.tsx, RecordsWorkspace.tsx and tests; narrow App.tsx.

- [x] Write RED tests for lazy legacy dispatch, ID connect, readiness blocking, form revision submission and dirty refresh.
- [x] Implement themed master/detail host CRUD/move/connect and mode-specific loading/blocked/paused landing; run GREEN.

### Task 3: Keys, spaces/account and confirmed import

**Files:** src/components/records/ImportPanel.tsx, KeysPanel.tsx, AccountPanel.tsx and tests.

- [x] Write RED tests for explicit copy consent, key/sync-code clearing, receipt-only resume, and direct secret calls without mutation-cache storage.
- [x] Implement new forms, account code/join/spaces/select and key local/sync actions; retain public overview only.

### Task 4: Integration verification and owned commits

- [x] Run focused tests, full Vitest, typecheck/build; root owns live native integration and whole Rust gate.
- [x] Inspect exact owned diff; commit under /private/tmp/sshelter-index.lock using Conventional Commits.

## Design decisions

- Existing approved spec plus root's exact native contract establish the architectural brief; standing autonomy replaces another approval pause.
- React selected ID keys change only on user selection; server generation is never a React editor key.
- Direct async calls keep secret arguments/results out of mutation variables/data cache; public status query uses generation ordering.
- Paused Legacy offers explicit use-existing choice; local file import confirms only in active Records until a migration activation RPC exists.

## Base verification

Focused frontend: 48 tests passed. Complete frontend: 58 files / 901 tests passed. TypeScript and production Vite bundle passed. Existing large bundle advisory remains; no dependency changes. Final account leave/rotation APIs remain an explicit follow-up owned by this worker once native contract is supplied; baseline has no fabricated live RPC success. No actual app launch, credential access, relay request or user migration was performed.

## Authenticated key sync DTO follow-up

Root native KeyView.synced:boolean|null is authoritative for private-key sync intent; Account authority only identifies public metadata. Overview.last_sync_ms exposes the last saved sync timestamp.

- [x] RED tests for account metadata with synced=false (re-sync), null (disabled unknown), true (stop with queued-delivery wording), and last-sync/error display.
- [x] Implement typed fields and sync-intent-based controls; focused GREEN and typecheck only.
- [x] Exact owned commit under shared index flock. Leave/rotate/migration remain separate until root supplies actual contracts.
