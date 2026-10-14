# Read-only vault reader implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this scoped implementation; parent owns broker/importer integration and final branch verification.

**Goal:** Read vault metadata and keys for preview, migration and connection without filesystem or credential-store mutations.

**Architecture:** A private ReadOnlyVault wrapper exposes ids/get/settings/key_account and no mutators. The reader parses a bounded snapshot directly and never calls the archival writable loader. Entry decryption reuses the existing zeroizing and sanitized Vault::get implementation.

**Tech Stack:** Rust std::fs/std::io, existing serde/crypto/zeroize, MemKeychain spies and tempfile fixtures.

**Spec:** docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md sections 4 and 6; parent-authorized read-only reader contract.

## Global constraints

- Existing Vault::open semantics remain unchanged.
- Maximum input is 64 MiB; metadata and capped Take(limit + 1) both enforce the bound.
- Accept only vault formats 1 and 2; future formats return Newer before full decode or credential reads; format 0 is refused.
- Recognized accounts are vault:key or vault:key: followed by exactly 16 lowercase hex characters, validated before any credential read.
- Missing file returns an empty view without mkdir, credentials or file creation; empty vaults need no credential read.
- Corrupt/keyless/credential failures preserve every source byte and filename; errors use static text that cannot echo source or credential values.
- Only vault/store.rs reader sections and tests are owned; parent owns broker adapters and other workers' edits remain intact.

## Review focus

- Corrupt or keyless preview must preserve the original instead of archiving it.
- A valid future header with an incompatible body must not query Keychain.
- A forged header must not query host: or sync: credential accounts.
- A file growing after metadata validation must stop after the cap plus one byte.
- Decrypted JSON type errors must not echo private values.

### Task 1: Bounded read-only view

**Files:** src-tauri/src/vault/store.rs reader helpers and focused tests.
**Interfaces:** read_vault(&Path, &dyn Keychain) -> Result<ReadOnlyVault, VaultError>; ReadOnlyVault ids/get/settings/key_account only.

- [x] Add an initial adapter to the existing loader plus regression tests, preserving existing writer semantics.
- [x] Run cargo test --offline --locked --lib readonly_vault and observe corrupt archival, namespace/credential reads, error echo and missing cap failures.
- [x] Replace the adapter with direct bounded file parsing, version/account validation and read-only key lookup.
- [x] Rerun focused read-only tests and all vault::store tests.
- [x] Verify git diff --check, update ledger and commit exact owned paths under shared index lock.

Core cap:
```rust
reader.take(MAX_READ_ONLY_VAULT_BYTES + 1).read_to_end(&mut bytes)?;
if bytes.len() as u64 > MAX_READ_ONLY_VAULT_BYTES { return Err(limit_error()); }
```
