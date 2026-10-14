# Own SSH Phase 1c-2 Read-Only Importer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preview explicitly selected SSH configuration and legacy relay host text with source fingerprints, stable alias mappings, key source suggestions, and no writes or command execution.

**Architecture:** The existing lexer/parser supplies lossless static directives. A dedicated capped source reader creates an Include tree with path/line provenance, canonical cycle detection, and source deduplication. A pure resolver evaluates first valid supported values and records every unsupported directive; only typed records can leave the preview.

**Tech Stack:** Rust; existing config parser, glob, sha2, serde, getrandom; no new dependencies.

**Spec:** docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md section 6 and own-ssh-client-design.md section 5.1. Verified primary references: https://man.openbsd.org/ssh_config and https://github.com/openssh/openssh-portable/blob/master/readconf.c (Include restores the parent active state; root depth zero, maximum depth sixteen).

## Global Constraints

- Depth 16, at most 128 source files, at most 1 MiB per file and 4 MiB total; errors name the source path and line.
- Explicit home/env values; never mutate or read process environment for expansion.
- No ssh -G, Match exec, ProxyCommand, KnownHostsCommand, LocalCommand, config load/repair, vault, Keychain, relay, or original-source writes.
- Private key sources in IdentityFile are suggestions only, never opened; private key content found in a selected configuration is rejected without exposing its bytes.
- File previews default to local; host IDs are random unless supplied by a confirmed journal mapping. Legacy relay previews retain space and derive their ID from space/old record ID.
- Duplicate physical sources are read once and are surfaced for review when repeated inclusion could affect semantics. Cycles always fail.
- Runtime activation, vault copying consent, preview confirmation, journal persistence, publishing, and real device tests belong to later root-owned work.
- Serialize exact-path staging/commits through /private/tmp/sshelter-index.lock and inspect cached paths before committing.

## Review Focus

- A nested Include inside an inactive Host must not give another alias active settings.
- Host wildcards and negations apply defaults, never become host candidates.
- Match and dynamic tokens cannot execute or silently become safe defaults; keep originals and block connection.
- Additional IdentityFile entries cannot silently collapse into one supported key; show each suggestion and require review.
- A ProxyJump endpoint override must not reuse a saved host's ID for a different endpoint.

---

### Task 1: Bounded explicit sources and provenance

**Files:** Create src-tauri/src/sync/records_v3/importer/{mod.rs,source.rs,types.rs,tests.rs}; modify records_v3/mod.rs.

**Interfaces:**
- Consumes: config::parser::parse_file; config::model::{Item,Directive}; explicit ImportOptions { home, env, at_ms, host_ids, key_ids, excluded_sources, reserved_host_ids }.
- Produces: preview_file(source:&Path,options:&ImportOptions)->Result<ImportPreview,ImportError>; source::load(source,options)->Snapshot; SourceLocation { path,line }; SourceFile { path,canonical_path,digest,bytes }; structured ImportError; internal Include tree.

- [x] **Step 1: Write loader RED tests.**

```rust
let source = fixture("config", "Include cycle\nHost web\n");
assert!(matches!(source::load(&source, &options), Err(ImportError::Cycle { .. })));
```

Tests cover root/relative/quoted/glob Includes; depth 17 refusal; 129th file refusal; file 1 MiB+1 and total 4 MiB+1 refusal; canonical symlink cycles/dedup; environment expansion from injected map; missing variable preservation; managed-source exclusion; private-key content rejection; and byte-for-byte source preservation.
- [x] **Step 2: Run focused tests.** `CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target cargo test --manifest-path src-tauri/Cargo.toml --offline --locked --lib sync::records_v3::importer`. Expected: loader assertions FAIL with the empty snapshot stub.
- [x] **Step 3: Implement capped source loading.** File::take(MAX_FILE_BYTES+1) bounds reads. Check canonical recursion stack before dedup; exclude explicit managed sources; parse only UTF-8 static text. Includes use explicit home/.ssh for relative paths, lexical glob order and injected ${VAR} expansion. Preserve unresolved path directives as unsupported events. Never call existing include::load_doc.
- [x] **Step 4: Run focused tests.** Expected: every source test PASS and original fixture bytes unchanged.
- [x] **Step 5: Commit exact owned files.** Commit message `feat(sync): add bounded read-only import sources`; ledger full command/result.

### Task 2: Pure host preview and legacy source mapping

**Files:** Create importer/resolve.rs; modify importer/mod.rs/types.rs/tests.rs and owned plans.

**Interfaces:**
- Consumes: Task 1 Snapshot; records_v3 HostRecord/HostPayload/ImportedSettings/UnsupportedSetting; migration_host_id; validate_hosts.
- Produces: ImportPreview { candidates, warnings, provenance, key_references, host_ids, source_digest }; preview_legacy_record(record:&Record,space_id:&str,options:&ImportOptions)->Result<ImportPreview,ImportError>; preview_legacy_records(records:&[Record],space_id:&str,options:&ImportOptions)->Result<ImportPreview,ImportError>; KeyReferenceSuggestion { host_id,key_id,value,resolved_path,fingerprint,will_copy } (fingerprint is None until a later explicit key selection).

- [x] **Step 1: Write RED tests for real preview behavior.**

```rust
let preview = preview_file(&source, &options).unwrap();
assert_eq!(preview.candidates.iter().map(|h| h.payload.alias.as_str()).collect::<Vec<_>>(), vec!["web", "db"]);
assert_eq!(preview.candidates[0].payload.port, 2222);
```

Use literal fixtures for multiple aliases; global/wildcard defaults and negation; first valid values across Includes; inactive conditional Include and parent scope restoration; Match exec/ProxyCommand/LocalCommand marker remains absent; token settings require review; explicit home key suggestions without opening key files; multiple key suggestions; missing jumps require review; saved jump ID reuse only at the identical endpoint; complete new jump endpoint synthesis; jump cycles; stable supplied journal IDs and deterministic relay IDs; changed source digest invalidates confirmation input.
- [x] **Step 2: Run importer tests.** Expected: preview assertions FAIL with an empty candidate resolver.
- [x] **Step 3: Implement pure resolution.** Respect OpenSSH * and ? patterns and negation. Restore containing scope after included files; only exact aliases become hosts. Map typed scalar timeouts/port/user/hostname and the engine's supported auth preference suffixes. Preserve all unsupported original keyword/value pairs with source/line reasons; mark blocking settings requires_review. Identity paths resolve from explicit home and become suggestions only. Resolve ProxyJump to preview records; ambiguous/missing or conflicting endpoint references remain review-required. Relay text preview uses schema 1 source, old record alias, original space and deterministic migration ID; never reads Includes from another device's source text.
- [x] **Step 4: Run importer and all records tests.** `CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target cargo test --manifest-path src-tauri/Cargo.toml --offline --locked --lib sync::records_v3`. Expected: all new preview tests and record primitive regressions PASS. Root later runs the full safe suite and CI integration.
- [x] **Step 5: Commit exact owned paths through the shared index lock.** Commit message `feat(sync): preview static SSH hosts without side effects`; record results in ledger.

## Rulings

- OpenSSH user Include relative paths resolve from explicit home/.ssh; the legacy include loader's parent-directory policy is not reused.
- Include restores its caller's active scope; use a tree, not naive concatenation.
- Repeated physical sources are deduplicated with an explicit blocking review notice because conditional repeated inclusion can otherwise change settings. This keeps source loading bounded without pretending full OpenSSH runtime evaluation.
- Match is conservatively review-required and never evaluated. Unsupported conditions do not supply typed endpoint/auth values.
- Private key fingerprint/material handling awaits explicit user selection; this preview displays source suggestions with fingerprint None and will_copy false.

- Legacy batch previews resolve each source alias independently, then bind jumps across the complete immutable space snapshot. Missing legacy jumps remain review-required; no random shared identities are invented.
- Legacy preflight reserves all original aliases, including tombstones, and caller-supplied unrelated identities; hash collisions return an explicit error.
- Confirmation source fingerprints include full relay Record metadata, so version changes invalidate an earlier preview even when text is unchanged. Relay provenance paths are virtual labels and must not be opened as files.
- Focused verification: isolated importer 18 passed; registered project records tests 39 passed, 0 failed. The root owns the later full safe suite, runtime integration, and independent review.
