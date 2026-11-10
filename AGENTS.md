# Agent guidelines

Lunport is a public repository. These rules apply to every coding agent that works in it.

## Keep internal notes out of the repository

- Write design specs, implementation plans, review records, handoff notes and validation logs outside the repository, in your agent's own plans or scratch folder. Never commit them, and do not cite them from code comments, documentation, pull request descriptions or release notes.
- `docs/` holds only `usage.md`, `development.md`, `ci.md` and `central-server-configuration.md`. Screenshots and review artifacts stay local.
- Agent configuration folders such as `.claude/` stay untracked; shared agent instructions belong in this file.

## Test data and secrets

- Tests, fixtures, documentation and comments use synthetic names only: Google Cloud projects `acme-dev-654321` and `acme-prod-123456`, accounts `frank@example.com` and `ops@example.com` (OS Login user `frank_example_com`), host `web-1`, key comment `frank@laptop`.
- Never copy real project ids, work accounts, host names, IP addresses or local home paths into the repository.
- Never commit signing keys, certificates, passwords or tokens.

## Conventions

- Code, comments and commit messages are in English; commits follow Conventional Commits.
- Build and test commands are in `docs/development.md`, and CI's check selection is in `docs/ci.md`. The CI-safe Rust suite runs in `src-tauri/`: `cargo test --locked --lib -- --test-threads=2 --skip secrets::tests::round_trip_set_get_delete --skip ssh::engine_tests::login_methods::pam`, together with `pnpm test` and `pnpm build`.
- Running the Rust tests regenerates the ts-rs bindings in `src/bindings/`; keep binding changes only when a Rust type changed.
- `src/lib/ipc-parity.test.ts` fails when the frontend calls a command that `src-tauri/src/lib.rs` does not register.
- Identity values (application id, product name, executables, credential service and the like) live in `src-tauri/tauri.conf.json`, `src-tauri/tauri.dev.conf.json` and `src-tauri/src/identity.rs`; scripts and workflows read the Tauri configurations, or `scripts/identity.mjs`, which prints each profile's application id, product name, publisher, main binary, console helper, credential service, login item and installer identity, and the frozen macOS helper manifests. `identity.mjs` reads the `PRODUCTION` and `DEVELOPMENT` blocks and `HELPER_V2_IDENTIFIER` of `identity.rs` as text, so keep those values plain string literals. Names from before 2.0 belong only in `legacy_identity`, `legacy-identity` and `scripts/legacy-identity.json`, and the few other places `scripts/identity-guard.mjs` lists.
