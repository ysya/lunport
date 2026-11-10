# CI and release checks

Application checks run on pull requests, once per revision. A newer revision cancels
obsolete checks. Merging does not repeat the same test suites; `Release - Stable`
runs release-please and builds installers only when a release PR is merged.

| Workflow | When | Responsibility |
| --- | --- | --- |
| CI - App | Every PR; manual full run | Version consistency, CI policy and identity tests, the identity guard and workflow syntax; frontend tests/build for UI changes; macOS and Linux Rust/SSH tests for native changes |
| CI - Windows | Every PR (Windows suites for native changes and the console helper scripts); manual | Windows Rust/SSH, console, GUI startup and one native tray smoke test |
| CI - macOS credentials | Every PR (suites for credential/signing/build scripts, the identity files the frozen helpers are pinned to, the identity data the scripts read, `tauri.conf.json` or Rust dependencies); manual | Disposable Keychain authorization, frozen helper transport/recovery, signed universal app and updater |
| CI - Relay | Relay paths; manual | Relay tests, deployed update script and self-host integration |
| Packages - Linux upgrade | Installer, icon, meaningful Tauri config, upgrade check or identity data changes; manual | DEB/RPM packaging and upgrade from the published 1.14.4 |
| Packages - Windows upgrade (manual) | Explicit dispatch | NSIS/MSI contents and upgrade; supports reuse of verified candidates |
| Release - Stable | Push to main; manual | Release PR/tag, signed installers and update channels |
| Release - Beta (manual) | Explicit version and notes | Beta installers and update channel |
| Recovery - Release platform (manual) | Existing stable tag and platform | Repair one failed platform build |
| Recovery - Beta manifest (manual) | Existing release tag | Refresh the Beta manifest after a repaired build |

## Selecting PR checks

`scripts/ci-changes.mjs` compares the PR base and head, including both sides of a
rename. It shares one policy across the app, Windows, Linux package and macOS
credential workflows. Workflow files keep their existing paths and native job IDs
so dispatch scripts and Rust caches continue to work.

- UI changes run frontend tests/build without three native suites.
- Rust changes run native suites without rebuilding the UI. Changes spanning both
  areas run both. Rust dependency changes also run credential checks.
- Release-profile boundary builds run on all three desktop platforms when their
  profile, identity, write policy, central sync capability, library entry point,
  build configuration or test
  changes. Other Rust changes keep the full platform debug suites and skip the
  extra production and development release builds.
- Docs changes run the inexpensive policy/version/workflow check.
- The Linux upgrade check runs for changes to its script and to the identity data it reads
  (`scripts/identity.mjs`, `scripts/legacy-identity.json`). The Rust tests compare
  `scripts/legacy-identity.json` with `legacy_identity`, so it runs the native suites too.
- `scripts/windows-console-helper.mjs` and `scripts/identity.mjs` run the Windows suite,
  whose console helper step builds the helper the way the Windows builds do.
- The macOS credential checks run for changes to the frozen helpers and their scripts, to
  the identity files that pin the helpers (`src-tauri/src/identity.rs`,
  `src-tauri/src/legacy_identity.rs`), to the identity data the scripts read
  (`scripts/identity.mjs`, `scripts/legacy-identity.json`) and to `src-tauri/tauri.conf.json`,
  whose bundle identifier the test clients are signed with.

## Required checks and auto-merge

`main` requires the checks that report on every PR: `Policy, versions and workflow lint`,
`Frontend tests and build`, `Rust and SSH (macOS)`, `Rust, SSH and PAM (Linux)`,
`Rust, SSH and native smoke (Windows)`, `Helper authorization protocol`,
`Frozen helper and Rust transport` and `Signed universal app and updater`. A job its
selection step skips reports as passing, so each of them can be required. CI - Windows
and CI - macOS credentials therefore run their selection job on every PR instead of
filtering by path. The `Production and Development boundaries` matrix is not required:
GitHub reports a skipped matrix job under its unexpanded name. Auto-merge is allowed and
merges a PR once every required check passes; administrators can still merge past them.
- Pure application version changes in package.json, Tauri config, Cargo.toml and
  the root Cargo.lock package skip compilation. Dependency, capability, installer
  or configuration edits in the same PR still run their relevant checks.
- All five version carriers, including release-please's manifest and Cargo.lock,
  must agree. Missing or malformed files fail the gate; they cannot silently skip
  validation.
- A manual application/package/credential dispatch runs its full scope. For a
  deliberate direct push without a PR, dispatch the affected checks explicitly.

The policy has Node-only regression tests, including release version changes,
dependency/configuration changes, missing files and manual runs. They also check that each
workflow passes the selection on under its own name and that every job condition reads one
it declares, since a misspelt output skips the job and a skipped required job reports as
passing:

```sh
node --test scripts/ci-changes.test-node.mjs
```

The same job keeps identity values in one place. `scripts/identity-guard.test-node.mjs`
scans every file git tracks and fails on a name from before 2.0 outside the places
`scripts/identity-guard.mjs` allows.
`scripts/note-citation-guard.test-node.mjs` scans the same files and fails on a citation of a
planning document that is not in the repository: a section, task, requirement or review-round
number of a spec, plan or design, or a design named by its date. `scripts/note-citation-guard.mjs`
lists each form and the files that may hold one.
`scripts/identity.test-node.mjs` checks what `scripts/identity.mjs` reads from the Tauri
configurations, the console helper's crate, `src-tauri/src/identity.rs` and the frozen helper
manifests;
`scripts/windows-console-helper.test-node.mjs` checks the step every Windows build uses to
bundle the console helper; `scripts/legacy-identity.test-node.mjs` checks that the NSIS
and WiX includes and `scripts/legacy-identity.json` hold the same earlier installer
identity for both profiles. Every Node script test runs locally with:

```sh
node --test scripts/*.test-node.mjs
```

## Update endpoints

The Tauri updater tries its endpoints in order. Stable (`plugins.updater.endpoints` in
`src-tauri/tauri.conf.json`) asks `https://lunport.ysya.dev/update/stable.json`, then
`https://github.com/ysya/lunport/releases/latest/download/latest.json`. Beta
(`BETA_ENDPOINTS` in `src-tauri/src/updater_channel.rs`) asks
`https://lunport.ysya.dev/update/beta.json`, then
`https://github.com/ysya/lunport/releases/download/updater-beta/latest.json`. The two
ysya.dev URLs redirect to those GitHub manifests, so releases and `scripts/beta-channel.mjs`
keep publishing `latest.json` on GitHub only. Installs before 2.0 ask GitHub directly, so the
GitHub manifests stay where they are. Every update is verified against the updater public
key in the Tauri configuration, whichever URL served it.

tauri-plugin-updater (2.10.1) moves on to the next endpoint only after a network error, an
error status, or a JSON answer that is not an update manifest. Any other successful answer
ends the check: a body that is not JSON ends it with an error, and `204 No Content` ends it
with no update. GitHub is therefore the fallback for an outage of the domain (it does not
resolve, cannot be reached or answers with an error), not for a parked or reused domain,
whose page answers `200`. Keep `ysya.dev` registered and the `lunport.ysya.dev` redirect
rules in place: every release from 2.0 asks it first.

## Tray and Keychain regressions

The normal Windows job runs the native tray regression in **one process**. The
existing test still exercises startup and concurrent updates. For an intermittent
native regression, dispatch `CI - Windows` with `native_probe=true`, choose `tray`
or `handles`, and supply `baseline_ref`. Only that explicit comparison runs ten
independent processes for each source; it does not run the full application suite.

Keychain probes run only in their dedicated workflow on disposable macOS runners.
The helper Rust job includes the partition regression;
the separate identity job is reserved for `identity_only=true` or fork PRs without
signing secrets. Ordinary releases verify and embed the frozen helper; they never
rebuild it. `freeze_helper` remains an explicit candidate-generation operation.

Workflow syntax is checked on every PR with the existing pinned actionlint image.
The relay's deployed workflow retains its separate shellcheck validation.

## Action versions and runtime

Audited against upstream stable releases on 2026-10-18. Workflows use the
maintained major tags, except pnpm, whose `v6` tag trails v6.1.0; that Action uses
the explicit stable release. `dtolnay/rust-toolchain@stable` deliberately tracks the
stable Rust channel. The deployed relay workflow follows the same versions.

| Action | Workflow ref | Stable release checked | Action runtime |
| --- | --- | --- | --- |
| actions/checkout | v7 | [v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) | Node 24 |
| actions/setup-node | v7 | [v7.1.0](https://github.com/actions/setup-node/releases/tag/v7.1.0) | Node 24 |
| actions/upload-artifact | v7 | [v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) | Node 24 |
| pnpm/action-setup | v6.1.0 | [v6.1.0](https://github.com/pnpm/action-setup/releases/tag/v6.1.0) | Node 24 |
| googleapis/release-please-action | v5 | [v5.0.0](https://github.com/googleapis/release-please-action/releases/tag/v5.0.0) | Node 24 |
| tauri-apps/tauri-action | v1 | [action-v1.0.0](https://github.com/tauri-apps/tauri-action/releases/tag/action-v1.0.0) | Node 24 |
| Swatinem/rust-cache | v2 | [v2.9.2](https://github.com/Swatinem/rust-cache/releases/tag/v2.9.2) | Node 24 |
| dtolnay/rust-toolchain | stable | stable channel | Composite; no Node runtime |
| rhysd/actionlint (Docker) | 1.7.12 | [v1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12) | Container; no Node runtime |

`setup-node`'s `node-version: lts/*` selects Node for project commands; it does not
change the runtime declared inside another Action. Node 24 Actions require runner
v2.327.1 or newer; these workflows use GitHub-hosted runners.

Tauri Action v1 uploads to the existing release by **release ID**, bypassing its
new behavior that edits an existing release's name/body when resolving a tag.
Stable, Beta and repair workflows retain their existing release metadata. The
macOS wrapper still verifies the original local archive before upload; v1 adds
version information to its uploaded name. Updater manifests now use GitHub asset
API URLs and retain universal macOS entries alongside architecture aliases. The
shipped Tauri updater downloads with `Accept: application/octet-stream`, and Beta
promotion accepts these URLs and additional aliases without rewriting signatures.
Old published releases and their manifests are left intact.

Workflow artifacts explicitly retain ZIP archiving for the existing `gh run
download` consumers. Windows candidate provenance checks use the workflow file
path, so display-name changes do not invalidate candidates.
