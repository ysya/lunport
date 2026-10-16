# Developing Lunport

Lunport uses Tauri 2, Rust, React, TypeScript and Vite, with Tailwind, shadcn/ui, TanStack Query and Zustand. Privileged file access and SSH operations run in Rust; the WebView has no filesystem or shell-execution permission. The Records workspace uses the built-in SSH engine; Legacy retains OpenSSH configuration tooling.

## Local setup

Install Rust through mise or rustup, Node and pnpm. macOS needs Xcode Command Line Tools. Linux needs the Tauri platform dependencies, including `libwebkit2gtk-4.1-dev`, `build-essential`, `libssl-dev` and `librsvg2-dev`.

With mise, run `mise install` for the project's Rust toolchain. Prefix commands with `mise exec --` when mise is not active in your shell.

```bash
pnpm install
pnpm tauri:dev
pnpm build
pnpm test
cd src-tauri
cargo test --locked
```

Some backend tests need a scratch OpenSSH server or platform-specific facilities; credential-service tests can touch the OS keychain. The safe suite and platform-specific checks are defined in [the SSH engine workflow](../.github/workflows/test-engine.yml) and [the Windows workflow](../.github/workflows/test-windows.yml).

## Isolated Development profile

`pnpm tauri:dev` runs **Lunport Dev**. `pnpm tauri:build:dev` builds a release-mode Development bundle. The Development profile uses `org.homelab.sshelter.dev`, the `SSHelter Development` credential service and a sandbox home under its data directory. It can run beside Production. Writes remain in that sandbox; updater and login integration are disabled. Selected external import sources are read and copied, preserving the originals.

Development refuses Legacy system-SSH evaluation, Connect, deployment and MCP execution before spawning OpenSSH. Records connections use the built-in engine. A build whose configured product name or identifier disagrees with its compiled profile refuses initialization.

An ordinary `pnpm tauri build` uses the Production profile. Keep the two profiles separate when validating existing data.

## Brand assets and compatibility

The mark geometry lives in [lunport-mark.json](../src/brand/lunport-mark.json); [product.json](../src/brand/product.json) supplies the About copy. Regenerate native and web icons from the canonical geometry with:

```bash
node scripts/generate-brand-icons.mjs
```

Use Lunport for visible product copy and `ysya/lunport` for current repository links. Bundle IDs, credential services, executable names, MCP registration, SSH paths and persisted storage keys intentionally retain their SSHelter identities. See [installer compatibility](../src-tauri/installers/README.md) before changing any of them. Historical releases, validation records and signatures retain their original names.

The 2.11.2 runtime has a narrow [context ownership patch](../src-tauri/vendor/tauri-runtime-wry/LUNPORT_PATCH.md). Preserve its provenance and run the handle-only, native tray and actual GUI regressions before updating or removing it. The patch keeps worker handle clones from copying a non-atomic native event-loop reference count.

## Release workflow

Stable releases use release-please. A push to `main` opens or updates a release PR; merging that PR creates the version tag and GitHub Release, then builds the platform installers and updater assets. Review the version, changelog and checks before merging a release PR. An ordinary feature or documentation merge does not itself publish an installer.

For each release, check the README, user guide and installer names against the actual packages and verify both update channels. Historical SSHelter releases and their assets remain intact. Native runtime changes require a failing baseline reproduction, repaired regression checks and full platform validation before publication.

For a beta, run **publish beta** in GitHub Actions with a new `X.Y.Z-N` version, using a numeric suffix. The workflow stamps the version, creates the prerelease, builds the platforms and updates the `updater-beta` manifest. Beta-channel devices can receive Stable releases too.

If a build fails, use **Re-run failed jobs** on that run to keep the same source and inputs. Do not use `build-platform.yml` for a beta: it does not stamp the beta version or update that channel. Use a new version for changed release content; preserve published tags, installers and signatures.

The **update beta channel** workflow can reconcile the Beta manifest with an existing release. It checks that the release manifest is complete, never moves the channel backwards and leaves an already current channel alone.

The Windows bundle workflow separately validates helper placement and old-version installer upgrades. It supports verified candidate reuse for installer-only diagnostics; see [installer documentation](../src-tauri/installers/README.md). These unsigned CI artifacts are not published releases.

## License

Lunport is licensed under [PolyForm Noncommercial 1.0.0](../LICENSE), Copyright © 2026 Frank Sung. Included third-party installer templates retain their separate [MIT notice](../src-tauri/installers/LICENSE_TAURI_MIT).
