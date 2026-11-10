# Windows installer identity

`nsis.nsi` and `main.wxs` derive from the MIT-licensed templates in Tauri CLI **2.11.2**. The license is in `LICENSE_TAURI_MIT`. Rebase and rerun the upgrade checks when updating the CLI; do not replace these templates with the defaults without keeping the changes below.

Upstream sources:

- https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.11.2/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi — SHA-256 `ee84148e405adc4d736a46456dd8345a644751bd1f28a335dd7fd833a32d7c3e`
- https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.11.2/crates/tauri-bundler/src/bundle/windows/msi/main.wxs — SHA-256 `e371a01628a06730828f9bd24111feacb8bec53c250ccec4b46df756fe0a0198`

## Identity

Both templates take the identity from Tauri's variables, as upstream does. The product name (`productName`: Lunport, or Lunport Dev) names the NSIS uninstall key, the manufacturer's product key and the login entry the uninstaller removes; the manufacturer is `bundle.publisher` (ysya); the executable is `mainBinaryName` (`lunport.exe`). The MSI UpgradeCodes stay pinned in the Tauri configurations: `d00b09d3-45df-5130-b6d5-52034e820843` (Production) and `cbb71e88-3302-5c89-a246-87037d1645f3` (Development).

Installs from before 2.0 registered another identity. Its values are written only in `legacy.nsh` (NSIS) and `legacy.wxi` (WiX), each a table from the current bundle identifier to that profile's earlier identity, and in `scripts/legacy-identity.json` for the upgrade check. `scripts/legacy-identity.test-node.mjs` keeps the three copies equal for both profiles; `scripts/identity-guard.mjs` allows those names in these files and nowhere else among the installer sources and scripts.

## Upgrading an earlier install

NSIS, run by hand or by the updater with `/UPDATE`, in every mode including silent:

- The install directory comes from the earlier manufacturer key, or else the earlier uninstall entry's `InstallLocation`, when the current key has none.
- While an earlier installation is registered or its executable is still in the install directory, the running-application check also stops the earlier executable: an AI client's MCP adapter or a terminal session may still run it.
- Once its own registration is complete, the installer removes the earlier one in place: the earlier executables (and, when that install is in another directory, its uninstaller), the earlier uninstall key and the values the earlier NSIS kept under the manufacturer key. Add/Remove Programs lists one entry. An executable still in use stays and is named in the installer's details. In the install directory, a later update or the uninstaller removes it; in another directory nothing tries again, since the registration that pointed there is gone. These deletes do not use `/REBOOTOK`: a per-user installer cannot schedule a delete at restart, and the reboot flag would only turn the finish page into a reboot prompt.
- Shortcuts that started the earlier executable are pointed at the current one with the current AppUserModelID: product-named shortcuts (upstream's `MainBinaryName` migration), shortcuts under the earlier name (`hooks.nsh` gives them the product name) and taskbar pins (kept under their names, which the taskbar refers to).
- Application data, saved credentials and the login entry stay as they are; the app moves them to the current identity on its first start. Uninstalling removes the login entry under both names.
- The reinstall page offers to uninstall an earlier MSI, now also one with the earlier manufacturer or name. It does not offer to uninstall an earlier NSIS install, which is replaced in place, so the earlier uninstaller and its delete-data choice never run.

MSI: the major upgrade (same UpgradeCode) removes the earlier product. The install directory comes from the earlier registry key when the current keys have none, and the shortcut names of the oldest MSIs are removed when upgrading one. As before, the MSI does not touch the login entry.

## Template notes

- makensis resolves `!include` from the generated script's directory, so `hooks.nsh` (included by absolute path) puts its own directory on the include path for `nsis.nsi` to include `legacy.nsh`.
- candle resolves `<?include?>` from the directory of the generated `main.wxs`, which Tauri writes to `target/release/wix/<arch>/` under `src-tauri`, so `main.wxs` includes `..\..\..\..\installers\legacy.wxi`. A build into another directory (with `--target`, for example) has to change that path; candle stops with a missing-file error instead of building without it.
- Handlebars consumes one backslash before its expressions, so the template keeps doubled separators before Handlebars expressions and a single separator before WiX variables. Rendered registry keys must contain one separator and no unexpanded expressions; the bundle check verifies the previous-directory searches in the rendered template and in the MSI before saving a candidate.

## Linux packages

Linux uses the `lunport` / `lunport-dev` package names. Their DEB provides/conflicts/replaces and RPM provides/obsoletes relations to the earlier package names are fixed in the Tauri configurations. Package upgrades are checked separately from GUI validation.

## Validation

`.github/workflows/windows-bundle-check.yml` builds both installers, checks their identity and contents, and preserves the unsigned test candidates for three days, with source and package checksums. Its upgrade job uses a clean runner, separate from administrative MSI extraction and console tests, and runs `scripts/validate-windows-rebrand.ps1`. Each phase installs the published 1.14.4 with application data, two saved credentials (one in a DPAPI file), an enabled login item and shortcuts under both names, then upgrades it: first the in-app update (the NSIS installer with the updater's `/P /R /UPDATE /ARGS` while a 1.14.4 MCP adapter still runs), then the NSIS installer by hand (`/S`), then the MSI. It checks the installer's result, what the app's first start moved and what uninstalling removes and keeps, and reports every failing check at the end. A manual run can reuse a previous candidate run ID for upgrade-only diagnostics; it rejects changed product sources or package checksums. These artifacts are not published releases.

For installer-only repairs, the workflow can repackage an earlier verified candidate with `tauri bundle` instead of recompiling Rust. It checks repository/source provenance and package checksums, rejects runtime or configuration changes, and records the original runtime source in the new candidate.
