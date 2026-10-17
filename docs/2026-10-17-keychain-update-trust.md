# Keychain authorization across macOS updates

The published 1.1.0 archive had an arm64 linker ad-hoc signature and an unsigned Intel executable. Those builds lack a stable code requirement that Keychain can recognize across updates. Separately, `secrets_has` read the password merely to show whether it existed.

Release downloads now share the project certificate pinned in [the signing policy](../src-tauri/signing/README.md). Its SHA-256 is `6bce9f14c85274ab36911c91c48e52249e49089afee80e6465b54ab6f4174830`. On the tested runner, both architectures use the same designated requirement:

```
identifier "org.homelab.sshelter" and certificate root = H"a346b47b8dccb4faeac8aec1ea997535809aeec9"
```

This is a self-signed project identity, not an Apple Developer ID or notarization. No certificate is installed in the user's trust store. Stable and Beta use the same identity; the updater's existing Minisign key, bundle identifiers, Keychain service/account names and credentials are retained. The first migration from an unsigned/ad-hoc build can still require authorization for existing items. Choosing Always Allow lets later builds with this identity retain that permission; one-time Allow and a locked Keychain still retain their normal macOS behavior.

macOS saved-password presence checks now request attributes only, with no protected data and no authentication UI. Protected get/set/delete operations run serially. No password cache, automatic ACL modification or noninteractive credential permission was introduced.

Validation of product candidate `882fc1922cc47db88c913e4a0f7b5c6a8706a4c1`:

- [Actual universal App and updater archive](https://github.com/ysya/lunport/actions/runs/39019569623): Tauri completed signing and packaging. Both the bundled App and extracted updater App passed strict signature verification, the certificate pin and designated-requirement checks on x86_64 and arm64 before any upload. A tiny universal App signed with the actual project certificate also retained access across different executable builds; re-signing at the same path with an ad-hoc identity was denied, with authentication UI disabled.
- [Frontend, macOS and Linux](https://github.com/ysya/lunport/actions/runs/39019569621): frontend tests/build, safe Rust suites and profile selections pass. The native metadata test found an ACL-protected item without obtaining password access. It ran exactly one test against a disposable CI keychain. A separate native probe confirms same-signer upgrade access and rejects a different signer.
- [Windows functional checks](https://github.com/ysya/lunport/actions/runs/39019569630): the safe suite, profile builds, actual app, AppHandle/tray regressions, GUI, console and OpenSSH checks pass. macOS-specific changes preserve the existing Windows credential behavior.
- Local macOS safe Rust suite: 2,601 passed; frontend: 84 files / 1,071 tests plus TypeScript and Vite production build. Credential tests requiring personal Keychain access were excluded; native Keychain assertions ran on isolated CI runners.

The final documentation commit removes two ignored workflow-artifact options unsupported by tauri-action v0. Signing scripts, release workflows and product sources remain identical to the validated candidate. The check builds and verifies without publishing; release workflows still upload only after the wrapper succeeds.
