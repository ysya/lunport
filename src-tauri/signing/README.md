The public `macos-project.pem` pins Lunport's macOS code-signing identity. Stable and Beta use this same certificate and the production bundle identifier `org.homelab.sshelter`. Its SHA-256 fingerprint is:

```
6bce9f14c85274ab36911c91c48e52249e49089afee80e6465b54ab6f4174830
```

This self-signed project certificate preserves the designated requirement across rebuilds, which lets Keychain recognize an authorized app after an update. It is not an Apple Developer ID and does not provide notarization or Gatekeeper approval. Never rotate it per release or replace it with ad-hoc signing. Changing the certificate requires a deliberate migration and can require user authorization again.

The encrypted PKCS#12 identity and password are stored in repository secrets `LUNPORT_MACOS_CERTIFICATE` (base64) and `LUNPORT_MACOS_CERTIFICATE_PASSWORD`. The initial local recovery copy is in the ignored `.local-signing/` directory with owner-only permissions. Treat both files as private signing material and back them up securely; they must never enter Git, artifacts or logs. Only this public certificate belongs in source control.

`scripts/macos-signing.sh` imports the identity into a temporary CI keychain, checks the certificate pin, and restores the search list on cleanup. It never installs a trusted root. `scripts/build-macos-release.sh` checks both universal architectures, the embedded certificate and the designated requirement in the App and updater archive before tauri-action uploads assets. Missing or changed credentials fail the build instead of silently reverting to unsigned output.

`scripts/validate-macos-keychain.sh` separately proves that different executable builds with the same signer retain access, a different signer is denied, and (with `--with-rust`) the production metadata query finds an item without gaining access to its protected password. It uses disposable CI credentials only.
