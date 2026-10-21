# Independent device identities for new server workspaces

The UI audit found that device recovery has no usable next step. Source tracing now confirms that a fresh `server-workspace-*` still calls `DeviceIdentity::load_or_create` in the account's default OS credential slot. Opening an empty library therefore reuses a revoked or unavailable device instead of creating a new device that can unlock with the sync password.

## Proposed change

- Existing workspaces keep their exact protected identity selection, account, files, trust anchor and highwaters.
- A newly created empty server workspace uses its native 32-hex workspace ID as an immutable device credential selector. The account locator continues to scope every OS credential.
- Initial selection needs a narrow native publication capability: exact empty source, generation, process-selected workspace path, protected identity readback, verified account session and accepted device registration. Ordinary state writers must continue rejecting an initial forged selector and any selector replacement.
- Passkey authenticates the account. A new device remains pending until the existing password unlock verifies history and signs its additive enrollment. Creating a new local credential grants no Vault membership or content keys.
- No default credential is overwritten or deleted. Retained libraries remain readable. Cloudflare and Docker protocols are unchanged.
- Revoked/lost devices can explicitly open a separate library, sign in and enter the existing sync password. Host and Group settings can be copied back using reviewed data import.

## Required checks

Verify two workspace identities differ and survive restart; repeated login reuses the selected identity; default/retained slots remain byte-identical; arbitrary paths/selectors and stale generations cannot publish; revoked/expired/mismatched grants cannot create an active library; password unlock retains normal membership/history checks. Run existing replacement, bootstrap, device and profile tests on all three platforms.

This decision changes the native identity selection boundary and requires the user's architectural approval under AGENTS.md. The UI/status/conflict/export cleanup can be validated independently.
