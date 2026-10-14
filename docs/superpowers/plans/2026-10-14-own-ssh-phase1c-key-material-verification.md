# Broker key material verification

Spec: own-SSH migration design sections 5 and 8: metadata is authoritative; mismatched local material must never sign.

Ownership: root owns session/auth.rs. The records worker owns typed metadata validation; no second runtime owner or account protocol changes here.

1. Add a KeyStore fixture returning PLAIN_PRIVATE but a different or malformed saved public key; assert unlock fails, no public key is offered, and sign returns KeyUnavailable. Watch RED.
2. After material opens, parse the saved public key with ssh_key::PublicKey and compare key_data to Material::key_data before caching. Reject mismatch with a non-secret user-facing message.
3. Add a same-key/different-comment case; comments do not change cryptographic identity. Preserve existing missing-key behavior and reconnect's consistent opened pair.
4. Run all session::auth:: tests and whole suite at integration. Conventional exact-path commit. No live SSH, Keychain or vault operations.

Review focus: mismatches after decryption must be rejected; no private material or passphrase appears in errors; comparisons ignore comments but never key bytes/algorithms. V3 directory checks missing keys separately before engine connection.
