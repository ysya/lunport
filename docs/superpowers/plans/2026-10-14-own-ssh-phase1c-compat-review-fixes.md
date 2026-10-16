# Legacy compatibility review fix pass

Standing authorization: autonomous implementation after immutable review. Scope findings 2, 4 and coordinated finding 5 callers. No repeated review, real credentials, network, app launch, push or merge.

1. RED: publish authenticated account schema 3 while each local material command waits on the vault mutex; assert unchanged vault bytes, key files, public files, remembered passphrases and all state except the observed gate/error. RED: escaping state path refuses start_rotation before any Keychain or relay call. RED: retirement destination denial precedes vault replacement/passphrase deletion.
2. GREEN: explicit MaterialTransaction holds vault -> format publication mutex; checks newest core before opening vault/Keychain/materials; keeps both through files and state commit. Only observer takes publication -> core. No doc/core held when acquiring transaction, no publication -> vault path. Nested helpers receive the transaction token and open Vault directly under its held mutex. Latest mutate also rejects read-only format. Events/agent refresh after releasing transaction.
3. Coordinate local key add/import/restore, key setup/reuse/adopt and background slot maintenance with the same transaction token. Preserve state save failure and file fallback contracts. All account-format publication paths must respect the boundary.
4. Start rotation calls saves_allowed at entry. Plan OwnKey retirement before replacing vault material and execute the selected plan afterward.
5. Focused Rust regressions only, exact owned files conventional commit using shared index flock; root runs latest integrated suite. Record evidence, rulings and remaining limitations.

Ruling: a transaction linearizes at its latest-format check after acquiring vault and publication locks. An already-started transaction completes before an observer publishes a newer gate. A command waiting for vault cannot block observation; once the gate is published it refuses before any materials. This is client-local serialization, not a relay atomic migration guarantee.
