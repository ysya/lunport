# Stable 1.0.0 publication receipts

The release source is `be39161f970a0c93dac1eb71fd6d89c6f678e72b`. Its full tree matches the tested candidate `574101545432201fe4be309ff4464d0d9d0a7c1d`. The tag and binaries remain fixed; later changes only record validation in documentation. Receipt timestamps are UTC; the publication date is 2026-10-17 in Asia/Taipei.

| Evidence | Receipts |
| --- | --- |
| Tested source and one release PR merge | [candidate source](candidate-source.json), [preflight](release-preflight.json), [merge](release-pr-merge.json), [tree equality](source-verification.json) |
| Final successful candidate gates | [engine/frontend/macOS/Linux](engine-ci.json), [Windows](windows-ci.json), [NSIS/MSI](windows-bundle-ci.json) |
| Test worker teardown correction | [30-process proof](native-worker-fix-verification.json), [successful run](native-worker-fix-ci.json), [results](native-worker-fix-results.txt) |
| Official publication | [trigger](dispatch.json), [six successful jobs](publish-ci.json), [curated notes](release-notes.md), [release](release.json), [tag](tag-ref.json) |
| Stable and Beta channels | [verification](verification.json), [Stable manifest](release/latest.json), [Beta manifest](channel/latest.json), [latest Stable](stable-after.json), [Beta release](channel-release.json) |
| Previous Stable assets preserved | [before](stable-before.json), [after](previous-stable-after.json) |
| Nine complete updater packages | [SHA-256, signatures and tampered-copy rejection](cryptographic-verification.json), uploaded `.sig` files in `signatures/` |
| Downloaded macOS package | [universal executable and non-GUI health check](macos-package-check.json) |

## Historical failures and earlier checks

These records are retained for traceability and are not the final candidate's CI result:

- `candidate-source-initial.json`, `windows-ci-initial-failure.json` and `windows-native-initial-failure.txt`: initial versioned candidate's native test failure.
- `native-diagnostic-initial-*`, `windows-native-repeat-failure-ci.json` and `windows-native-repeat-failure.txt`: native heap fault after the old test's event loop returned. The final test joins controller/watchdog workers before cleanup; the 30-process proof and final 10-process gate passed. This is evidence for a test harness fix, not a claim that all customer crashes share this cause.
- `main-engine-ci.json`, `main-windows-ci.json`, `windows-bundle-ci-initial.json` and the bundle/diagnostic dispatch records: integration or earlier-source checks. The final candidate gates above are authoritative.

Windows/Linux manual visual acceptance remains pending. Windows GUI startup CI uses a placeholder frontend. macOS UI validation uses the Development profile; the downloaded Production package was not installed or opened as a GUI. Full details are in [the validation record](../../1.0.0-validation.md).
