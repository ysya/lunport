# Portable publication receipt tools

These are read-only release verification helpers for remote continuation. They do not dispatch workflows, create tags, update releases or install an app.

- `fetch-publication.py ROOT TAG EXPECTED_SHA` requires a fresh `ROOT/stable-before.json` captured before publication, then uses authenticated `gh` to fetch public release/tag/Stable/channel metadata, both manifests and uploaded `.sig` files. It invokes the sibling validator with portable repository-relative paths.
- `verify-publication.mjs ROOT TAG EXPECTED_SHA` reuses the repository's canonical Beta manifest functions. It validates expected source/tag, prerelease flags, all assets' uploaded/nonempty state, required platform families, exact Release/channel manifest content, downloaded signature-file coherence and unchanged Stable ID/tag.

Observed 2026-10-15: Python AST parsing and `node --check` succeeded. A read-only live smoke run on **existing v1.0.0-2** at `07e669a7682b4550d006e9e3ee6e1523502be424` succeeded: 20 uploaded nonempty assets, 15 platform aliases, matching manifests/signature files, unchanged Stable `v0.16.0` / ID `400974628`. Changing one downloaded local signature to an invalid value produced the expected assertion failure (`signature file differs from manifest`); restoring the exact bytes succeeded again. No remote data was changed.

This smoke run validates the tools; it does not mean Beta 3 has been published. Signature-file coherence is not independent cryptographic validation of every installer. Remote continuation must collect a new pre-publication baseline and run the tools against the actual Beta 3 release after all installer jobs complete.
