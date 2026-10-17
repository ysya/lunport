# Lunport 1.5.0 publication

- Release: https://github.com/ysya/lunport/releases/tag/v1.5.0
- Source: `68b11eb1f9b173edff04790a6abf563018dbf58d`
- Product PR: https://github.com/ysya/lunport/pull/38
- Release PR: https://github.com/ysya/lunport/pull/39
- Successful publish run: https://github.com/ysya/lunport/actions/runs/39079074789

The receipts in `publication/` record verification of all 20 downloaded assets,
SHA256 digests, nine updater payload signatures (including rejection of tampered
copies), 15 platform aliases, Stable/Beta manifests and both legacy SSHelter update
URLs. Historical releases and tags were compared with snapshots taken before
publication and remain unchanged.

The downloaded universal macOS app passed strict signature verification for Intel
and Apple Silicon with the existing pinned project certificate and hardened
runtime. Each native executable contains the exact frozen helper bytes. The
Folded L icon matches the source. This is project signing without Apple notarization.

This verification did not install or launch the app or access personal Keychain
secrets. Disposable CI fixtures verified denied/approved helper access and recovery;
the first real macOS approval dialog remains an installation check. On first use,
existing protected items may each require **Always Allow** for Lunport Credential
Helper. Subsequent ordinary app updates preserve the helper. Deliberate helper
updates or Keychain policy changes can require authorization again.

CI organization is being updated separately after this tag; it does not change
the published application or installers.
