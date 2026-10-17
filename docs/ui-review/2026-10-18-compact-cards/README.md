# Compact host cards preview

This preview supersedes the directory experiment in `../2026-10-18-host-directory/`. Cards expose a name and one address line. Port 22, usernames, tags, normal-state placeholders and persistent edit icons are omitted. Non-default ports remain visible; multiple accounts on the same address/port also show the username for disambiguation. Problems retain a short visible warning and an accessible full label. All cards keep the same height.

Select a card for the existing Host Details pane with username, port, authentication, tags, checks and Edit. Quick Connect appears on hover, selection or keyboard focus; it remains visible on touch devices and while connecting. Search still matches the hidden usernames and tags.

The preview uses the actual RecordHostList, LibraryNavigation and HostPreview components with 20 synthetic hosts. Backend actions are represented by fixture callbacks; no Production App, SSH connection, Keychain or saved user data is accessed.

- [Overview](overview-dark.jpg): 20 hosts in three columns at a 1240×800 viewport, with the sidebar expanded.
- [Selected host](selected-details.jpg): account and tags appear in the existing detail pane.
- [Narrow view](narrow-dark.jpg).
- [Measured results](responsive-metrics.json): 1240/860/540/360px with the sidebar collapsed, plus 19px text at 860/360px. Heights are uniform, with no horizontal page overflow or clipped/out-of-card warning text.
- Verified card selection and detail content, multi-select, tag search, Enter to connect, disabled missing-key connections, non-default ports, IPv6, duplicate-ID labels and account disambiguation.
- TypeScript, all 86 frontend files / 1,078 tests and the production Vite build pass. The duplicate-ID markup assertion now checks the short visible label and full accessible label. Native code, dependencies and saved-data formats are unchanged.

The floating extension buttons at the right edge of screenshots belong to the browser. This is a preview for feedback, with no merge or release.
