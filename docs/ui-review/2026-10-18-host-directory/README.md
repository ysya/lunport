# Host directory review

The host catalog now uses one aligned directory instead of independently sized cards. Name, address/port, username, status and actions have consistent positions. Rows stay the same height when a host has warnings or tags. The redundant Hosts/count heading and view switch are removed; Import hosts and New group are available in the header's More menu. The obsolete persisted grid/list preference is removed without changing saved hosts, groups, keys or sync formats.

The actual `RecordHostList` was rendered in a temporary Vite harness with 20 synthetic hosts. The fixture included long names/users, IPv6, multiple tags, missing keys, key conflicts, review states and duplicate IDs. No Production App data was read or changed.

- [Dark desktop preview](directory-dark.jpg), [narrow preview](directory-narrow.jpg), [light preview at 19px](directory-light-19px.jpg).
- [Measured responsive checks](responsive-metrics.json): 1240/860/540/360px, uniform row heights, no horizontal page overflow, no overlap with actions and no clipped status text. At 15px base font, rows measure 48.75px on desktop and 56.25px in narrow views.
- 19px font at 860px and 360px: uniform rows, no horizontal page overflow and no clipped warnings, including Conflicting host ID.
- Browser interactions: import menu via keyboard, host selection, edit, Enter to connect, IPv6 search, selection/clear/done and keyboard context-menu opening. Select visible selects 18 of 20 when two hosts share an ID; conflicting connections remain disabled. While connecting, the busy spinner is present and every Connect button is disabled.
- TypeScript, all 86 frontend files / 1,078 tests and the production Vite build pass. No dependencies or native sources change. The existing large-chunk build advisory remains.

Screenshots show the actual component with fixture data rather than a drawn mockup. The browser's floating extension controls at the right edge are outside the app. This review does not claim native WebKit or a new published Beta verification.
