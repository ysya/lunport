# Task 2 actual-component verification

Source checked: f071333 Group UI, followed by a3ce927 fix. Local Vite10496/session22049, browser4/tab3. ui-review.html supplies public in-memory fixtures and a mock native bridge; every mutation stays inside the fixture. No native/remote operation or real data/policy upgrade occurred.

- 800x560 light / 1100x720 dark HostEditor: effective port2222/userops/key and Operations key shown with per-field inheritance/source; identifying fields visible; DOM root dimensions correct, no document horizontal overflow. Screenshots in durable visualization directory: sshelter-groups-host-min-light.jpg, sshelter-groups-host-normal-dark.jpg.
- 1100x720 light GroupEditor: scope, parent/defaults and 1 descendant/17 hosts consequence displayed; sshelter-groups-editor-normal-light.jpg. Minimum Group editor also visually inspected.
- Group draft Production draft persisted through Keys→Hosts; host replacement dialog focused Keep editing.
- Clearing inherited Port restored raw22; Connect disabled while unsaved.
- Collapse Production then search web-01 revealed Production/Web services ancestors and matching host. Clearing search retained original expansion state.
- Native scroll moved only tree: top Search/New host/New group stayed fixed, main Group form stayed at its current position.
- a3ce927 mounted deletion race: opening Delete Group subtree? captured revision9007199254740993; fixture's out-of-band overview refresh changed Group name and revision9007199254740994. Confirm delete sent the original revision9007199254740993. Mock native CAS rejected it; real component displayed Fixture CAS conflict, retained candidate and did not report deletion success. Dialog still displayed original 1 descendant/17 host counts.
- a3ce927 mounted broken-host repair: original missing Group showed Unavailable preview. Choosing valid Production group showed its Source and effective user control, removed draft unavailable notice, left saved Needs review/Connect disabled. Detach to Ungrouped showed OS username placeholder and Source: App default, Connect remained disabled until persistence.
- Native select theme baseline: root and all observed selects computed normal in both app modes, while foreground changed. After CSS fix, root/all four Group-editor selects computed dark in app Dark; root/select computed light in app Light. IAB AX verified native popup expands/collapses, but the native popup overlay is omitted from tab screenshots. This is not actual Windows popup visual verification; final receipt must state that limit.

Screenshots are visual fixture checks and do not replace final native CI or execution verification.
