# Workspace layout corrections

The user reported narrow dropdowns, a narrow fixed Connection details panel, and inconsistent colors. Extend the pending Beta 9 fixes before publication; keep the host actions and sync correctness changes already committed in `41d730b`.

Use the existing React/Radix/Zustand stack with no new dependencies. Implement inline under the user's standing delegation to make routine design decisions. The user confirmed neutral gray surfaces with restrained blue emphasis, reducing the existing mixed blue-gray tones.

- Command menus size to their contents rather than the trigger button. All popup menus stay within the viewport; long labels wrap and icons/checkmarks remain visible. Selection controls retain field-width alignment.
- Connection details defaults to 400 CSS px, supports a 320–640 px preference, and caps the rendered width to preserve 320 px of the list. Store the preferred width separately from a temporarily smaller rendered width.
- The separator is operable with pointer capture and keyboard arrows, Home/End and double-click reset. Left moves the divider left and grows the right pane. Cancellation/unmount clears drag state. The saved preference survives restart and host changes.
- At the existing compact breakpoint (820 px), details occupies the available content area and the separator is hidden. The native minimum window remains 800×560.
- Use common theme tokens for navigation, workspace, cards, menus, dialogs and inspector. Remove Library-only hardcoded blue-gray surfaces. Verify ordinary text/primary-button contrast against a 4.5:1 target in both themes; this is a targeted check, not a claim of whole-app WCAG certification.
- Audit the complete Records workspace with long hostnames, Group names and terminal names at 800×560, 1100×720 and a wide desktop size. Verify both themes, menus, editor dialogs, overflow, panel resizing and the existing dirty-draft guard.
- Do not use real hosts, codes, vaults, keys or native update installation for visual fixtures. Do not change relay, sync format, credentials or security gates.

References: [Radix menu sizing](https://www.radix-ui.com/primitives/docs/components/dropdown-menu), [WAI splitter interaction](https://www.w3.org/WAI/ARIA/apg/patterns/windowsplitter/), [WCAG contrast minimum](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html).
