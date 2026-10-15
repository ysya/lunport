# Workspace Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Fix popup sizing, add an adjustable Connection details pane, and unify the visual hierarchy before publishing Beta 9.

**Architecture:** Keep shared popup sizing in the existing Radix wrappers. Give the inspector a small width-policy module and a resize handle; persist its preferred width in the existing UI store. Derive Library colors from the global theme tokens.

**Tech Stack:** React 19, TypeScript, Radix UI, Zustand, CSS, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-16-workspace-layout.md`

## Global Constraints

- No new dependencies; preserve the existing host actions, saved-ID guards and sync gates.
- Details: default 400 px, preferred range 320–640 px, reserve 320 px for the list.
- At 820 px and below, retain the compact details view and hide its separator.
- Validate the native 800×560 minimum and 1100×720 default; use fake data only.
- Implement inline under the user's existing delegation; publish only after the revised source passes verification.

## Review Focus

- A short icon trigger with long commands must not squeeze menu labels; verify real DOM bounds before/after the shared fix.
- A long option must stay inside the viewport with a readable value/checkmark; inspect selection controls in the complete workspace.
- Shrinking then enlarging the window must restore the preferred panel width; test the policy and actual pane.
- Pointer cancellation, lost capture and unmount must not leave selection disabled or the resize cursor active; exercise the mounted handle.
- Persisted invalid widths and keyboard directions must be safe; test hydration, bounds and left/right behavior.

### Task 1: Shared popup sizing

**Files:** Modify `src/components/ui/dropdown-menu.tsx`, `src/components/ui/context-menu.tsx`, `src/components/ui/select.tsx` and shared CSS as necessary.

**Interfaces:** Existing component props and actions remain unchanged. Dropdowns use intrinsic width with a viewport cap; Select remains at least trigger width.

- [x] Reproduce the small-trigger bug in the complete fake Records workspace. Record trigger/content bounds and long-label wrapping.
- [x] Replace trigger-bound command-menu width with intrinsic sizing. The intended rule is `width: max-content; min-width: 12rem; max-width: min(24rem, var(--radix-dropdown-menu-content-available-width));` and equivalent bounds for submenus/context menus. Preserve explicit caller widths.
- [x] Bound Select content and its value text without replacing native Records selects or changing values. Check keyboard selection, collision handling and long labels in both themes.
- [x] Run `npm run build`; verify mounted menus at the three target sizes before committing this task with the related layout changes.

### Task 2: Adjustable details pane

**Files:** Create `src/lib/host-preview-width.ts`, `src/lib/host-preview-width.test.ts`, `src/components/records/HostPreviewResizeHandle.tsx`; modify `HostPreview.tsx`, `library.css`, `src/stores/ui.ts`.

**Interfaces:** Export `DEFAULT_HOST_PREVIEW_WIDTH`, `MIN_HOST_PREVIEW_WIDTH`, `MAX_HOST_PREVIEW_WIDTH`, `clampHostPreviewWidth(value: unknown)`, `hostPreviewLimit(available: number)`, `hostPreviewWidthAfterDrag(start: number, delta: number, limit: number)`, and `hostPreviewWidthAfterKey(width: number, key: string, limit: number)`. The UI store gains `hostPreviewWidth` / `setHostPreviewWidth`.

- [ ] Add and run failing policy/store tests. Examples: `hostPreviewWidthAfterDrag(400, -80, 640) === 480`; `hostPreviewWidthAfterKey(400, 'ArrowRight', 640) === 384`; `hostPreviewLimit(800) === 480`. Assert invalid inputs, limits, persistence, old envelopes and preservation of the requested width across viewport caps.
- [ ] Implement the pure policy, store setter and partial persistence. Clamp at render as well as setter so old/untrusted persisted values are safe.
- [ ] Observe the actual parent content width. Size the aside from the saved preference and current limit; remove the old 20rem/18rem fixed overrides.
- [ ] Add an accessible left-edge separator controlling the aside. Use pointer capture, reverse drag direction for the right pane, commit on release, restore on cancel, clean up lost capture/unmount, and implement arrow/Home/End/reset behavior.
- [ ] Verify the tests pass and exercise actual drag, keyboard, cancellation, host switching, reopening and viewport changes. Confirm no navigation or draft state is changed by resizing.

### Task 3: Shared colors and final acceptance

**Files:** Modify `src/index.css`, `src/components/records/library.css`, and `docs/releases/1.0.0-9-validation.md`.

**Interfaces:** Existing semantic CSS variables remain stable. Library derives its canvas/nav/line/dim tokens from global background/sidebar/border/muted-foreground values.

- [ ] Apply the chosen neutral palette. Start with light primary `#2563eb` / white text and dark primary `#82b1ff` / `#10213d` text; use neutral surfaces and semantic error colors. Calculate contrast before accepting the values.
- [ ] Check complete workspace, menus, selection controls, details, host/group editors and settings in both themes. Confirm long names and lower status bars do not cause horizontal overflow or unreadable text.
- [ ] Run the full frontend suite and build. Obtain one scoped independent review of this new patch and resolve its actionable findings.
- [ ] Commit and push the revised source, run required cross-platform CI, then publish an unused Beta version from that exact source. Verify all installer jobs, tag, Beta manifest/signature-file coherence and the fresh Stable baseline. Update the inspection checklist with results and remaining device-only acceptance.
