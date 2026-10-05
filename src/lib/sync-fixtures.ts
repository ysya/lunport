import type { SyncDeviceView } from "@/bindings/SyncDeviceView";
import type { SyncOverview } from "@/bindings/SyncOverview";
import type { SyncSpaceView } from "@/bindings/SyncSpaceView";

/*
 * Test builders for the sync bindings: a joined, healthy, up-to-date state that
 * each test bends with overrides. Only `*.test.ts` files import this module.
 */

export const NOW = Date.UTC(2026, 9, 2, 12, 0, 0);
export const MINUTE = 60_000;

/**
 * A name another computer could send (the backend refuses control characters in a space's name, not format
 * characters): a right-to-left override and a zero-width space inside it. `revealHidden` shows them as
 * `⟨U+202E⟩` and `⟨U+200B⟩`; written as escapes so no invisible character is in this file.
 */
export const SPOOFED_NAME = "Lab\u202Eevil\u200B";
export const SPOOFED_NAME_SHOWN = "Lab⟨U+202E⟩evil⟨U+200B⟩";

export function space(overrides: Partial<SyncSpaceView> = {}): SyncSpaceView {
  const id = overrides.id ?? "3fa2c1d9".padEnd(64, "0");
  return {
    id,
    name: "Personal",
    selected: true,
    file_name: `personal-${id.slice(0, 8)}.config`,
    file_path: `/home/f/.ssh/sshelter/personal-${id.slice(0, 8)}.config`,
    hosts: 3,
    pending_uploads: 0,
    approvals: 0,
    first_sync_pending: false,
    missing: false,
    last_error: null,
    created_at_ms: NOW - 86_400_000,
    synced_on: ["MacBook-A"],
    ...overrides,
  };
}

export function device(overrides: Partial<SyncDeviceView> = {}): SyncDeviceView {
  return {
    id: "device-a",
    name: "MacBook-A",
    platform: "macos",
    joined_at_ms: NOW - 86_400_000,
    last_seen_ms: NOW - 5 * MINUTE,
    is_this: true,
    spaces: [],
    ...overrides,
  };
}

export function overview(overrides: Partial<SyncOverview> = {}): SyncOverview {
  return {
    joined: true,
    account_short: "8b01e4aa",
    device_id: "device-a",
    device_name: "MacBook-A",
    relay_url: "https://relay.example.com",
    relay: { url: "https://relay.example.com", version: "0.2.0", batch_pull: true, freeze: true },
    last_sync_ms: NOW - 2 * MINUTE,
    last_error: null,
    read_only: false,
    upgrading: false,
    frozen: null,
    rotation: null,
    devices: [device()],
    spaces: [space()],
    pending_uploads: 0,
    approvals_waiting: 0,
    stray_files: [],
    key_slots: [],
    notices: [],
    phrase_cleanup_pending: false,
    ...overrides,
  };
}
