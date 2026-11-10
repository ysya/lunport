import type { ReactElement } from "react";
import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { MigrationStatus } from "@/bindings/MigrationStatus";
import { buttonsIn, textIn } from "@/components/keychain/test-markup";
import { renderHook, stubBackend } from "@/lib/test-ipc";
import { usePermissionSheetStore } from "@/stores/permission-sheet";
import { answeredFor, CredentialPermissionSheet, PermissionSheetView, permissionReminder, permissionRequest, sheetShows } from "./CredentialPermissionSheet";

// A server render reads Zustand's initial snapshot; these cases exercise the sheet's current state.
vi.mock("@/stores/permission-sheet", async load => {
  const original = await load<typeof import("@/stores/permission-sheet")>();
  type State = ReturnType<typeof original.usePermissionSheetStore.getState>;
  return { ...original, usePermissionSheetStore: Object.assign(<T,>(selector: (state: State) => T) => selector(original.usePermissionSheetStore.getState()), original.usePermissionSheetStore) };
});
afterEach(() => {
  vi.unstubAllGlobals();
  usePermissionSheetStore.setState({ answered: null });
});

const status = (fields: Partial<MigrationStatus>): MigrationStatus => ({
  state: "completed",
  old_path: null,
  new_path: null,
  detail: null,
  failed_step: null,
  credentials_left: 0,
  credentials_need_permission: 0,
  credentials_retry_helps: false,
  credentials_permission_put_off: 0,
  ...fields,
});

describe("permissionRequest", () => {
  it("asks once for every saved item that waits for the user's permission, saying what to choose", () => {
    for (const state of ["completed", "credentials_pending"] as const) {
      const request = permissionRequest(status({ state, credentials_need_permission: 3 }));
      expect(request?.count).toBe(3);
      expect(request?.title).toBe("3 saved items need your permission once");
      expect(request?.description).toContain("Always Allow");
      expect(request?.description).toContain("Lunport Credential Helper");
      expect(request?.description).toContain("Nothing is deleted");
    }
    expect(permissionRequest(status({ credentials_need_permission: 1 }))?.title).toBe("1 saved item needs your permission once");
  });

  it("asks nothing when nothing waits, or before the app is open", () => {
    expect(permissionRequest(status({ credentials_need_permission: 0, credentials_left: 4 }))).toBeNull();
    for (const state of ["not_needed", "deferred", "conflict"] as const) {
      expect(permissionRequest(status({ state, credentials_need_permission: 2 }))).toBeNull();
    }
    expect(permissionRequest(undefined)).toBeNull();
  });
});

describe("sheetShows", () => {
  it("shows until the user answers, and again only when more wait than they answered for", () => {
    expect(sheetShows(2, null)).toBe(true);
    expect(sheetShows(0, null)).toBe(false);
    // Later, or Continue with some denied: not again in this window for as many or fewer.
    expect(sheetShows(2, 2)).toBe(false);
    expect(sheetShows(1, 2)).toBe(false);
    // More turned up since.
    expect(sheetShows(3, 2)).toBe(true);
  });
});

describe("PermissionSheetView", () => {
  const request = permissionRequest(status({ credentials_need_permission: 2 }))!;

  it("offers Continue, which lets macOS ask, and Later, which leaves them where they are", () => {
    const onContinue = vi.fn();
    const onLater = vi.fn();
    const sheet = PermissionSheetView({ request, busy: false, error: null, onContinue, onLater });
    expect(textIn(sheet)).toContain("2 saved items need your permission once");
    expect(textIn(sheet)).toContain("Lunport reminds you of them, and Allow… asks again when you are ready");
    const buttons = buttonsIn(sheet);
    expect(buttons.map(button => textIn(button.props.children))).toEqual(["Later", "Continue"]);
    buttons[1].props.onClick!();
    expect(onContinue).toHaveBeenCalledTimes(1);
    expect(onLater).not.toHaveBeenCalled();
    buttons[0].props.onClick!();
    expect(onLater).toHaveBeenCalledTimes(1);
    expect(buttons.every(button => !button.props.disabled)).toBe(true);
  });

  it("waits for macOS while it asks, and says why a run stopped", () => {
    const sheet = PermissionSheetView({ request, busy: true, error: "Lunport could not ask macOS about every saved item: no helper", onContinue: () => {}, onLater: () => {} });
    const buttons = buttonsIn(sheet);
    expect(buttons.map(button => textIn(button.props.children))).toEqual(["Later", "Waiting for macOS…"]);
    expect(buttons.every(button => button.props.disabled)).toBe(true);
    expect(textIn(sheet)).toContain("could not ask macOS about every saved item: no helper");
  });
});

type ViewProps = Parameters<typeof PermissionSheetView>[0];

/** What the sheet draws for `current`: its view, or nothing. */
function sheet(current: MigrationStatus, settle: (next: MigrationStatus) => void = () => {}) {
  return renderHook(new QueryClient(), () => CredentialPermissionSheet({ status: current, settle })) as ReactElement<ViewProps> | null;
}

describe("answeredFor", () => {
  it("counts the answer in this window first, then Later at an earlier start", () => {
    const putOff = status({ credentials_need_permission: 2, credentials_permission_put_off: 2 });
    expect(answeredFor(status({ credentials_need_permission: 2 }), null)).toBeNull();
    expect(answeredFor(putOff, null)).toBe(2);
    expect(answeredFor(putOff, 0)).toBe(0);
    expect(answeredFor(status({ credentials_need_permission: 2 }), 1)).toBe(1);
    expect(answeredFor(undefined, null)).toBeNull();
  });
});

describe("CredentialPermissionSheet", () => {
  it("puts the sheet away on Later, remembers it for later starts, and shows it again when asked to", () => {
    const calls = stubBackend(async () => undefined);
    const waiting = status({ credentials_need_permission: 2 });
    sheet(waiting)!.props.onLater();
    expect(usePermissionSheetStore.getState().answered).toBe(2);
    expect(calls.map(([cmd]) => cmd)).toEqual(["identity_migration_put_off_credentials"]);
    expect(sheet(waiting)).toBeNull();
    usePermissionSheetStore.getState().reopen();
    expect(sheet(waiting)?.props.request.count).toBe(2);
  });

  it("starts put away once the user chose Later at an earlier start, with the reminder's Allow… to bring it back", () => {
    const putOff = status({ credentials_need_permission: 2, credentials_permission_put_off: 2 });
    expect(sheet(putOff)).toBeNull();
    expect(permissionReminder(putOff, answeredFor(putOff, null))?.title).toBe("2 saved items still need your permission");
    // More wait than the user put off: the sheet asks for all of them.
    expect(sheet(status({ credentials_need_permission: 3, credentials_permission_put_off: 2 }))?.props.request.count).toBe(3);
    usePermissionSheetStore.getState().reopen();
    expect(sheet(putOff)?.props.request.count).toBe(2);
    expect(permissionReminder(putOff, answeredFor(putOff, usePermissionSheetStore.getState().answered))).toBeNull();
  });

  it("keeps Later in this window when the backend could not remember it", async () => {
    stubBackend(async () => {
      throw "Another Lunport is moving its data right now. Try again in a moment.";
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    sheet(status({ credentials_need_permission: 1 }))!.props.onLater();
    await vi.waitFor(() => expect(warn).toHaveBeenCalled());
    warn.mockRestore();
    expect(usePermissionSheetStore.getState().answered).toBe(1);
    expect(sheet(status({ credentials_need_permission: 1 }))).toBeNull();
  });

  it("lets helper v2 adopt them on Continue, takes the status it answers with, and does not ask again at once for what was denied", async () => {
    const next = status({ state: "credentials_pending", failed_step: "credentials", credentials_need_permission: 1 });
    const calls = stubBackend(async cmd => (cmd === "identity_migration_adopt_credentials" ? next : null));
    const settle = vi.fn();
    sheet(status({ credentials_need_permission: 2 }), settle)!.props.onContinue();
    await vi.waitFor(() => expect(settle).toHaveBeenCalledWith(next));
    expect(calls.map(([cmd]) => cmd)).toEqual(["identity_migration_adopt_credentials"]);
    expect(usePermissionSheetStore.getState().answered).toBe(1);
    expect(sheet(next)).toBeNull();
    // The notice's Allow… shows it again.
    usePermissionSheetStore.getState().reopen();
    expect(sheet(next)?.props.request.count).toBe(1);
  });

  it("stays up after a run that stopped part way, with what still waits", async () => {
    const now = status({ credentials_need_permission: 1 });
    const calls = stubBackend(async cmd => {
      if (cmd === "identity_migration_adopt_credentials") throw "Lunport could not ask macOS about every saved item: no helper";
      return now;
    });
    const settle = vi.fn();
    sheet(status({ credentials_need_permission: 2 }), settle)!.props.onContinue();
    await vi.waitFor(() => expect(settle).toHaveBeenCalledWith(now));
    expect(calls.map(([cmd]) => cmd)).toEqual(["identity_migration_adopt_credentials", "identity_migration_status"]);
    expect(usePermissionSheetStore.getState().answered).toBeNull();
    expect(sheet(now)?.props.request.count).toBe(1);
  });
});

describe("permissionReminder", () => {
  it("says, once the user answered, what still waits, that it stays where it was, and how to allow it", () => {
    const reminder = permissionReminder(status({ credentials_need_permission: 2 }), 2);
    expect(reminder?.title).toBe("2 saved items still need your permission");
    expect(reminder?.description).toContain("stay where they were");
    expect(reminder?.description).toContain("Allow…");
    expect(reminder?.description).toContain("Always Allow");
    expect(reminder?.description).toContain("Lunport reminds you each time it starts");
    expect(permissionReminder(status({ credentials_need_permission: 1 }), 1)?.title).toBe("1 saved item still needs your permission");
  });

  it("says nothing while the sheet shows, when nothing waits, or where the credentials notice offers Allow… itself", () => {
    expect(permissionReminder(status({ credentials_need_permission: 2 }), null)).toBeNull();
    expect(permissionReminder(status({ credentials_need_permission: 3 }), 2)).toBeNull();
    expect(permissionReminder(status({ credentials_need_permission: 0 }), 2)).toBeNull();
    expect(permissionReminder(status({ state: "credentials_pending", failed_step: "credentials", credentials_need_permission: 1 }), 1)).toBeNull();
  });
});
