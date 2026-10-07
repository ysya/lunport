import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import type { SyncNotice } from "@/bindings/SyncNotice";
import { syncApprovalsKey, syncOverviewKey } from "@/lib/sync";
import { useUiStore } from "@/stores/ui";
import { SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "./sync-fixtures";
import { conflictMessage, noticeMessage, subscribeSyncEvents, upgradeExplanation, upgradeNotice } from "./sync-events";

describe("conflictMessage", () => {
  it("names the hosts and their space", () => {
    expect(conflictMessage([{ space_id: "a", space_name: "Work", aliases: ["web"] }])).toEqual({
      title: "Sync replaced a local change",
      description: "web in Work was edited on another computer more recently.",
    });
  });

  it("lists every space and counts every host", () => {
    expect(
      conflictMessage([
        { space_id: "a", space_name: "Work", aliases: ["web", "db"] },
        { space_id: "b", space_name: "Personal", aliases: ["nas"] },
      ]),
    ).toEqual({
      title: "Sync replaced local changes",
      description: "web and db in Work; nas in Personal were edited on another computer more recently.",
    });
  });

  it("says nothing when no host is named", () => {
    expect(conflictMessage([])).toBeNull();
    expect(conflictMessage([{ space_id: "a", space_name: "Work", aliases: [] }])).toBeNull();
  });

  it("shows the hidden characters in a space's name, which another computer chose, instead of drawing them", () => {
    const message = conflictMessage([{ space_id: "a", space_name: SPOOFED_NAME, aliases: ["web"] }]);
    expect(message?.description).toBe(`web in ${SPOOFED_NAME_SHOWN} was edited on another computer more recently.`);
    expect(JSON.stringify(message)).not.toMatch(/[\u202E\u200B]/);
  });
});

describe("notices", () => {
  const upgraded: SyncNotice = { kind: "upgraded", kept_file: null, kept_hosts: [], moved_files: [] };
  const kept: SyncNotice = { kind: "upgraded", kept_file: "/home/f/.ssh/sshelter-v1-kept.config", kept_hosts: ["jump", "lab"], moved_files: [] };

  it("explain the v1 upgrade once, with the hosts that stayed local and the user's own files that moved", () => {
    expect(upgradeExplanation(upgraded)).toEqual([
      "Your synced hosts moved into a space named “Synced”, unless another computer had already renamed or deleted it. Rename it or add more spaces in Settings → Sync; each computer chooses which spaces it syncs.",
      "Update SSHelter on your other computers too. Until they are updated, they don't see changes made here.",
    ]);
    expect(upgradeExplanation(kept)[2]).toBe(
      "jump and lab could not move into a space, so they stay on this computer in /home/f/.ssh/sshelter-v1-kept.config, where ssh keeps reading them.",
    );
    expect(upgradeExplanation({ ...kept, kept_hosts: ["jump"] })[2]).toBe(
      "jump could not move into a space, so it stays on this computer in /home/f/.ssh/sshelter-v1-kept.config, where ssh keeps reading it.",
    );
    const mine = "/home/f/.ssh/sshelter-local/mine.config";
    expect(upgradeExplanation({ ...upgraded, moved_files: [mine] })[2]).toBe(
      "Your own config file in ~/.ssh/sshelter moved to /home/f/.ssh/sshelter-local/mine.config, where ssh keeps reading it.",
    );
    expect(upgradeExplanation({ ...kept, moved_files: [mine, "/home/f/.ssh/sshelter-local/lab.config"] }).slice(2)).toEqual([
      "jump and lab could not move into a space, so they stay on this computer in /home/f/.ssh/sshelter-v1-kept.config, where ssh keeps reading them.",
      "Your own config files in ~/.ssh/sshelter moved to /home/f/.ssh/sshelter-local/mine.config and /home/f/.ssh/sshelter-local/lab.config, where ssh keeps reading them.",
    ]);
  });

  it("finds the upgrade notice and its index", () => {
    const deleted: SyncNotice = { kind: "space_deleted", name: "Work", by_device: "MacBook-A" };
    expect(upgradeNotice([deleted, kept])).toEqual({ index: 1, notice: kept });
    expect(upgradeNotice([deleted])).toBeNull();
  });

  it("have a title and a description for every kind", () => {
    expect(noticeMessage(upgraded).title).toBe("Sync was upgraded");
    expect(noticeMessage({ kind: "space_deleted", name: "Work", by_device: "MacBook-A" })).toEqual({
      title: "“Work” was deleted on MacBook-A",
      description: "Its file was backed up and removed from this computer.",
    });
    expect(noticeMessage({ kind: "rename_blocked", space_id: "a", name: "Work", file_name: "work-3fa2c1d9.config" })).toEqual({
      title: "The file of “Work” keeps its old name",
      description:
        "work-3fa2c1d9.config already exists in ~/.ssh/sshelter, so SSHelter did not overwrite it. Move that file away; SSHelter renames the space's file on the next sync.",
    });
    expect(noticeMessage({ kind: "left_account", kept_files: ["/home/f/.ssh/sshelter-local/personal-3fa2c1d9.config"] })).toEqual({
      title: "Your synced files are now local files",
      description:
        "ssh keeps reading /home/f/.ssh/sshelter-local/personal-3fa2c1d9.config, but it no longer syncs. To sync these hosts again, use “Move hosts into a space” in a sync account.",
    });
    expect(noticeMessage({ kind: "left_account", kept_files: ["/x/a.config", "/x/b-2.config"] }).description).toBe(
      "ssh keeps reading /x/a.config and /x/b-2.config, but they no longer sync. To sync these hosts again, use “Move hosts into a space” in a sync account.",
    );
    expect(noticeMessage({ kind: "new_sync_code" })).toEqual({
      title: "The sync code was changed",
      description: "Show the new sync code, save it, and enter it on each of your other computers.",
    });
    expect(noticeMessage({ kind: "other_rotation", devices: ["MacBook-B"] })).toEqual({
      title: "MacBook-B also changed the sync code",
      description:
        "Use one of the new sync codes on every computer. To use the other one on this computer, leave the sync account and join with it.",
    });
    expect(noticeMessage({ kind: "keys_needed", names: ["id_mac", "work"] })).toEqual({
      title: "Pick keys for this computer",
      description: "Synced hosts use id_mac and work, which stay on your other computers.",
    });
    // 名稱來自別台電腦:看不見的字元要顯示出來。
    expect(noticeMessage({ kind: "keys_needed", names: [SPOOFED_NAME] }).description).toContain(SPOOFED_NAME_SHOWN);
  });
});

describe("notices that name a space or a computer another computer chose the name of", () => {
  const hidden = /[\u202E\u200B]/;

  it("show the hidden characters of a space's name, in the toast and in the row", () => {
    const deleted = noticeMessage({ kind: "space_deleted", name: SPOOFED_NAME, by_device: "MacBook-A" });
    expect(deleted.title).toBe(`“${SPOOFED_NAME_SHOWN}” was deleted on MacBook-A`);
    const blocked = noticeMessage({ kind: "rename_blocked", space_id: "a", name: SPOOFED_NAME, file_name: "lab-3fa2c1d9.config" });
    expect(blocked.title).toBe(`The file of “${SPOOFED_NAME_SHOWN}” keeps its old name`);
    for (const message of [deleted, blocked]) expect(JSON.stringify(message)).not.toMatch(hidden);
  });

  it("show the hidden characters of the computers' names in the same sentences", () => {
    expect(noticeMessage({ kind: "space_deleted", name: "Work", by_device: SPOOFED_NAME }).title).toBe(`“Work” was deleted on ${SPOOFED_NAME_SHOWN}`);
    expect(noticeMessage({ kind: "other_rotation", devices: [SPOOFED_NAME, "MacBook-C"] }).title).toBe(
      `${SPOOFED_NAME_SHOWN} and MacBook-C also changed the sync code`,
    );
  });
});

/**
 * A fake Tauri event bus: `listen()` registers its handler through `transformCallback` and the
 * `plugin:event|listen` command, so both are captured here and `emit` calls the handler the way
 * the webview would. Any other command is recorded — the events must never start a sync round.
 * `failListen` makes the backend refuse to register a listener; `failUnlisten` makes releasing one fail.
 */
function stubEventBus({ failListen = false, failUnlisten = false }: { failListen?: boolean; failUnlisten?: boolean } = {}) {
  const callbacks = new Map<number, (event: unknown) => void>();
  const handlers = new Map<string, (event: unknown) => void>();
  const commands: string[] = [];
  let nextId = 1;
  vi.stubGlobal("window", {
    __TAURI_INTERNALS__: {
      transformCallback: (callback: (event: unknown) => void) => {
        const id = nextId++;
        callbacks.set(id, callback);
        return id;
      },
      invoke: async (cmd: string, args: { event?: string; handler?: number }) => {
        commands.push(cmd);
        if (cmd === "plugin:event|listen" && args.event && args.handler) {
          if (failListen) throw new Error("the event plugin refused the listener");
          handlers.set(args.event, callbacks.get(args.handler)!);
          return nextId++;
        }
        return undefined;
      },
    },
    __TAURI_EVENT_PLUGIN_INTERNALS__: {
      unregisterListener: () => {
        if (failUnlisten) throw new Error("the listener is already gone");
      },
    },
  });
  const emit = (event: string, payload: unknown) => {
    const handler = handlers.get(event);
    if (!handler) throw new Error(`nobody listens to ${event}`);
    handler({ event, id: 0, payload });
  };
  return { emit, handlers, commands };
}

/** The unhandled rejections Node reports while `action` runs and during the next macrotask. */
async function unhandledRejectionsDuring(action: () => void | Promise<void>): Promise<unknown[]> {
  const seen: unknown[] = [];
  const onRejection = (reason: unknown) => void seen.push(reason);
  process.on("unhandledRejection", onRejection);
  try {
    await action();
    await new Promise((resolve) => setTimeout(resolve, 0));
  } finally {
    process.off("unhandledRejection", onRejection);
  }
  return seen;
}

describe("subscribeSyncEvents", () => {
  beforeEach(() => {
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
      cb(0);
      return 0;
    });
  });

  afterEach(() => {
    for (const t of toast.getToasts()) toast.dismiss(t.id);
    vi.unstubAllGlobals();
    useUiStore.setState({ settingsOpen: false, settingsCategory: "general", syncApprovalsOpen: false });
  });

  async function subscribed() {
    const bus = stubEventBus();
    const queryClient = new QueryClient();
    const stop = subscribeSyncEvents(queryClient);
    await vi.waitFor(() => expect(bus.handlers.size).toBe(6));
    return { ...bus, queryClient, stop };
  }

  it("listens to the engine's events and never asks for a sync round itself", async () => {
    const { handlers, commands, emit, stop } = await subscribed();
    expect([...handlers.keys()].sort()).toEqual([
      "agent://connect-expired",
      "sync://applied",
      "sync://approval",
      "sync://conflict",
      "sync://notice",
      "sync://status",
    ]);
    // Every handler runs once: only the "Sync now" button may start a round.
    emit("sync://status", { joined: true, device_name: "MacBook-A" });
    emit("sync://applied", 1);
    emit("sync://approval", [{ space_id: "a", space_name: "Work", aliases: ["web"] }]);
    emit("sync://conflict", [{ space_id: "a", space_name: "Work", aliases: ["web"] }]);
    emit("sync://notice", { kind: "space_deleted", name: "Work", by_device: "MacBook-A" });
    emit("agent://connect-expired", "web");
    stop();
    expect(commands.filter((c) => c.startsWith("sync_"))).toEqual([]);
  });

  it("puts each status push into the overview cache", async () => {
    const { emit, queryClient } = await subscribed();
    emit("sync://status", { joined: true, device_name: "MacBook-A" });
    expect(queryClient.getQueryData(syncOverviewKey)).toEqual({ joined: true, device_name: "MacBook-A" });
  });

  it("refreshes the config views and the approval list when the engine wrote files", async () => {
    const { emit, queryClient } = await subscribed();
    queryClient.setQueryData(["config", "hosts"], { files: [], hosts: [] });
    queryClient.setQueryData(syncApprovalsKey, []);
    emit("sync://applied", 2);
    expect(queryClient.getQueryState(["config", "hosts"])?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(syncApprovalsKey)?.isInvalidated).toBe(true);
  });

  it("toasts conflicts with their space", async () => {
    const { emit } = await subscribed();
    emit("sync://conflict", [{ space_id: "a", space_name: "Work", aliases: ["web"] }]);
    expect(toast.getToasts()).toEqual([
      expect.objectContaining({ title: "Sync replaced a local change", description: "web in Work was edited on another computer more recently." }),
    ]);
  });

  it("announces hosts waiting for approval with a button that opens the review", async () => {
    const { emit, queryClient } = await subscribed();
    queryClient.setQueryData(syncApprovalsKey, []);
    emit("sync://approval", [{ space_id: "a", space_name: "Work", aliases: ["web", "db"] }]);
    expect(queryClient.getQueryState(syncApprovalsKey)?.isInvalidated).toBe(true);
    const [shown] = toast.getToasts();
    expect(shown).toEqual(expect.objectContaining({ title: "2 synced hosts need your approval" }));
    const action = "action" in shown ? shown.action : undefined;
    if (!action || typeof action !== "object" || !("onClick" in action)) throw new Error("the toast has no button");
    action.onClick(undefined as never);
    expect(useUiStore.getState().syncApprovalsOpen).toBe(true);
  });

  it("toasts notices with a way to Settings → Sync, except the upgrade (it has its own dialog)", async () => {
    const { emit } = await subscribed();
    emit("sync://notice", { kind: "upgraded", kept_file: null, kept_hosts: [], moved_files: [] });
    expect(toast.getToasts()).toEqual([]);
    emit("sync://notice", { kind: "space_deleted", name: "Work", by_device: "MacBook-A" });
    const [shown] = toast.getToasts();
    expect(shown).toEqual(expect.objectContaining({ title: "“Work” was deleted on MacBook-A" }));
    const action = "action" in shown ? shown.action : undefined;
    if (!action || typeof action !== "object" || !("onClick" in action)) throw new Error("the notice has no button");
    action.onClick(undefined as never);
    expect(useUiStore.getState()).toEqual(expect.objectContaining({ settingsOpen: true, settingsCategory: "sync" }));
  });

  it("toasts a key channel that closed before ssh asked for the key, naming the host", async () => {
    const { emit } = await subscribed();
    emit("agent://connect-expired", "web");
    expect(toast.getToasts()).toEqual([
      expect.objectContaining({
        type: "warning",
        title: "Connect to web again",
        description:
          "ssh didn't ask SSHelter for the key within a minute (a new host's fingerprint question may still be open), so SSHelter stopped offering it.",
      }),
    ]);
  });

  it("shows the hidden characters of the host's name in that toast", async () => {
    const { emit } = await subscribed();
    emit("agent://connect-expired", SPOOFED_NAME);
    const [shown] = toast.getToasts();
    expect(shown).toEqual(expect.objectContaining({ title: `Connect to ${SPOOFED_NAME_SHOWN} again` }));
    expect(JSON.stringify(shown)).not.toMatch(/[\u202E\u200B]/);
  });

  it("leaves the keys notice to its dialog", async () => {
    const { emit } = await subscribed();
    emit("sync://notice", { kind: "keys_needed", names: ["id_mac"] });
    expect(toast.getToasts()).toEqual([]);
  });

  it("ignores events that reach a subscription after it was dropped, and still releases its listeners", async () => {
    const bus = stubEventBus();
    const queryClient = new QueryClient();
    queryClient.setQueryData(["config", "hosts"], { files: [], hosts: [] });
    queryClient.setQueryData(syncApprovalsKey, []);
    // StrictMode mounts, unmounts and mounts again: the dropped subscription's callbacks are registered
    // with the webview before listen() resolves, so events can arrive while no unlisten is known yet.
    const stop = subscribeSyncEvents(queryClient);
    stop();
    const registered = bus.handlers.size; // listen() registers its callback synchronously
    bus.emit("sync://status", { joined: true, device_name: "MacBook-A" });
    bus.emit("sync://applied", 2);
    bus.emit("sync://conflict", [{ space_id: "a", space_name: "Work", aliases: ["web"] }]);
    bus.emit("sync://notice", { kind: "space_deleted", name: "Work", by_device: "MacBook-A" });
    bus.emit("agent://connect-expired", "web");
    expect(queryClient.getQueryData(syncOverviewKey)).toBeUndefined();
    expect(queryClient.getQueryState(["config", "hosts"])?.isInvalidated).toBe(false);
    expect(queryClient.getQueryState(syncApprovalsKey)?.isInvalidated).toBe(false);
    expect(toast.getToasts()).toEqual([]);
    // Once listen() resolves, each late registration is released at once.
    await vi.waitFor(() => expect(bus.commands.filter((c) => c === "plugin:event|unlisten")).toHaveLength(registered));
  });

  it("releases every listener it registered when it is dropped (one unlisten per handler, counted from the handlers)", async () => {
    const { handlers, commands, stop } = await subscribed();
    // Every listen() has answered by now, so each unlisten function is known: this is the normal path, not the late one.
    await new Promise((resolve) => setTimeout(resolve, 0));
    const released = () => commands.filter((c) => c === "plugin:event|unlisten");
    expect(handlers.size).toBeGreaterThan(0);
    expect(released()).toEqual([]); // nothing is released while the subscription lives
    stop();
    await vi.waitFor(() => expect(released()).toHaveLength(handlers.size));
  });

  it("stays quiet when the backend refuses to register the listeners", async () => {
    stubEventBus({ failListen: true });
    const rejections = await unhandledRejectionsDuring(() => {
      subscribeSyncEvents(new QueryClient());
    });
    expect(rejections).toEqual([]);
  });

  it("stays quiet when a listener cannot be released, before or after it was registered", async () => {
    stubEventBus({ failUnlisten: true });
    const rejections = await unhandledRejectionsDuring(async () => {
      const queryClient = new QueryClient();
      subscribeSyncEvents(queryClient)(); // dropped before listen() resolves: released as soon as it does
      const stop = subscribeSyncEvents(queryClient);
      await new Promise((resolve) => setTimeout(resolve, 0)); // registered by now
      stop();
    });
    expect(rejections).toEqual([]);
  });
});
