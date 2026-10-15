import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import { groupView, hostPayload, hostView, recordOverview } from "./fixtures";
import {
  beginGroupEditor,
  beginGroupDeletion,
  refreshGroupEditor,
  submitGroupDeletion,
} from "./group-editor";
import { beginEditor, buildEditorPayload, changeEditor } from "./editor";
import { previewHostDraft } from "./inheritance";
import { connectSavedHost } from "./operations";
afterEach(() => vi.unstubAllGlobals());
describe("immutable Group deletion review", () => {
  it("uses reviewed revision and counts after a pristine editor refresh", async () => {
    const group = groupView();
    const original = beginGroupEditor(group);
    const candidate = beginGroupDeletion(original, { groups: 1, hosts: 2 }, "reviewed-snapshot");
    const updated = {
      ...group,
      revision: {
        version: "999",
        updated_at_ms: "1000",
        device_id: "e".repeat(32),
      },
    };
    const refreshed = refreshGroupEditor(original, updated);
    expect(refreshed.revision?.version).toBe("999");
    expect(candidate).toMatchObject({
      id: "0000000000000010",
      revision: {
        version: "9007199254740993",
        updated_at_ms: "18446744073709551614",
        device_id: "d".repeat(32),
      },
      counts: { groups: 1, hosts: 2 },
    });
    const calls = stubBackend(async (_command, args) => {
      if (
        (args as { revision: { version: string } }).revision.version !== "999"
      )
        throw new Error("revision conflict");
      return recordOverview();
    });
    await expect(submitGroupDeletion(candidate, refreshed)).rejects.toThrow(
      "revision conflict",
    );
    expect(calls).toEqual([
      [
        "records_group_delete",
        {
          id: "0000000000000010",
          snapshotToken: "reviewed-snapshot",
          revision: {
            version: "9007199254740993",
            updated_at_ms: "18446744073709551614",
            device_id: "d".repeat(32),
          },
        },
      ],
    ]);
    expect(candidate.counts).toEqual({ groups: 1, hosts: 2 });
    expect(refreshed.payload.name).toBe("Operations");
  });
  it("passes the frozen snapshot token even when only descendants change", async () => {
    const state = beginGroupEditor(groupView());
    const reviewed = recordOverview({ group_deletion_token: "before-descendant-edit" });
    const candidate = beginGroupDeletion(state, { groups: 1, hosts: 2 }, reviewed.group_deletion_token);
    reviewed.group_deletion_token = "after-descendant-edit";
    const calls = stubBackend(async (_command, args) => {
      if ((args as { snapshotToken: string }).snapshotToken !== reviewed.group_deletion_token)
        throw new Error("Refresh the records and review the deletion again.");
      return reviewed;
    });
    await expect(submitGroupDeletion(candidate, state)).rejects.toThrow("review the deletion again");
    expect(calls).toHaveLength(1);
    expect(candidate.snapshotToken).toBe("before-descendant-edit");
    const fresh = beginGroupDeletion(state, { groups: 2, hosts: 3 }, reviewed.group_deletion_token);
    await expect(submitGroupDeletion(fresh, state)).resolves.toBe(reviewed);
    expect(calls[1][1]).toMatchObject({ snapshotToken: "after-descendant-edit" });
  });
  it("refuses to open a deletion review without a backend snapshot token", () => {
    expect(() => beginGroupDeletion(beginGroupEditor(groupView()), { groups: 1, hosts: 2 }, ""))
      .toThrow("Refresh the records and review the deletion again");
  });
  it("copies the candidate values instead of retaining mutable editor/count objects", () => {
    const state = beginGroupEditor(groupView());
    const counts = { groups: 1, hosts: 2 };
    const candidate = beginGroupDeletion(state, counts, "reviewed-snapshot");
    state.revision!.version = "999";
    counts.hosts = 5;
    expect(candidate.revision.version).toBe("9007199254740993");
    expect(candidate.counts).toEqual({ groups: 1, hosts: 2 });
  });
});
describe("saved diagnosis versus repair draft preview", () => {
  const broken = () =>
    hostView({
      payload: hostPayload({
        schema: 3,
        group_id: "0000000000000099",
        user: "fallback",
        inherit: ["user"],
      }),
      group_error: "Opaque winning Group",
      readiness: { kind: "needs_review" },
    });
  const target = () =>
    groupView({
      payload: {
        schema: 1,
        name: "Operations",
        parent_id: null,
        defaults: { user: "ops" },
      },
    });
  it("previews a valid replacement Group while saved diagnostic still blocks Connect", async () => {
    const saved = broken();
    const overview = recordOverview({ hosts: [saved], groups: [target()] });
    const state = changeEditor(beginEditor(saved), { group_id: target().id });
    expect(
      previewHostDraft(overview, state.scope, state.payload, saved),
    ).toMatchObject({
      error: null,
      payload: { user: "ops" },
      sources: { user: "0000000000000010" },
    });
    expect(buildEditorPayload(state)).toMatchObject({
      user: "fallback",
      group_id: "0000000000000010",
      inherit: ["user"],
    });
    const calls = stubBackend(async () => undefined);
    await expect(
      connectSavedHost(overview, saved.id, null, false),
    ).rejects.toThrow(/settings/);
    expect(calls).toEqual([]);
    expect(saved.group_error).toBe("Opaque winning Group");
  });
  it("previews app defaults after detach without flattening the raw override", () => {
    const saved = broken();
    const overview = recordOverview({ hosts: [saved], groups: [target()] });
    const state = changeEditor(beginEditor(saved), { group_id: null });
    expect(
      previewHostDraft(overview, state.scope, state.payload, saved),
    ).toMatchObject({
      error: null,
      payload: { user: "" },
      sources: { user: "default" },
    });
    expect(buildEditorPayload(state)).toMatchObject({
      schema: 3,
      user: "fallback",
      group_id: null,
      inherit: ["user"],
    });
  });
  it("keeps an opaque saved diagnosis for unchanged resolution inputs and notes-only changes", () => {
    const saved = broken();
    // A stale readable Group view must not overrule the native winning-record diagnostic.
    const stale = groupView({
      id: "0000000000000099",
      payload: {
        schema: 1,
        name: "Stale cache",
        parent_id: null,
        defaults: { user: "cached" },
      },
    });
    const overview = recordOverview({ hosts: [saved], groups: [stale] });
    const state = changeEditor(beginEditor(saved), {
      notes: "changed only notes",
    });
    expect(
      previewHostDraft(overview, state.scope, state.payload, saved).error,
    ).toBe("Opaque winning Group");
  });
  it("does not show fallback for a draft that still references an invalid Group", () => {
    const saved = broken();
    const state = changeEditor(beginEditor(saved), {
      group_id: "0000000000000098",
    });
    expect(
      previewHostDraft(
        recordOverview({ hosts: [saved] }),
        state.scope,
        state.payload,
        saved,
      ).error,
    ).toMatch(/missing or conflicting/i);
  });
});
