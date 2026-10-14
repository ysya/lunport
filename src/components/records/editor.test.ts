import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import {
  hostPayload,
  hostView,
  importPreview,
  recordOverview,
} from "./fixtures";
import {
  beginEditor,
  changeEditor,
  refreshEditor,
  buildEditorPayload,
  editorProblem,
  submitEditor,
  selectHost,
  confirmedCopyIds,
} from "./editor";
afterEach(() => vi.unstubAllGlobals());
describe("record editor", () => {
  it("creates a local unpinned draft with no inferred key sharing", () => {
    const draft = beginEditor(null);
    expect(draft.scope).toEqual({ kind: "local" });
    expect(draft.id).toBeNull();
    expect(draft.payload.host_key).toBeNull();
    expect(draft.payload.key_id).toBeNull();
    expect(editorProblem(draft)).not.toBeNull();
  });
  it("clones payload and revision so input edits cannot mutate the current snapshot", () => {
    const host = hostView();
    const state = beginEditor(host);
    const edited = changeEditor(state, { alias: "changed", tags: ["new"] });
    expect(host.payload.alias).toBe("web");
    expect(host.payload.tags).toEqual([]);
    expect(state.payload.alias).toBe("web");
    expect(edited.dirty).toBe(true);
    expect(edited.revision?.version).toBe("9007199254740993");
  });
  it("preserves dirty input and original optimistic revision when the server refreshes", () => {
    const edited = changeEditor(beginEditor(hostView()), {
      hostname: "my-unsaved.invalid",
    });
    const remote = hostView({
      payload: hostPayload({ hostname: "remote.invalid" }),
      revision: {
        version: "9007199254740994",
        updated_at_ms: "18446744073709551615",
        device_id: "e".repeat(32),
      },
    });
    const refreshed = refreshEditor(edited, remote);
    expect(refreshed.payload.hostname).toBe("my-unsaved.invalid");
    expect(refreshed.revision).toEqual(hostView().revision);
    expect(refreshed.changedOnServer).toBe(true);
    expect(refreshed.dirty).toBe(true);
  });
  it("accepts new server values only while pristine and never turns a missing dirty host into a create", () => {
    const remote = hostView({ payload: hostPayload({ alias: "remote" }) });
    expect(refreshEditor(beginEditor(hostView()), remote).payload.alias).toBe(
      "remote",
    );
    const edited = changeEditor(beginEditor(hostView()), {
      notes: "keep this draft",
    });
    const unavailable = refreshEditor(edited, null);
    expect(unavailable.id).toBe(hostView().id);
    expect(unavailable.payload.notes).toBe("keep this draft");
    expect(unavailable.unavailable).toBe(true);
  });
  it("strips pins and clears only blocking imported entries after explicit review", () => {
    const host = hostView({
      payload: hostPayload({
        host_key: {
          algorithm: "ssh-ed25519",
          public_key: "fixture",
          fingerprint: "SHA256:fixture",
          pinned_at_ms: 1,
          pinned_by_device_id: "d".repeat(32),
        },
        imported: {
          source: "/fixture/config",
          at_ms: 1,
          unsupported: [
            { keyword: "Match", value: "unsupported", requires_review: true },
            { keyword: "Comment", value: "keep", requires_review: false },
          ],
        },
      }),
    });
    const state = beginEditor(host);
    expect(buildEditorPayload(state).host_key).toBeNull();
    expect(buildEditorPayload(state).imported?.unsupported).toHaveLength(2);
    const reviewed = buildEditorPayload({ ...state, reviewed: true });
    expect(reviewed.imported?.unsupported).toEqual([
      { keyword: "Comment", value: "keep", requires_review: false },
    ]);
    expect(host.payload.imported?.unsupported).toHaveLength(2);
  });
  it("submits the frozen revision and keeps failure input intact", async () => {
    const state = changeEditor(beginEditor(hostView()), { alias: "edited" });
    const before = structuredClone(state);
    const calls = stubBackend(async () => {
      throw "revision conflict";
    });
    await expect(submitEditor(state)).rejects.toBe("revision conflict");
    expect(calls).toEqual([
      [
        "records_host_update",
        {
          id: state.id,
          revision: hostView().revision,
          payload: hostPayload({ alias: "edited" }),
        },
      ],
    ]);
    expect(state).toEqual(before);
  });
  it("validates saveable endpoints and permits a missing referenced key", () => {
    const valid = changeEditor(
      beginEditor(null),
      hostPayload({ auth: "key", key_id: "a".repeat(32) }),
    );
    expect(editorProblem(valid)).toBeNull();
    expect(editorProblem(changeEditor(valid, { port: 0 }))).not.toBeNull();
    expect(editorProblem(changeEditor(valid, { key_id: null }))).not.toBeNull();
    expect(
      editorProblem(changeEditor(valid, { connect_timeout_secs: 0 })),
    ).not.toBeNull();
  });
  it("creates with local scope and lets backend allocate the ID", async () => {
    const calls = stubBackend(async () => recordOverview());
    const state = changeEditor(beginEditor(null), hostPayload());
    await submitEditor(state);
    expect(calls).toEqual([
      [
        "records_host_create",
        { scope: { kind: "local" }, payload: hostPayload() },
      ],
    ]);
  });
  it("refuses arbitrary selection of duplicate global IDs", () => {
    const host = hostView();
    expect(selectHost([host], host.id)).toEqual(host);
    expect(
      selectHost(
        [host, { ...host, scope: { kind: "space", space_id: "a".repeat(64) } }],
        host.id,
      ),
    ).toBeNull();
  });
  it("confirms only explicit unique copy IDs from the current preview", () => {
    const preview = importPreview();
    expect(confirmedCopyIds(preview, [])).toEqual([]);
    expect(
      confirmedCopyIds(preview, [
        "a".repeat(32),
        "a".repeat(32),
        "stale-preview-id",
      ]),
    ).toEqual(["a".repeat(32)]);
    expect(
      confirmedCopyIds(importPreview({ key_references: [] }), ["a".repeat(32)]),
    ).toEqual([]);
  });
});
