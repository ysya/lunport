import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Dialog } from "@/components/ui/dialog";
import { stubBackend } from "@/lib/test-ipc";
import { hostPayload, hostView, recordOverview, groupView } from "./fixtures";
import { beginEditor, changeEditor, submitEditor } from "./editor";
import { previewInheritance, toggleInheritance } from "./inheritance";
import {
  buildRecordTree,
  groupPath,
  selectGroup,
  affectedRecords,
} from "./group-tree";
import {
  beginGroupEditor,
  changeGroupEditor,
  refreshGroupEditor,
  submitGroupEditor,
} from "./group-editor";
import { RecordHostEditor } from "./HostEditor";
import { decideHostSelection } from "./selection";
afterEach(() => vi.unstubAllGlobals());
const parent = () =>
  groupView({
    id: "0000000000000010",
    payload: {
      schema: 1,
      name: "Operations",
      parent_id: null,
      defaults: { user: "ops", port: 2222 },
    },
  });
const child = () =>
  groupView({
    id: "0000000000000011",
    payload: { schema: 1, name: "Fleet", parent_id: parent().id, defaults: {} },
  });
const inherited = () =>
  hostView({
    payload: hostPayload({
      schema: 3,
      user: "fallback",
      group_id: child().id,
      inherit: ["user"],
    }),
    effective_payload: hostPayload({ schema: 3, user: "ops" }),
    inherited_from: { user: parent().id },
  });
describe("Group inheritance editing", () => {
  it("shows effective user and Group source while saving raw fallback and selected inheritance", async () => {
    const overview = recordOverview({
      hosts: [inherited()],
      groups: [parent(), child()],
    });
    const state = changeEditor(beginEditor(inherited()), { notes: "edited" });
    expect(
      previewInheritance(overview, state.scope, state.payload),
    ).toMatchObject({
      payload: { user: "ops", port: 22 },
      sources: { user: parent().id },
      error: null,
    });
    const calls = stubBackend(async () => overview);
    await submitEditor(state);
    expect(calls[0]).toEqual([
      "records_host_update",
      {
        id: inherited().id,
        revision: inherited().revision,
        payload: { ...inherited().payload, notes: "edited", host_key: null },
      },
    ]);
    const html = renderToStaticMarkup(
      <RecordHostEditor
        host={inherited()}
        hostId={inherited().id}
        overview={overview}
        terminalId={null}
        newTab={false}
        accept={(v) => v}
        onSaved={vi.fn()}
        onDeleted={vi.fn()}
        onDirty={vi.fn()}
      />,
    );
    const effectiveInput =
      html.match(/<input[^>]*value="ops"[^>]*>/)?.[0] ?? "";
    expect(effectiveInput).toContain('disabled=""');
    expect(html).not.toContain('value="fallback"');
    expect(html).toContain('aria-label="Username: Use group default"');
    expect(html).toContain("ops");
    expect(html).toContain("Operations");
  });
  it("clearing inheritance preserves an explicit edit and unsaved group choices change preview", () => {
    const overview = recordOverview({ groups: [parent(), child()] });
    let payload = toggleInheritance(inherited().payload, "user", false);
    payload = { ...payload, user: "explicit" };
    expect(payload.inherit).toEqual([]);
    expect(
      previewInheritance(overview, { kind: "local" }, payload).payload.user,
    ).toBe("explicit");
    payload = toggleInheritance({ ...payload, group_id: null }, "user", true);
    expect(
      previewInheritance(overview, { kind: "local" }, payload),
    ).toMatchObject({ payload: { user: "" }, sources: { user: "default" } });
  });
  it("resolves all literal app defaults and authentication as one pair", () => {
    const fields = [
      "port",
      "user",
      "authentication",
      "jump",
      "keepalive_secs",
      "keepalive_max_missed",
      "connect_timeout_secs",
    ] as const;
    const p = hostPayload({
      schema: 3,
      port: 99,
      user: "raw",
      auth: "key",
      key_id: "a".repeat(32),
      jump: ["0000000000000002"],
      keepalive_secs: 99,
      keepalive_max_missed: 99,
      connect_timeout_secs: 99,
      inherit: [...fields],
    });
    expect(
      previewInheritance(recordOverview(), { kind: "local" }, p).payload,
    ).toMatchObject({
      port: 22,
      user: "",
      auth: "password",
      key_id: null,
      jump: [],
      keepalive_secs: 30,
      keepalive_max_missed: 3,
      connect_timeout_secs: 15,
    });
    const group = parent();
    group.payload.defaults.authentication = {
      auth: "key",
      key_id: "b".repeat(32),
    };
    expect(
      previewInheritance(recordOverview({ groups: [group] }), group.scope, {
        ...p,
        group_id: group.id,
      }).payload,
    ).toMatchObject({ auth: "key", key_id: "b".repeat(32) });
    expect(p.key_id).toBe("a".repeat(32));
  });
});
describe("Group tree", () => {
  it("reveals matching host ancestors and matches complete Group paths", () => {
    const overview = recordOverview({
      hosts: [
        inherited(),
        hostView({
          id: "0000000000000002",
          payload: hostPayload({ alias: "other" }),
        }),
      ],
      groups: [child(), parent()],
    });
    const roots = buildRecordTree(overview, "web");
    expect(
      roots[0].groups.map((g) => [
        g.group.id,
        g.children.map((c) => c.group.id),
      ]),
    ).toEqual([[parent().id, [child().id]]]);
    expect(roots[0].groups[0].children[0].hosts.map((h) => h.id)).toEqual([
      inherited().id,
    ]);
    expect(groupPath(overview, child().id, { kind: "local" })).toBe(
      "Operations / Fleet",
    );
    expect(
      buildRecordTree(overview, "Operations / Fleet")[0].groups[0].children[0]
        .hosts,
    ).toHaveLength(1);
  });
  it("keeps cycle, missing-parent and duplicate-ID rows visible without arbitrary selection", () => {
    const a = parent(),
      b = child();
    a.payload.parent_id = b.id;
    const orphan = groupView({
      id: "0000000000000012",
      payload: {
        schema: 1,
        name: "Orphan",
        parent_id: "0000000000000099",
        defaults: {},
      },
    });
    const overview = recordOverview({
      hosts: [inherited()],
      groups: [
        a,
        b,
        orphan,
        { ...orphan, payload: { ...orphan.payload, name: "Duplicate" } },
      ],
    });
    const tree = buildRecordTree(overview);
    expect(tree[0].diagnostics).toHaveLength(4);
    expect(selectGroup(overview.groups, orphan.id)).toBeNull();
    expect(
      previewInheritance(overview, inherited().scope, inherited().payload)
        .error,
    ).toMatch(/cycle/i);
    expect(tree[0].ungrouped).toHaveLength(1);
    expect(
      buildRecordTree(overview, "web")[0].diagnostics.map((d) => d.group.id),
    ).toEqual([b.id, a.id]);
  });
  it("counts descendant Groups and hosts using stable identities", () => {
    const overview = recordOverview({
      groups: [parent(), child()],
      hosts: [inherited()],
    });
    expect(affectedRecords(overview, parent())).toEqual({
      groups: 1,
      hosts: 1,
    });
  });
});
describe("Group draft and command contract", () => {
  it("keeps failed draft and frozen revision, creates only with explicit scope and upgrade consent", async () => {
    const state = changeGroupEditor(beginGroupEditor(parent()), {
      name: "Renamed",
    });
    const before = structuredClone(state);
    const calls = stubBackend(async () => {
      throw new Error("revision conflict");
    });
    await expect(
      submitGroupEditor(state, recordOverview({ groups: [parent()] })),
    ).rejects.toThrow("revision conflict");
    expect(calls[0]).toEqual([
      "records_group_update",
      {
        id: parent().id,
        revision: parent().revision,
        payload: { ...parent().payload, name: "Renamed" },
      },
    ]);
    expect(state).toEqual(before);
    expect(
      refreshGroupEditor(
        state,
        groupView({
          ...parent(),
          revision: { ...parent().revision, version: "999" },
        }),
      ).payload.name,
    ).toBe("Renamed");
    const fresh = changeGroupEditor(
      beginGroupEditor(null, { kind: "space", space_id: "a".repeat(64) }),
      { name: "Team" },
    );
    const upgraded = recordOverview({ format_upgrade_required: true });
    await expect(submitGroupEditor(fresh, upgraded)).rejects.toThrow(
      /updated/i,
    );
    stubBackend(async () => recordOverview());
    await submitGroupEditor(fresh, upgraded, true);
  });
  it("guards dirty host to Group and Group to new-host navigation and retains same Group", () => {
    expect(
      decideHostSelection(
        { kind: "host", id: "h" },
        { kind: "group", id: "g" },
        true,
        false,
      ),
    ).toBe("confirm");
    expect(
      decideHostSelection(
        { kind: "group", id: "g" },
        { kind: "new", nonce: 1 },
        true,
        true,
      ),
    ).toBe("keep");
    expect(
      decideHostSelection(
        { kind: "group", id: "g" },
        { kind: "group", id: "g" },
        true,
        false,
      ),
    ).toBe("keep");
  });
});

describe("Group editor presentation", () => {
  it("keeps first-time group creation free of impact and deletion warnings", async () => {
    const { RecordGroupEditor } = await import("./GroupEditor");
    const html = renderToStaticMarkup(
      <Dialog>
        <RecordGroupEditor
          group={null}
          groupId={null}
          overview={recordOverview({ group_deletion_token: "" })}
          accept={(v) => v}
          onSaved={vi.fn()}
          onDeleted={vi.fn()}
          onDirty={vi.fn()}
        />
      </Dialog>,
    );
    expect(html).not.toContain("host-key pin");
    expect(html).not.toContain("deletion review");
    expect(html).not.toContain("Manage group");
    expect(html).toContain("Only a name is required");
  });

  it("explains how to recover when no deletion snapshot is available", async () => {
    const { RecordGroupEditor } = await import("./GroupEditor");
    const html = renderToStaticMarkup(
      <Dialog>
        <RecordGroupEditor
          group={parent()}
          groupId={parent().id}
          overview={recordOverview({
            groups: [parent()],
            group_deletion_token: "",
          })}
          accept={(v) => v}
          onSaved={vi.fn()}
          onDeleted={vi.fn()}
          onDirty={vi.fn()}
        />
      </Dialog>,
    );
    expect(html).toContain(
      "Refresh the records to prepare a new deletion review.",
    );
  });
  it("states immutable scope, descendant effects and host-preserving deletion", async () => {
    const { RecordGroupEditor } = await import("./GroupEditor");
    const html = renderToStaticMarkup(
      <Dialog>
        <RecordGroupEditor
          group={parent()}
          groupId={parent().id}
          overview={recordOverview({
            groups: [parent(), child()],
            hosts: [inherited()],
          })}
          accept={(v) => v}
          onSaved={vi.fn()}
          onDeleted={vi.fn()}
          onDirty={vi.fn()}
        />
      </Dialog>,
    );
    expect(html).toContain("Library");
    expect(html).toContain("1 descendant Group");
    expect(html).toContain("1 host");
    expect(html).toContain("preserved");
    expect(html).toContain("Use parent/app default");
  });
});

describe("Group creation, format and safety boundaries", () => {
  it("sends exact Group scope, parent, upgrade confirmation and frozen deletion revision", async () => {
    const { deleteRecordGroup } = await import("@/lib/records");
    const scope = { kind: "space" as const, space_id: "a".repeat(64) };
    const overview = recordOverview({ shared_format_upgrade_required: true });
    const state = changeGroupEditor(beginGroupEditor(null, scope), {
      name: " Team ",
    });
    const calls = stubBackend(async () => overview);
    await submitGroupEditor(state, overview, true);
    await deleteRecordGroup(
      parent().id,
      parent().revision,
      overview.group_deletion_token,
    );
    expect(calls).toEqual([
      [
        "records_group_create",
        {
          scope,
          payload: { schema: 1, name: "Team", parent_id: null, defaults: {} },
          upgradeConfirmed: true,
        },
      ],
      [
        "records_group_delete",
        {
          id: parent().id,
          revision: parent().revision,
          snapshotToken: overview.group_deletion_token,
        },
      ],
    ]);
    expect(state.payload.name).toBe(" Team ");
  });
  it("creates a new host in the selected Group without implicit inheritance", () => {
    const html = renderToStaticMarkup(
      <RecordHostEditor
        host={null}
        hostId={null}
        overview={recordOverview({ groups: [parent()] })}
        initialScope={{ kind: "local" }}
        initialGroupId={parent().id}
        terminalId={null}
        newTab={false}
        accept={(v) => v}
        onSaved={vi.fn()}
        onDeleted={vi.fn()}
        onDirty={vi.fn()}
      />,
    );
    expect(html).toContain(`value="${parent().id}" selected=""`);
    expect(html).toContain("Use group default");
    expect(html).not.toContain('type="checkbox" checked=""');
  });
  it("passes host format upgrade consent without flattening inheritance", async () => {
    const state = changeEditor(beginEditor(inherited()), { notes: "preserve" });
    const calls = stubBackend(async () => recordOverview());
    await submitEditor(state, true);
    expect(calls[0]).toEqual([
      "records_host_update",
      {
        id: inherited().id,
        revision: inherited().revision,
        payload: { ...inherited().payload, notes: "preserve" },
        upgradeConfirmed: true,
      },
    ]);
  });
  it("refuses diagnostic hosts even when a stale readiness flag claims ready", async () => {
    const { connectSavedHost } = await import("./operations");
    const host = hostView({
      group_error: "Unreadable winning Group",
      readiness: { kind: "ready" },
    });
    const calls = stubBackend(async () => undefined);
    await expect(
      connectSavedHost(recordOverview({ hosts: [host] }), host.id, null, false),
    ).rejects.toThrow(/settings/i);
    expect(calls).toEqual([]);
  });
  it("Group path remains searchable in the CommandPalette", async () => {
    // Path inclusion is shared with the tree and visible in the actual palette item.
    const { recordHostSearchText } = await import("./group-tree");
    expect(
      recordHostSearchText(
        recordOverview({ groups: [parent(), child()] }),
        inherited(),
      ),
    ).toContain("Operations / Fleet");
  });
});

describe("Group validation and refresh recovery", () => {
  it("rejects cross-scope parent, own descendants and atomic authentication errors before IPC", async () => {
    const overview = recordOverview({ groups: [parent(), child()] });
    const calls = stubBackend(async () => overview);
    const ownChild = changeGroupEditor(beginGroupEditor(parent()), {
      parent_id: child().id,
    });
    await expect(submitGroupEditor(ownChild, overview)).rejects.toThrow(
      /subtree/i,
    );
    const otherScope = {
      ...beginGroupEditor(parent()),
      scope: { kind: "space" as const, space_id: "a".repeat(64) },
      payload: { ...parent().payload, parent_id: child().id },
    };
    await expect(submitGroupEditor(otherScope, overview)).rejects.toThrow(
      /scope/i,
    );
    const badAuth = changeGroupEditor(beginGroupEditor(parent()), {
      defaults: {
        authentication: { auth: "password", key_id: "a".repeat(32) },
      },
    });
    await expect(submitGroupEditor(badAuth, overview)).rejects.toThrow(
      /cannot reference/i,
    );
    expect(calls).toEqual([]);
  });
  it("retains removed Group draft identity and marks remote changes without changing CAS", () => {
    const state = changeGroupEditor(beginGroupEditor(parent()), {
      defaults: { user: "draft" },
    });
    const removed = refreshGroupEditor(state, null);
    expect(removed).toMatchObject({
      id: parent().id,
      payload: { defaults: { user: "draft" } },
      revision: parent().revision,
      unavailable: true,
      changedOnServer: true,
    });
    expect(
      refreshGroupEditor(state, {
        ...parent(),
        revision: { ...parent().revision, version: "999" },
      }),
    ).toMatchObject({
      payload: { defaults: { user: "draft" } },
      revision: parent().revision,
      changedOnServer: true,
      unavailable: false,
    });
  });
  it("distinguishes Local format requirements from shared schema promotion", async () => {
    const { requiresFormatUpgrade } = await import("./group-tree");
    const overview = recordOverview({ shared_format_upgrade_required: true });
    expect(requiresFormatUpgrade(overview, { kind: "local" })).toBe(false);
    expect(
      requiresFormatUpgrade(overview, {
        kind: "space",
        space_id: "a".repeat(64),
      }),
    ).toBe(true);
    expect(
      requiresFormatUpgrade(
        { ...overview, format_upgrade_required: true },
        { kind: "local" },
      ),
    ).toBe(true);
  });
  it("orders scope roots and nested names consistently, keeping Ungrouped separate", () => {
    const team = groupView({
      id: "0000000000000012",
      scope: { kind: "space", space_id: "a".repeat(64) },
      payload: { schema: 1, name: "Team", parent_id: null, defaults: {} },
    });
    const overview = recordOverview({
      groups: [child(), team, parent()],
      hosts: [
        inherited(),
        hostView({
          id: "0000000000000002",
          payload: hostPayload({ alias: "standalone" }),
        }),
      ],
      spaces: [
        { id: "a".repeat(64), name: "Work", selected: true, missing: false },
      ],
    });
    const roots = buildRecordTree(overview);
    expect(roots.map((root) => root.label)).toEqual(["Local", "Work"]);
    expect(roots[0].ungrouped.map((h) => h.payload.alias)).toEqual([
      "standalone",
    ]);
    expect(roots[1].groups.map((g) => g.group.payload.name)).toEqual(["Team"]);
    expect(overview.groups.map((g) => g.id)).toEqual([
      child().id,
      team.id,
      parent().id,
    ]);
  });
});

describe("Effective inherited controls", () => {
  it("renders effective key authentication without exposing the preserved password override", () => {
    const group = parent();
    group.payload.defaults.authentication = {
      auth: "key",
      key_id: "b".repeat(32),
    };
    const host = hostView({
      payload: hostPayload({
        schema: 3,
        auth: "password",
        key_id: null,
        group_id: group.id,
        inherit: ["authentication"],
      }),
    });
    const html = renderToStaticMarkup(
      <RecordHostEditor
        host={host}
        hostId={host.id}
        overview={recordOverview({
          groups: [group],
          hosts: [host],
          keys: [
            {
              id: "b".repeat(32),
              authority: "local",
              public: {
                schema: 1,
                name: "Work key",
                public_key: "fixture",
                fingerprint: "SHA256:fixture",
                key_type: "ed25519",
                has_passphrase: false,
                created_at_ms: 1,
                origin_device_id: "d".repeat(32),
              },
              synced: null,
              status: "available",
            },
          ],
        })}
        terminalId={null}
        newTab={false}
        accept={(v) => v}
        onSaved={vi.fn()}
        onDeleted={vi.fn()}
        onDirty={vi.fn()}
      />,
    );
    const selects = html.match(/<select\b[^>]*>[\s\S]*?<\/select>/g) ?? [];
    const auth =
      selects.find((select) => select.includes('value="key" selected=""')) ??
      "";
    expect(auth).toContain('disabled=""');
    const key =
      selects.find((select) =>
        select.includes(`value="${"b".repeat(32)}" selected=""`),
      ) ?? "";
    expect(key).toContain('disabled=""');
    expect(key).toContain("Work key");
    expect(host.payload).toMatchObject({ auth: "password", key_id: null });
    expect(html).toContain("Source: Operations");
  });
  it("restores the explicit raw value when inheritance is cleared", () => {
    const host = inherited();
    host.payload = toggleInheritance(host.payload, "user", false);
    const html = renderToStaticMarkup(
      <RecordHostEditor
        host={host}
        hostId={host.id}
        overview={recordOverview({ groups: [parent(), child()] })}
        terminalId={null}
        newTab={false}
        accept={(v) => v}
        onSaved={vi.fn()}
        onDeleted={vi.fn()}
        onDirty={vi.fn()}
      />,
    );
    const input = html.match(/<input[^>]*value="fallback"[^>]*>/)?.[0] ?? "";
    expect(input).toContain('value="fallback"');
    expect(input).not.toContain('disabled=""');
    expect(html).not.toContain('value="ops"');
  });
  it("shows a conflicting selected Group as unavailable instead of appearing Ungrouped", () => {
    const group = parent();
    const host = hostView({
      payload: hostPayload({ group_id: group.id, schema: 3 }),
    });
    const html = renderToStaticMarkup(
      <RecordHostEditor
        host={host}
        hostId={host.id}
        overview={recordOverview({
          groups: [
            group,
            { ...group, payload: { ...group.payload, name: "Duplicate" } },
          ],
        })}
        terminalId={null}
        newTab={false}
        accept={(v) => v}
        onSaved={vi.fn()}
        onDeleted={vi.fn()}
        onDirty={vi.fn()}
      />,
    );
    expect(html).toContain(`value="${group.id}" selected=""`);
    expect(html).toContain("Unavailable Group");
  });
});
