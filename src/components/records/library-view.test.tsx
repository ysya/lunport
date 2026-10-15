import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { stubBackend } from "@/lib/test-ipc";
import { useSettingsStore } from "@/stores/settings";
import { buttonTag, DISABLED } from "@/components/keychain/test-markup";
import { groupView, hostPayload, hostView, recordOverview } from "./fixtures";
import { libraryHosts, recentHostKey } from "./library-view";
import { connectSavedHost } from "./operations";
import { HostPreview } from "./HostPreview";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("connection library browsing", () => {
  it("searches multiple words across inherited connection values, tags and group paths", () => {
    const group = groupView({
      payload: {
        schema: 1,
        name: "Production",
        parent_id: null,
        defaults: { user: "deployer" },
      },
    });
    const host = hostView({
      payload: hostPayload({
        group_id: group.id,
        hostname: "raw.invalid",
        user: "fallback",
        tags: ["api"],
      }),
      effective_payload: hostPayload({
        hostname: "10.0.0.8",
        user: "deployer",
        port: 2222,
      }),
    });
    const overview = recordOverview({ groups: [group], hosts: [host] });
    expect(
      libraryHosts(
        overview,
        { kind: "all" },
        "DEPLOYER 10.0 api production 2222",
        {},
      ),
    ).toEqual([host]);
    expect(
      libraryHosts(overview, { kind: "all" }, "deployer missing", {}),
    ).toEqual([]);
    expect(host.payload.user).toBe("fallback");
  });
  it("includes descendants of a selected Group and keeps broken membership inspectable in All hosts", () => {
    const parent = groupView();
    const child = groupView({
      id: "0000000000000011",
      payload: { schema: 1, name: "API", parent_id: parent.id, defaults: {} },
    });
    const member = hostView({ payload: hostPayload({ group_id: child.id }) });
    const broken = hostView({
      id: "0000000000000002",
      payload: hostPayload({ group_id: "missing" }),
      group_error: "Missing group",
    });
    const overview = recordOverview({
      groups: [parent, child],
      hosts: [member, broken],
    });
    expect(
      libraryHosts(overview, { kind: "group", id: parent.id }, "", {}),
    ).toEqual([member]);
    expect(libraryHosts(overview, { kind: "all" }, "", {})).toHaveLength(2);
    expect(libraryHosts(overview, { kind: "attention" }, "", {})).toEqual([
      broken,
    ]);
  });
  it("uses stable IDs for recent hosts with duplicate aliases and does not revive removed hosts", () => {
    const first = hostView();
    const second = hostView({ id: "0000000000000002" });
    const recent = {
      web: 999,
      [recentHostKey(first.id)]: 20,
      [recentHostKey(second.id)]: 40,
      [recentHostKey("removed")]: 100,
    };
    expect(
      libraryHosts(
        recordOverview({ hosts: [first, second] }),
        { kind: "recent" },
        "",
        recent,
      ).map((h) => h.id),
    ).toEqual([second.id, first.id]);
  });
  it("matches whole tags and does not treat a hidden storage name as a filter", () => {
    const host = hostView({ payload: hostPayload({ tags: ["production"] }) });
    const overview = recordOverview({ hosts: [host] });
    expect(libraryHosts(overview, { kind: "tag", id: "prod" }, "", {})).toEqual(
      [],
    );
    expect(
      libraryHosts(overview, { kind: "tag", id: "production" }, "", {}),
    ).toEqual([host]);
    expect(libraryHosts(overview, { kind: "all" }, "local", {})).toEqual([]);
  });
  it("keeps missing keys and Group errors out of the direct connect action", () => {
    for (const host of [
      hostView({ readiness: { kind: "needs_key" } }),
      hostView({ group_error: "Review inheritance" }),
    ]) {
      const html = renderToStaticMarkup(
        <HostPreview
          host={host}
          overview={recordOverview({ hosts: [host] })}
          connect={vi.fn()}
          edit={vi.fn()}
          close={vi.fn()}
          busy={false}
        />,
      );
      expect(buttonTag(html, "Connect")).toContain(DISABLED);
      expect(html).toContain("Review settings");
    }
  });
});

describe("conflicting host identities", () => {
  it("includes every duplicate ID in Needs attention without choosing one to connect", () => {
    const host = hostView();
    const overview = recordOverview({
      hosts: [
        host,
        hostView({ scope: { kind: "space", space_id: "a".repeat(64) } }),
      ],
    });
    expect(libraryHosts(overview, { kind: "attention" }, "", {})).toHaveLength(
      2,
    );
  });
});

describe("recent connection launches", () => {
  it("records the stable host ID only after the connection command succeeds", async () => {
    const record = vi
      .spyOn(useSettingsStore.getState(), "recordConnection")
      .mockImplementation(() => {});
    const host = hostView();
    const calls = stubBackend(async () => undefined);
    await connectSavedHost(recordOverview(), host.id, "iterm2", true);
    expect(calls).toEqual([
      [
        "records_connect",
        { hostId: host.id, terminalId: "iterm2", newTab: true },
      ],
    ]);
    expect(record).toHaveBeenCalledExactlyOnceWith(recentHostKey(host.id));
  });
  it("still succeeds when the terminal opens but local history cannot be written", async () => {
    vi.spyOn(
      useSettingsStore.getState(),
      "recordConnection",
    ).mockImplementation(() => {
      throw new Error("Storage full");
    });
    stubBackend(async () => undefined);
    await expect(
      connectSavedHost(recordOverview(), hostView().id, null, false),
    ).resolves.toBeUndefined();
  });
  it("does not add refused or failed launches to Recent", async () => {
    const record = vi
      .spyOn(useSettingsStore.getState(), "recordConnection")
      .mockImplementation(() => {});
    stubBackend(async () => {
      throw new Error("Launch failed");
    });
    await expect(
      connectSavedHost(recordOverview(), hostView().id, null, false),
    ).rejects.toThrow("Launch failed");
    await expect(
      connectSavedHost(
        recordOverview({
          hosts: [hostView({ readiness: { kind: "needs_key" } })],
        }),
        hostView().id,
        null,
        false,
      ),
    ).rejects.toThrow();
    expect(record).not.toHaveBeenCalled();
  });
});
