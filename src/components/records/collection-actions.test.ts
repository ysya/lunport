import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import { applyCollectionAction } from "./collection-actions";
import { hostPayload, hostView, recordOverview } from "./fixtures";

afterEach(() => vi.unstubAllGlobals());
describe("collection operations use reviewed stable IDs", () => {
  it("rejects removed and conflicting IDs before changing any host", async () => {
    const host = hostView();
    const calls = stubBackend(async () => recordOverview());
    for (const [hosts, ids] of [
      [[], [host.id]],
      [[host, host], [host.id]],
      [[host], [host.id, host.id]],
    ] as const) {
      await expect(
        applyCollectionAction(
          recordOverview({ hosts: [...hosts] }),
          [...ids],
          { kind: "tag", tag: "work" },
          vi.fn(),
        ),
      ).rejects.toThrow();
    }
    expect(calls).toEqual([]);
  });
  it("preserves inherited settings and uses the reviewed revision when adding a tag", async () => {
    const host = hostView({
      payload: hostPayload({
        schema: 3,
        tags: ["existing"],
        group_id: "0000000000000010",
        inherit: ["user"],
        user: "raw-fallback",
      }),
    });
    const overview = recordOverview({ hosts: [host] });
    const calls = stubBackend(async () => overview);
    const accept = vi.fn();
    expect(
      await applyCollectionAction(
        overview,
        [host.id],
        { kind: "tag", tag: " work " },
        accept,
      ),
    ).toEqual({ completed: [host.id], error: null });
    expect(calls).toEqual([
      [
        "records_host_update",
        {
          id: host.id,
          revision: host.revision,
          payload: {
            ...host.payload,
            tags: ["existing", "work"],
            host_key: null,
          },
        },
      ],
    ]);
    expect(accept).toHaveBeenCalledWith(overview);
  });
  it("keeps partial successes and stops on a conflict without replaying writes", async () => {
    const first = hostView();
    const second = hostView({ id: "0000000000000002" });
    const third = hostView({ id: "0000000000000003" });
    const overview = recordOverview({ hosts: [first, second, third] });
    const destination = { kind: "space" as const, space_id: "a".repeat(64) };
    const calls = stubBackend(async (_, args) => {
      if ((args as { id: string }).id === second.id)
        throw new Error("revision changed");
      return overview;
    });
    const accept = vi.fn();
    const result = await applyCollectionAction(
      overview,
      [first.id, second.id, third.id],
      { kind: "move", destination },
      accept,
    );
    expect(result.completed).toEqual([first.id]);
    expect(result.error).toContain("remaining hosts");
    expect(calls).toEqual([
      [
        "records_host_move",
        { id: first.id, revision: first.revision, destination },
      ],
      [
        "records_host_move",
        { id: second.id, revision: second.revision, destination },
      ],
    ]);
    expect(accept).toHaveBeenCalledOnce();
  });
  it("does not write a move when the host already has the destination scope", async () => {
    const host = hostView();
    const calls = stubBackend(async () => recordOverview());
    const result = await applyCollectionAction(
      recordOverview(),
      [host.id],
      { kind: "move", destination: { kind: "local" } },
      vi.fn(),
    );
    expect(result).toEqual({ completed: [host.id], error: null });
    expect(calls).toEqual([]);
  });
});
