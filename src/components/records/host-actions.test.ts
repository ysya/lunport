import { afterEach, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import { hostView, recordOverview } from "./fixtures";
import { deleteReviewedHost, reviewedHostIsCurrent } from "./host-actions";

afterEach(() => vi.unstubAllGlobals());
it("deletes only the reviewed saved host and revision", async () => {
  const reviewed = hostView();
  const overview = recordOverview({
    hosts: [hostView({ id: "0000000000000002" }), reviewed],
  });
  const calls = stubBackend(async () => overview);
  const accept = vi.fn();
  await deleteReviewedHost(reviewed, overview, accept);
  expect(calls).toEqual([
    ["records_host_delete", { id: reviewed.id, revision: reviewed.revision }],
  ]);
  expect(accept).toHaveBeenCalledWith(overview);
});
it("rejects removed, ambiguous, edited and relocated hosts before deletion", async () => {
  const host = hostView();
  const calls = stubBackend(async () => recordOverview());
  for (const hosts of [
    [],
    [host, host],
    [hostView({ revision: { ...host.revision, version: "2" } })],
    [hostView({ scope: { kind: "space", space_id: "a".repeat(64) } })],
  ]) {
    const current = recordOverview({ hosts });
    expect(reviewedHostIsCurrent(host, current)).toBe(false);
    await expect(deleteReviewedHost(host, current, vi.fn())).rejects.toThrow(
      "changed",
    );
  }
  expect(calls).toEqual([]);
});
it("does not replay a rejected deletion", async () => {
  const calls = stubBackend(async () => {
    throw new Error("revision conflict");
  });
  const accept = vi.fn();
  await expect(
    deleteReviewedHost(hostView(), recordOverview(), accept),
  ).rejects.toThrow();
  expect(calls).toHaveLength(1);
  expect(accept).not.toHaveBeenCalled();
});
