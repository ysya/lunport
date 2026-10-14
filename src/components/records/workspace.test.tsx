import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import { text } from "@/components/keychain/test-markup";
import { WorkspaceGate } from "./WorkspaceGate";
import { connectSavedHost } from "./operations";
import { hostView, recordOverview, recordsStatus } from "./fixtures";
afterEach(() => vi.unstubAllGlobals());
describe("records workspace mode boundary", () => {
  const render = (status?: ReturnType<typeof recordsStatus>, error = false) => {
    const legacy = vi.fn(() => <p>Legacy mounted</p>);
    const records = vi.fn(() => <p>Records mounted</p>);
    const html = renderToStaticMarkup(
      <WorkspaceGate
        status={status}
        error={error}
        retry={() => {}}
        useLegacy={() => {}}
        legacy={legacy}
        records={records}
      />,
    );
    return { html, legacy, records };
  };
  it("mounts only the records callback for an active records state", () => {
    const result = render(recordsStatus());
    expect(result.legacy).not.toHaveBeenCalled();
    expect(result.records).toHaveBeenCalledOnce();
    expect(text(result.html)).toContain("Records mounted");
  });
  it("never falls through to legacy while loading or failed", () => {
    for (const error of [false, true]) {
      const result = render(undefined, error);
      expect(result.legacy).not.toHaveBeenCalled();
      expect(result.records).not.toHaveBeenCalled();
    }
  });
  it("refuses cached legacy on a failed status refresh", () => {
    const result = render(
      recordsStatus({ format: "legacy", overview: null, legacy_paused: false }),
      true,
    );
    expect(result.legacy).not.toHaveBeenCalled();
    expect(result.records).not.toHaveBeenCalled();
  });
  it("requires explicit use-existing choice for paused legacy and refuses blocked state", () => {
    const paused = render(
      recordsStatus({ format: "legacy", overview: null, legacy_paused: true }),
    );
    expect(paused.legacy).not.toHaveBeenCalled();
    expect(text(paused.html)).toContain("Use existing SSH configuration");
    const blocked = render(
      recordsStatus({
        format: "blocked",
        overview: null,
        blocked_reason: "Invalid state",
      }),
    );
    expect(blocked.legacy).not.toHaveBeenCalled();
    expect(text(blocked.html)).toContain("Invalid state");
    expect(text(blocked.html)).not.toContain("Use existing SSH configuration");
  });
  it("renders the paused migration callback without evaluating legacy config hooks", () => {
    const legacy = vi.fn(() => <p>Legacy mounted</p>);
    const paused = vi.fn(() => <p>Migration landing</p>);
    const html = renderToStaticMarkup(
      <WorkspaceGate
        status={recordsStatus({
          format: "legacy",
          legacy_paused: true,
          overview: null,
        })}
        retry={vi.fn()}
        useLegacy={vi.fn()}
        legacy={legacy}
        records={vi.fn()}
        pausedLegacy={paused}
      />,
    );
    expect(paused).toHaveBeenCalledOnce();
    expect(legacy).not.toHaveBeenCalled();
    expect(text(html)).toContain("Migration landing");
  });
  it("mounts legacy only after its explicit in-memory pause is cleared", () => {
    const result = render(
      recordsStatus({ format: "legacy", overview: null, legacy_paused: false }),
    );
    expect(result.legacy).toHaveBeenCalledOnce();
    expect(result.records).not.toHaveBeenCalled();
  });
  it("does not mount records when its snapshot is missing", () => {
    const result = render(recordsStatus({ overview: null }));
    expect(result.legacy).not.toHaveBeenCalled();
    expect(result.records).not.toHaveBeenCalled();
    expect(text(result.html)).toContain("unavailable");
  });
});
describe("stable-ID connection", () => {
  it("connects the selected ID even when another scope has the same alias", async () => {
    const selected = hostView();
    const second = hostView({
      id: "0000000000000002",
      scope: { kind: "space", space_id: "a".repeat(64) },
    });
    const calls = stubBackend(async () => undefined);
    await connectSavedHost(
      recordOverview({ hosts: [selected, second] }),
      second.id,
      "iterm2",
      true,
    );
    expect(calls).toEqual([
      [
        "records_connect",
        { hostId: second.id, terminalId: "iterm2", newTab: true },
      ],
    ]);
  });
  it("blocks every non-ready route before a launch command", async () => {
    const calls = stubBackend(async () => undefined);
    for (const kind of ["needs_key", "key_conflict", "needs_review"] as const)
      await expect(
        connectSavedHost(
          recordOverview({ hosts: [hostView({ readiness: { kind } })] }),
          hostView().id,
          null,
          false,
        ),
      ).rejects.toThrow();
    expect(calls).toEqual([]);
  });
  it("refuses duplicate or removed IDs without choosing an arbitrary host", async () => {
    const calls = stubBackend(async () => undefined);
    const host = hostView();
    for (const hosts of [
      [],
      [
        host,
        {
          ...host,
          scope: { kind: "space" as const, space_id: "a".repeat(64) },
        },
      ],
    ])
      await expect(
        connectSavedHost(recordOverview({ hosts }), host.id, null, false),
      ).rejects.toThrow();
    expect(calls).toEqual([]);
  });
});
