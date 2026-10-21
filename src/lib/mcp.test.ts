import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuthRequest } from "@/bindings/AuthRequest";
import type { McpStatus } from "@/bindings/McpStatus";
import { renderHook, stubBackend } from "./test-ipc";
import { useSetMcpApprovalMode, useSetMcpGroupAllowed, mcpStatusKey } from "./mcp";
import { resolveAuthentication, followAuthentication } from "./authentication";

const eventSource = vi.hoisted(() => ({
  handler: null as null | ((event: { payload: AuthRequest[] }) => void),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: async (_name: string, handler: typeof eventSource.handler) => {
    eventSource.handler = handler;
    return () => { eventSource.handler = null; };
  },
}));
afterEach(() => {
  vi.unstubAllGlobals();
  eventSource.handler = null;
});

const question = (id: string): AuthRequest => ({
  id, request_id: "exec1", hop: null, kind: "password",
  text: "Password:", echo: false, remaining_ms: 1000,
});

describe("native MCP frontend boundary", () => {
  it("sends an explicit risk acknowledgment to native mode change and reflects returned policy", async () => {
    const result: McpStatus = {
      approval_mode: "auto_log", enabled: true, bridge_active: true,
      noninteractive_credentials_supported: false,
      noninteractive_credentials_notice: "Use Ask for stored credentials.",
      audit_error: null, allowed_hosts: [], allowed_groups: [], pending: [], recent: [],
      executable: "/fixture/sshelter", last_client_at_ms: null,
    };
    const calls = stubBackend(async () => result);
    const client = new QueryClient();
    const mutation = renderHook(client, useSetMcpApprovalMode);
    await mutation.mutateAsync({ approvalMode: "auto_log", riskAcknowledged: true });
    expect(calls).toEqual([["mcp_set_approval_mode", { approvalMode: "auto_log", riskAcknowledged: true }]]);
    expect(client.getQueryData(mcpStatusKey)).toEqual(result);
  });

  it("sends the explicit Group and scope instead of expanding to host grants", async () => {
    const result = { allowed_hosts: [], allowed_groups: ["space/fixture/group-1"] };
    const calls = stubBackend(async () => result);
    const client = new QueryClient();
    const mutation = renderHook(client, useSetMcpGroupAllowed);
    await mutation.mutateAsync({ groupId: "group-1", scope: { kind: "space", space_id: "fixture" }, generation: "9007199254740993", allowed: true });
    expect(calls).toEqual([["mcp_set_group_allowed", { groupId: "group-1", scope: { kind: "space", space_id: "fixture" }, generation: "9007199254740993", allowed: true }]]);
    expect(client.getQueryData(mcpStatusKey)).toEqual(result);
  });

  it("sends cancellation as null with the native question ID, not execution ID", async () => {
    const calls = stubBackend(async () => undefined);
    await resolveAuthentication("question-2", null);
    expect(calls).toEqual([["auth_resolve", { requestId: "question-2", value: null }]]);
  });

  it("does not restore an older pending fetch over a newer native event", async () => {
    let finish!: (value: unknown) => void;
    stubBackend(() => new Promise(resolve => { finish = resolve; }));
    const lists: unknown[] = [];
    const stop = followAuthentication(
      list => lists.push(list.map(snapshot => snapshot.request.id)),
      () => { throw Error("unexpected failure"); },
    );
    await Promise.resolve();
    await Promise.resolve();
    eventSource.handler!({ payload: [question("new-question")] });
    finish([question("old-question")]);
    await Promise.resolve();
    await Promise.resolve();
    expect(lists).toEqual([["new-question"]]);
    stop();
  });
});
