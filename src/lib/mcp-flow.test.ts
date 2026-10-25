import { describe, expect, it } from "vitest";
import { chooseMcpMode, receiveAuthQuestion, authRemaining, takeAuthAnswer, grantFields, encodeGrantAnswer, grantAnswerReady } from "./mcp-flow";
import type { AuthRequest } from "@/bindings/AuthRequest";

const question: AuthRequest = {
  id: "q1", request_id: "exec1", hop: null, kind: "password",
  text: "Password:", echo: false, remaining_ms: 1000, grant: null,
};

describe("MCP mode changes", () => {
  it("does not enable Auto-log until concrete risk is acknowledged, while Ask is immediate", () => {
    const applied: unknown[] = [];
    const apply = (mode: string, ack: boolean) => applied.push([mode, ack]);
    expect(chooseMcpMode("auto_log", false, apply)).toBe(true);
    expect(applied).toEqual([]);
    chooseMcpMode("auto_log", true, apply);
    chooseMcpMode("ask", false, apply);
    expect(applied).toEqual([["auto_log", true], ["ask", false]]);
  });
});

describe("native authentication answers", () => {
  it("expires on either clock and clears an answer before it can be submitted", () => {
    const state = receiveAuthQuestion(question, { wall: 100, monotonic: 10 });
    state.answer = "private test value";
    expect(authRemaining(state, { wall: 1100, monotonic: 20 })).toBe(0);
    expect(takeAuthAnswer(state, { wall: 1100, monotonic: 20 })).toBeNull();
    expect(state.answer).toBe("");
    expect(state.abandoned).toBe(true);
  });

  it("clears a secret as soon as a refreshed native snapshot has expired", () => {
    const state = receiveAuthQuestion(question, { wall: 0, monotonic: 0 });
    state.answer = "previous secret";
    const expired = receiveAuthQuestion({ ...question, remaining_ms: 0 }, { wall: 50, monotonic: 50 }, state);
    expect(expired.answer).toBe("");
    expect(expired.abandoned).toBe(true);
  });

  it("does not extend the deadline when a question snapshot refreshes or wall time moves backwards", () => {
    const state = receiveAuthQuestion(question, { wall: 100, monotonic: 10 });
    state.answer = "answer";
    const refreshed = receiveAuthQuestion({ ...question, remaining_ms: 1000 }, { wall: 500, monotonic: 410 }, state);
    expect(authRemaining(refreshed, { wall: 0, monotonic: 1010 })).toBe(0);
    expect(refreshed.answer).toBe("answer");
  });

  it("clears prior answers on a new question and abandons a submitted answer to prevent replay", () => {
    const state = receiveAuthQuestion(question, { wall: 0, monotonic: 0 });
    state.answer = "answer";
    expect(receiveAuthQuestion({ ...question, id: "q2" }, { wall: 0, monotonic: 0 }, state).answer).toBe("");
    expect(takeAuthAnswer(state, { wall: 1, monotonic: 1 })).toBe("answer");
    expect(state.answer).toBe("");
    expect(takeAuthAnswer(state, { wall: 2, monotonic: 2 })).toBeNull();
  });
});

describe("grant questions", () => {
  const now = { wall: 0, monotonic: 0 };
  const grant: AuthRequest = {
    ...question, id: "g1", kind: "grant", echo: true, remaining_ms: 400000,
    text: "No active Privileged Access Manager grant for prod-operate on knowknow-prod.",
    grant: { project: "knowknow-prod", entitlement: "prod-operate", minutes: 30, justification: "restart app-api" },
  };

  it("waits up to five minutes for a grant request, two for a server's question", () => {
    expect(authRemaining(receiveAuthQuestion(grant, now), now)).toBe(300000);
    expect(authRemaining(receiveAuthQuestion({ ...question, remaining_ms: 400000 }, now), now)).toBe(120000);
    expect(authRemaining(receiveAuthQuestion({ ...grant, remaining_ms: 1000 }, now), now)).toBe(1000);
  });

  it("starts the form from the stored justification and duration, and keeps both fields in the one answer", () => {
    expect(receiveAuthQuestion(grant, now).answer).toBe("30\nrestart app-api");
    expect(receiveAuthQuestion({ ...grant, grant: { ...grant.grant!, justification: null } }, now).answer).toBe("30\n");
    expect(receiveAuthQuestion(question, now).answer).toBe("");
    expect(grantFields("30\nrestart app-api")).toEqual({ minutes: "30", justification: "restart app-api" });
    expect(grantFields("")).toEqual({ minutes: "", justification: "" });
    expect(encodeGrantAnswer("45", "restart app-api")).toBe("45\nrestart app-api");
  });

  it("lets Request go only with whole minutes from 1 to 480 and a justification with something in it", () => {
    expect(grantAnswerReady("30\nrestart app-api")).toBe(true);
    expect(grantAnswerReady("480\nx")).toBe(true);
    for (const answer of ["0\nx", "481\nx", "30\n", "30\n   ", "abc\nx", "30.5\nx", "-1\nx", "", "30"]) {
      expect(grantAnswerReady(answer), JSON.stringify(answer)).toBe(false);
    }
  });
});
