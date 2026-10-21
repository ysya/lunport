import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, it, expect, vi } from "vitest";
import { CentralAccountPanel, CentralAccountSection } from "./CentralAccountPanel";
import { centralStatusKey, type CentralStatus } from "@/lib/central-sync";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
vi.mock("react", async (original) => {
  const actual = await original<typeof import("react")>();
  return { ...actual, useState: vi.fn(actual.useState) };
});
const base: CentralStatus = {
  available: true,
  configured: true,
  phase: "setup",
  service: "https://sync.example.com",
  account_id: "a".repeat(64),
  device_id: "b".repeat(32),
  root_fingerprint: null,
  membership_head: null,
  authorization_epoch: "1",
  has_session: true,
  login_pending: false,
  needs_recovery: false,
  replacement_pending: false,
  needs_reconciliation: false,
  can_sync: false,
  pending: 0,
  conflicts: 0,
  error: null,
};
const render = (patch: Partial<CentralStatus> = {}) =>
  renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <CentralAccountPanel status={{ ...base, ...patch }} update={vi.fn()} />
    </QueryClientProvider>,
  );
describe("automatic encrypted sync", () => {
  it("uses one password setup instead of manual Vault and library steps", () => {
    const html=render();
    expect(text(html)).toContain("Sync unlock password");
    expect(text(html)).toContain("Confirm sync unlock password");
    expect(buttonTag(html,"Set password and sync")).toContain(DISABLED);
    expect(text(html)).toContain("never sent to your server");
    expect(text(html)).not.toContain("Set up encrypted Vault");
    expect(text(html)).not.toContain("whole-library review");
    expect(html).not.toContain("LPREC2:");
  });
  it("resumes interrupted setup through the same password form", () => {
    const html=render({phase:"backup_required",root_fingerprint:"c".repeat(64)});
    expect(text(html)).toContain("Set password and sync");
    expect(text(html)).not.toContain("Finish Vault setup");
    expect(html).not.toContain('aria-label="Offline recovery kit"');
  });
  it("asks a new device to unlock without exposing a pairing code", () => {
    const html=render({phase:"awaiting_approval"});
    expect(text(html)).toContain("password you set on your first device");
    expect(buttonTag(html,"Unlock and sync")).toContain(DISABLED);
    expect(text(html)).not.toContain("Show pairing code");
    expect(text(html)).not.toContain("Confirm sync unlock password");
  });
  it("requires sign-in again when the session is unavailable", () => {
    const html=render({has_session:false});
    expect(text(html)).toContain("Sign in again to resume automatic sync");
    expect(buttonTag(html,"Sign in again")).not.toContain(DISABLED);
    expect(text(html)).not.toContain("Set password and sync");
  });
  it("keeps credential recovery separate from creating a fresh encrypted root", () => {
    const html=render({needs_recovery:true,has_session:false});
    expect(text(html)).toContain("Sync needs your attention");
    expect(text(html)).not.toContain("Set password and sync");
  });
  it("offers cancellation while waiting for browser authorization", () => {
    expect(buttonTag(render({login_pending:true}),"Cancel sign-in")).not.toContain(DISABLED);
  });
});
it("starts with a blank user-deployed server and explicit whole-library sign-in consent", () => {
  const html=render({configured:false,has_session:false,phase:"signed_out",service:null});
  expect(html).toContain('value=""');
  expect(buttonTag(html,"Sign in and sync with Passkey")).toContain(DISABLED);
  expect(text(html)).toContain("Deploy your own sync server");
  expect(text(html)).toContain("all managed SSH private keys");
  expect(text(html)).not.toContain("lunport.ysya.me");
});

it("explains unavailable platform support without offering a broken sign-in flow", () => {
  const client = new QueryClient();
  client.setQueryData(centralStatusKey, { ...base, available: false, configured: false });
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><CentralAccountSection /></QueryClientProvider>);
  expect(text(html)).toContain("Central account sync is unavailable in this build");
  expect(text(html)).toContain("Your local library remains available without signing in");
  expect(text(html)).not.toContain("Older sync-code libraries");
  expect(text(html)).not.toContain("Sign in with Passkey");
});


it("requires applying a changed server before login and explains the empty library and restart", () => {
  vi.mocked(useState).mockReturnValueOnce(["https://other.example.com", vi.fn()]);
  const html=render();
  expect(buttonTag(html,"Change server and restart")).not.toContain(DISABLED);
  expect(text(html)).not.toContain("Set password and sync");
  expect(text(html)).toContain("empty local library");
  expect(text(html)).toContain("Open terminal sessions will close");
  expect(text(html)).not.toContain("Join with sync code");
});


it("lets a first-time local library sign in to the typed server without resetting that library", () => {
  vi.mocked(useState).mockReturnValueOnce(["https://selfhost.example.com", vi.fn()]);
  const html=render({service:null,configured:false,has_session:false,phase:"signed_out"});
  expect(buttonTag(html,"Sign in and sync with Passkey")).not.toContain(DISABLED);
  expect(text(html)).not.toContain("Change server and restart");
});

it("offers a separate fresh workspace for a new account while a signed-out library remains account-bound", () => {
  const html=render({has_session:false,phase:"signed_out"});
  expect(buttonTag(html,"Start with a new account and restart")).not.toContain(DISABLED);
  expect(text(html)).toContain("open an empty local library");
  expect(text(html)).toContain("open terminal sessions close");
  expect(text(render({has_session:true}))).not.toContain("Start with a new account and restart");
});
