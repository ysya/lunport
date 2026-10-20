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
describe("central account setup safety boundaries", () => {
  it("keeps sign-in and library consent separate", () => {
    const html = render();
    expect(text(html)).toContain("separate whole-library review");
    expect(buttonTag(html, "Set up encrypted Vault")).not.toContain(DISABLED);
    expect(html).not.toContain("LPREC2:");
  });
  it("requires an explicit backup acknowledgement and does not reveal secrets in status", () => {
    const html = render({
      phase: "backup_required",
      root_fingerprint: "c".repeat(64),
    });
    expect(buttonTag(html, "Finish Vault setup")).toContain(DISABLED);
    expect(text(html)).toContain("Anyone with the kit can recover");
    expect(html).not.toContain('aria-label="Offline recovery kit"');
    expect(html).not.toContain("Download private key");
  });
  it("keeps an existing active vault locked when device credentials are unavailable", () => {
    const html = render({ needs_recovery: true, has_session: false });
    expect(text(html)).toContain("Sign-in alone cannot unlock it");
    expect(html).not.toContain("Set up encrypted Vault");
  });
  it("provides cancellation while the system browser is waiting", () => {
    const html = render({ login_pending: true });
    expect(buttonTag(html, "Cancel sign-in")).not.toContain(DISABLED);
    expect(html).not.toContain("Sign in with browser");
  });
});

it("shows pairing as an explicit short-lived reveal on the waiting device", () => {
  const html = render({ phase: "awaiting_approval" });
  expect(buttonTag(html, "Show pairing code")).not.toContain(DISABLED);
  expect(html).not.toContain('aria-label="Device pairing code"');
});

it("offers optional external sign-in only before an account is pinned", () => {
  const first = render({
    configured: false,
    has_session: false,
    phase: "signed_out",
  });
  expect(text(first)).toContain("Sign in with Passkey");
  expect(text(first)).toContain("Use external sign-in provider");
  expect(text(render())).not.toContain("Use external sign-in provider");
  expect(
    text(render({ configured: false, login_pending: true })),
  ).not.toContain("Use external sign-in provider");
});

it("starts with a blank server and requires a user-deployed service before sign-in", () => {
  const html = render({ configured: false, has_session: false, phase: "signed_out", service: null });
  expect(html).toContain('value=""');
  expect(buttonTag(html, "Sign in with Passkey")).toContain(DISABLED);
  expect(text(html)).toContain("Deploy your own sync server");
  expect(text(html)).toContain("Account and encrypted sync");
  expect(text(html)).not.toContain("Preview");
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
  expect(buttonTag(html,"Sign in again")).toContain(DISABLED);
  expect(text(html)).toContain("empty local library");
  expect(text(html)).toContain("Open terminal sessions will close");
  expect(text(html)).not.toContain("Join with sync code");
});


it("lets a first-time local library sign in to the typed server without resetting that library", () => {
  vi.mocked(useState).mockReturnValueOnce(["https://selfhost.example.com", vi.fn()]);
  const html=render({service:null,configured:false,has_session:false,phase:"signed_out"});
  expect(buttonTag(html,"Sign in with Passkey")).not.toContain(DISABLED);
  expect(text(html)).not.toContain("Change server and restart");
});
