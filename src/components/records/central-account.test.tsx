import { renderToStaticMarkup } from "react-dom/server";
import { describe, it, expect, vi } from "vitest";
import { CentralAccountPanel } from "./CentralAccountPanel";
import type { CentralStatus } from "@/lib/central-sync";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
const base: CentralStatus = {
  available: true,
  configured: true,
  phase: "setup",
  service: "https://sync.example.com",
  account_id: "a".repeat(64),
  device_id: "b".repeat(32),
  root_fingerprint: null,
  has_session: true,
  login_pending: false,
  needs_recovery: false,
  can_sync: false,
  pending: 0,
  conflicts: 0,
  error: null,
};
const render = (patch: Partial<CentralStatus> = {}) =>
  renderToStaticMarkup(
    <CentralAccountPanel status={{ ...base, ...patch }} update={vi.fn()} />,
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
