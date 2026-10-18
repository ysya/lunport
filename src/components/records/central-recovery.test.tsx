import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { CentralRecovery, recoveryCanConfirm } from "./CentralRecovery";
import {
  centralRecoveryKey,
  type CentralRecoveryProgress,
  type CentralStatus,
} from "@/lib/central-sync";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
const status: CentralStatus = {
  available: true,
  configured: true,
  phase: "awaiting_approval",
  service: "https://sync.example.com",
  account_id: "a",
  device_id: "b",
  root_fingerprint: null,
  membership_head: null,
  authorization_epoch: "2",
  has_session: true,
  login_pending: false,
  needs_recovery: false,
  replacement_pending: false,
  can_sync: false,
  pending: 0,
  conflicts: 0,
  error: null,
};
const progress: CentralRecoveryProgress = {
  phase: "backup_required",
  operation: "operation-a",
  backup_confirmed: false,
  verified: 33,
  total: 33,
  root_fingerprint: "root-a",
};
function render(
  partial: Partial<CentralRecoveryProgress> = {},
  scope: CentralStatus = status,
) {
  const client = new QueryClient();
  client.setQueryData(centralRecoveryKey(scope), { ...progress, ...partial });
  const html = renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <CentralRecovery
        status={scope}
        disabled={false}
        update={vi.fn()}
        onBusyChange={vi.fn()}
      />
    </QueryClientProvider>,
  );
  return { html, client };
}
describe("offline recovery consent and reveal boundaries", () => {
  it("requires review of the new kit and explicit device revocation acknowledgement", () => {
    const { html, client } = render();
    expect(text(html)).toContain("removes cloud access for your other devices");
    expect(text(html)).toContain("does not change remote authorized_keys");
    expect(buttonTag(html, "Recover account")).toContain(DISABLED);
    expect(buttonTag(html, "Show new recovery kit")).not.toContain(DISABLED);
    expect(html).not.toContain('aria-label="New offline recovery kit"');
    expect(
      JSON.stringify(
        client
          .getQueryCache()
          .getAll()
          .map((query) => query.state.data),
      ),
    ).not.toContain("kit");
    expect(html).not.toContain("Download");
  });
  it("refuses missing acknowledgement, a different root and non-backup phases", () => {
    expect(recoveryCanConfirm(progress, true, "root-a")).toBe(true);
    expect(recoveryCanConfirm(progress, false, "root-a")).toBe(false);
    expect(recoveryCanConfirm(progress, true, null)).toBe(false);
    expect(recoveryCanConfirm(progress, true, "another-root")).toBe(false);
    expect(
      recoveryCanConfirm({ ...progress, operation: null }, true, "root-a"),
    ).toBe(false);
    expect(
      recoveryCanConfirm({ ...progress, phase: "submitted" }, true, "root-a"),
    ).toBe(false);
  });
  it("retains an acknowledged backup after explicit revalidation", () => {
    const acknowledged = { ...progress, backup_confirmed: true };
    expect(recoveryCanConfirm(acknowledged, false, null)).toBe(true);
    expect(
      recoveryCanConfirm({ ...acknowledged, phase: "reading" }, false, null),
    ).toBe(false);
    const { html } = render({ backup_confirmed: true });
    expect(buttonTag(html, "Recover account")).not.toContain(DISABLED);
    expect(text(html)).toContain("without backing it up again");
    expect(buttonTag(html, "Revalidate recovery")).not.toContain(DISABLED);
    expect(html).toContain('aria-label="Current recovery kit (optional)"');
    expect(html).not.toContain('type="checkbox"');
  });
  it("shows submitted recovery as resumable without revealing credentials again", () => {
    const { html } = render({ phase: "submitted" });
    expect(buttonTag(html, "Resume recovery")).not.toContain(DISABLED);
    expect(html).not.toContain("Show new recovery kit");
    expect(html).not.toContain("LPREC2:");
    expect(
      buttonTag(
        render({ phase: "submitted" }, { ...status, has_session: false }).html,
        "Resume recovery",
      ),
    ).toContain(DISABLED);
  });
  it("keeps cleanup separate from cloud authentication and scopes progress to the current owner", () => {
    expect(
      buttonTag(
        render({ phase: "cleanup_required" }, { ...status, has_session: false })
          .html,
        "Finish recovery",
      ),
    ).not.toContain(DISABLED);
    expect(centralRecoveryKey(status)).not.toEqual(
      centralRecoveryKey({ ...status, device_id: "other-device" }),
    );
    expect(centralRecoveryKey(status)).not.toEqual(
      centralRecoveryKey({ ...status, authorization_epoch: "3" }),
    );
  });
});
