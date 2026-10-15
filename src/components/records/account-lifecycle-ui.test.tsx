import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RecordsAccountPanel } from "./AccountPanel";
import { recordOverview } from "./fixtures";
import { describe, expect, it, vi } from "vitest";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
import {
  AccountLifecycleReview,
  AccountLeaveOutcome,
  AccountRotationOutcome,
} from "./AccountLifecyclePanel";
describe("explicit account lifecycle consent and outcomes", () => {
  const review = (mode: "leave" | "rotate", consent = false, busy = false) =>
    renderToStaticMarkup(
      <AccountLifecycleReview
        mode={mode}
        consent={consent}
        busy={busy}
        deviceName="Laptop"
        setConsent={vi.fn()}
        setDeviceName={vi.fn()}
        confirm={vi.fn()}
        cancel={vi.fn()}
      />,
    );
  it("requires leave consent and explains saved copies and retained sources", () => {
    const html = review("leave");
    expect(buttonTag(html, "Leave account")).toContain(DISABLED);
    expect(html).toContain('data-state="unchecked"');
    expect(text(html)).toContain("on this device");
    expect(text(html)).toContain("remote");
    expect(text(html)).toContain("passwords");
    expect(buttonTag(review("leave", true), "Leave account")).not.toContain(
      DISABLED,
    );
  });
  it("states that old codes read historical data and requires rotation consent", () => {
    const html = review("rotate");
    expect(buttonTag(html, "Rotate sync code")).toContain(DISABLED);
    expect(text(html)).toContain("historical data");
    expect(text(html)).toContain("rejoin");
    expect(
      buttonTag(review("rotate", true, true), "Rotate sync code"),
    ).toContain(DISABLED);
  });
  it("renders incomplete leave as pending and shows the stable copy mapping", () => {
    const html = renderToStaticMarkup(
      <AccountLeaveOutcome
        receipt={{
          operation_id: "a".repeat(32),
          complete: false,
          copied_hosts: 1,
          mappings: [
            {
              source_space_id: "space",
              source_host_id: "old",
              local_host_id: "new",
              alias: "work",
            },
          ],
          pending_error: "Pending",
        }}
      />,
    );
    expect(text(html)).toContain("Leaving account is pending");
    expect(text(html)).not.toContain("Account left");
    expect(text(html)).toContain("new");
    expect(text(html)).toContain("Retry sync setup");
  });
  it("shows an incomplete rotation honestly and keeps the code in an explicit private field", () => {
    const html = renderToStaticMarkup(
      <AccountRotationOutcome
        words="SECRET fixture new code"
        rotation={{ operation_id: "b".repeat(32), complete: false }}
        busy={false}
        clear={vi.fn()}
      />,
    );
    expect(text(html)).toContain("Sync code rotation is pending");
    expect(text(html)).not.toContain("Sync code rotated");
    expect(html).toContain('readOnly=""');
    expect(text(html)).toContain("historical data");
    expect(buttonTag(html, "I saved the new code")).not.toContain(DISABLED);
  });
});

describe("account workspace lifecycle integration", () => {
  const render = (
    kind: "leave_account" | "rotate_account" | null,
    blocked = false,
  ) =>
    renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <RecordsAccountPanel
          overview={recordOverview({
            account: { chain_id: "c".repeat(64), device_name: "Laptop" },
            shared_writes_blocked: blocked,
            pending_account: kind
              ? { id: "a".repeat(32), kind, phase: "publishing" }
              : null,
          })}
        />
      </QueryClientProvider>,
    );
  it("exposes explicit actions only for an idle joined account", () => {
    expect(buttonTag(render(null), "Leave sync account…")).not.toContain(
      DISABLED,
    );
    expect(buttonTag(render(null), "Rotate sync code…")).not.toContain(
      DISABLED,
    );
    expect(buttonTag(render(null, true), "Rotate sync code…")).toContain(
      DISABLED,
    );
  });
  it("uses generic durable retry for both kinds and avoids a code field for leaving", () => {
    const leaving = render("leave_account");
    expect(text(leaving)).toContain("Resume sync setup");
    expect(buttonTag(leaving, "Leave sync account…")).toContain(DISABLED);
    expect(text(leaving)).not.toContain("Sync code for recovery");
    const rotating = render("rotate_account");
    expect(text(rotating)).toContain("Sync code for recovery");
    expect(buttonTag(rotating, "Rotate sync code…")).toContain(DISABLED);
    expect(buttonTag(rotating, "Show sync code")).toContain(DISABLED);
  });
});
