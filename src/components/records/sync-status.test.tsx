import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { text } from "@/components/keychain/test-markup";
import { RecordSyncStatus } from "./SyncStatus";
describe("records sync status", () => {
  it("makes retained conflicts visible ahead of pending changes and last sync", () => {
    const html = renderToStaticMarkup(<RecordSyncStatus lastSyncMs={1700000000000} error={null} pendingChanges={3} conflicts={2} />);
    expect(text(html)).toContain("2 saved sync conflicts need review");
    expect(text(html)).not.toContain("Last sync:");
  });
  it("shows real activity and retains the previous failure without raising a new alert", () => {
    const html = renderToStaticMarkup(
      <RecordSyncStatus
        lastSyncMs={null}
        error="Relay unavailable"
        syncing
        pending
      />,
    );
    expect(text(html)).toContain("Setting up sync…");
    expect(text(html)).toContain("Previous attempt");
    expect(text(html)).toContain("Relay unavailable");
    expect(html).not.toContain('role="alert"');
    expect(html).not.toContain("text-destructive");
  });
  it("shows the failure as an alert once the attempt ends", () => {
    const html = renderToStaticMarkup(
      <RecordSyncStatus
        lastSyncMs={null}
        error="Relay unavailable"
        syncing={false}
      />,
    );
    expect(html).toContain('role="alert"');
  });
  it("shows queued offline changes instead of implying the last sync includes them", () => {
    const html = renderToStaticMarkup(
      <RecordSyncStatus
        lastSyncMs={1700000000000}
        error={null}
        pendingChanges={3}
      />,
    );
    expect(text(html)).toContain("3 changes saved, waiting to sync");
    expect(text(html)).not.toContain("Last sync:");
  });
  it("does not imply failed sync when this device only has local data", () => {
    const html = renderToStaticMarkup(
      <RecordSyncStatus lastSyncMs={null} error={null} connected={false} />,
    );
    expect(text(html)).toContain("Sync not set up");
    expect(text(html)).not.toContain("Not synced yet");
  });
  it("distinguishes an incomplete setup from an account waiting for sync", () => {
    const html = renderToStaticMarkup(
      <RecordSyncStatus
        lastSyncMs={null}
        error={null}
        connected={false}
        pending
      />,
    );
    expect(text(html)).toContain("Sync setup pending");
    expect(text(html)).not.toContain("Sync not set up");
  });
  it("shows the saved last sync timestamp and public error independently", () => {
    const html = renderToStaticMarkup(
      <RecordSyncStatus lastSyncMs={1700000000000} error="Relay unavailable" />,
    );
    expect(html).toContain('dateTime="2023-11-14T22:13:20.000Z"');
    expect(text(html)).toContain("Last sync:");
    expect(text(html)).toContain("Relay unavailable");
  });
  it("handles never-synced and invalid dates without a render failure", () => {
    expect(
      text(
        renderToStaticMarkup(
          <RecordSyncStatus lastSyncMs={null} error={null} />,
        ),
      ),
    ).toContain("Not synced yet");
    expect(
      text(
        renderToStaticMarkup(
          <RecordSyncStatus lastSyncMs={18446744073709551615} error={null} />,
        ),
      ),
    ).toContain("Last sync time unavailable");
  });
  it("makes hidden control characters visible in public sync errors", () => {
    const html = renderToStaticMarkup(
      <RecordSyncStatus lastSyncMs={null} error={"Relay\u202e\u200b"} />,
    );
    expect(html).not.toContain("\u202e");
    expect(html).not.toContain("\u200b");
    expect(text(html)).toContain("Relay");
  });
});
