import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { text } from "@/components/keychain/test-markup";
import { RecordSyncStatus } from "./SyncStatus";
describe("records sync status", () => {
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
