import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { recordsPendingMigrationsKey } from "@/lib/records";
import { describe, expect, it, vi } from "vitest";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
import { LegacyPauseReview } from "./LegacyPauseReview";
import {
  MigrationReview,
  MigrationOutcome,
  RecordsMigrationPanel,
} from "./MigrationPanel";
import { migrationPreview } from "./fixtures";
describe("explicit migration review", () => {
  const render = (consent: boolean, eligible = true, consumed = false) => {
    const preview = migrationPreview();
    preview.preview.can_confirm = eligible;
    return renderToStaticMarkup(
      <MigrationReview
        preview={preview}
        consent={consent}
        busy={false}
        consumed={consumed}
        setConsent={vi.fn()}
        confirm={vi.fn()}
      />,
    );
  };
  it("leaves old-client consent unchecked and disables confirmation by default", () => {
    const html = render(false);
    expect(html).toContain('data-state="unchecked"');
    expect(buttonTag(html, "Confirm migration")).toContain(DISABLED);
    expect(text(html)).toContain("old apps");
    expect(text(html)).toContain("2 hosts");
    expect(text(html)).toContain("1 keys");
  });
  it("requires both eligible preview and explicit consent and refuses consumed tokens", () => {
    expect(buttonTag(render(true), "Confirm migration")).not.toContain(
      DISABLED,
    );
    expect(buttonTag(render(true, false), "Confirm migration")).toContain(
      DISABLED,
    );
    expect(buttonTag(render(true, true, true), "Confirm migration")).toContain(
      DISABLED,
    );
  });
  it("shows a partial migration as pending with resume, never completion", () => {
    const html = renderToStaticMarkup(
      <MigrationOutcome
        receipt={{
          migration_id: "a".repeat(32),
          phase: "publishing",
          complete: false,
        }}
        busy={false}
        resume={vi.fn()}
      />,
    );
    expect(text(html)).toContain("Migration pending");
    expect(text(html)).not.toContain("Migration completed");
    expect(text(html)).toContain("Resume migration");
  });
  it("requires saving editor changes before the pause command becomes available", () => {
    const renderPause = (saved: boolean) =>
      renderToStaticMarkup(
        <LegacyPauseReview
          saved={saved}
          busy={false}
          setSaved={vi.fn()}
          confirm={vi.fn()}
          cancel={vi.fn()}
          error={null}
        />,
      );
    expect(buttonTag(renderPause(false), "Pause legacy workspace")).toContain(
      DISABLED,
    );
    expect(
      buttonTag(renderPause(true), "Pause legacy workspace"),
    ).not.toContain(DISABLED);
  });
});

it("offers optional staged-key recovery for a persisted migration without creating a new preview", () => {
  const client = new QueryClient();
  client.setQueryData(recordsPendingMigrationsKey, [
    {
      migration_id: "a".repeat(32),
      phase: "account-gated",
      host_count: 2,
      key_count: 1,
    },
  ]);
  const html = renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <RecordsMigrationPanel />
    </QueryClientProvider>,
  );
  expect(text(html)).toContain("Migration recovery code (optional)");
  expect(text(html)).toContain("original sync code");
  expect(buttonTag(html, "Resume migration")).not.toContain(DISABLED);
  expect(html).toContain('autoComplete="off"');
});
