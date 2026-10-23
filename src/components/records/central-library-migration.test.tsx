import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import {
  CentralLibraryMigration,
  LibraryReviewDetails,
  libraryCanConfirm,
} from "./CentralLibraryMigration";
import {
  migrationKey,
  type LibraryReview,
  type MigrationProgress,
} from "@/lib/central-migration";
import type { CentralStatus } from "@/lib/central-sync";
import { text } from "@/components/keychain/test-markup";
const status: CentralStatus = {
  available: true,
  configured: true,
  phase: "enrolled",
  service: "https://sync.test",
  account_id: "account",
  device_id: "device",
  root_fingerprint: "root",
  membership_head: "head",
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
const progress: MigrationProgress = {
  phase: "review",
  mode: "publish",
  legacy_sources: false,
  total: 10,
  staged: 0,
  verified: 0,
  approved: false,
};
const review: LibraryReview = {
  ticket: "a".repeat(64),
  approved: false,
  summary: {
    hosts: 2,
    groups: 1,
    collections: 2,
    history_records: 10,
    private_key_versions: 2,
    key_versions: [
      {
        name: "Work key",
        fingerprint: "SHA256:public",
        key_type: "ssh-ed25519",
        has_passphrase: true,
        storage: "managed",
        retained: false,
      },
      {
        name: "Old security key",
        fingerprint: "SHA256:hardware",
        key_type: "sk-ssh-ed25519",
        has_passphrase: false,
        storage: "hardware",
        retained: true,
      },
    ],
  },
};
function render(partial: Partial<MigrationProgress> = {}, scope = status) {
  const client = new QueryClient();
  client.setQueryData(migrationKey(scope), { ...progress, ...partial });
  return {
    client,
    html: renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <CentralLibraryMigration
          status={scope}
          disabled={false}
          update={vi.fn()}
          onBusyChange={vi.fn()}
        />
      </QueryClientProvider>,
    ),
  };
}
describe("whole-library review and continuation", () => {
  it("requires the displayed exact pending review and one explicit acknowledgement", () => {
    expect(libraryCanConfirm(progress, review, true)).toBe(true);
    expect(libraryCanConfirm({ ...progress, legacy_sources: true }, review, true)).toBe(false);
    expect(libraryCanConfirm(progress, review, false)).toBe(false);
    expect(libraryCanConfirm(progress, null, true)).toBe(false);
    expect(
      libraryCanConfirm(progress, { ...review, ticket: "invalid" }, true),
    ).toBe(false);
    expect(
      libraryCanConfirm({ ...progress, phase: "staging" }, review, true),
    ).toBe(false);
    expect(
      libraryCanConfirm({ ...progress, approved: true }, review, true),
    ).toBe(false);
    expect(
      libraryCanConfirm(progress, { ...review, approved: true }, true),
    ).toBe(false);
  });
  it("shows public metadata and retained versions without per-key sharing or export controls", () => {
    const html = renderToStaticMarkup(<LibraryReviewDetails review={review} />);
    expect(text(html)).toContain("2 managed private key versions");
    expect(text(html)).toContain("retained version");
    expect(text(html)).toContain("Hardware key reference");
    expect(text(html)).toContain(
      "Key passphrases stay on this device",
    );
    expect(html).not.toMatch(
      /type="checkbox"|Download|Export private|This device only|local.only|inventory_digest/,
    );
    expect(html).not.toContain(review.ticket);
  });
  it("keeps pending review details out of the progress query cache", () => {
    const { client, html } = render();
    expect(text(html)).toContain("Review complete library");
    expect(text(html)).toContain("Original local data and saved progress are retained");
    const cache = JSON.stringify(
      client
        .getQueryCache()
        .getAll()
        .map((query) => query.state.data),
    );
    expect(cache).not.toContain(review.ticket);
    expect(cache).not.toContain("key_versions");
    expect(
      text(
        render({ phase: "reading", approved: true, staged: 10, verified: 4 })
          .html,
      ),
    ).toContain("10 of 10 records staged · 4 verified by readback");
  });
  it("blocks a saved setup that still depends on the retired chain service", () => {
    const html = render({ legacy_sources: true }).html;
    expect(text(html)).toContain("cannot continue");
    expect(text(html)).toContain("local files are retained");
    expect(text(html)).not.toContain("Review complete library");
  });
  it("lets approved joiners prepare a verified merge of their local data", () => {
    const html = render({ mode: "join", phase: "waiting" }).html;
    expect(text(html)).toContain("Connect this device");
    expect(text(html)).toContain("separate merge before upload");
    expect(text(html)).toContain("Continue preparing");
  });
  it("offers reviewed history reconciliation for an active replacement and hides it after completion", () => {
    const current = { ...status, phase: "active" as const, needs_reconciliation: true };
    const html = render({ mode: "join", phase: "review" }, current).html;
    expect(text(html)).toContain("Reconcile restored library");
    expect(text(html)).toContain("Original files stay preserved");
    expect(text(html)).toContain("Review complete library");
    expect(render({}, { ...current, needs_reconciliation: false }).html).toBe("");
    expect(render({}, { ...current, needs_recovery: true }).html).toBe("");
  });
  it("hides migration actions for an unapproved, signed-out or replacement device", () => {
    for (const partial of [
      { has_session: false },
      { needs_recovery: true },
      { replacement_pending: true },
      { phase: "awaiting_approval" as const },
    ])
      expect(render({}, { ...status, ...partial }).html).toBe("");
  });
});
