import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
import { RecordHostEditor } from "./HostEditor";
import { RecordHostList } from "./HostList";
import { RecordsKeysPanel } from "./KeysPanel";
import { RecordsAccountPanel } from "./AccountPanel";
import { ImportReview } from "./ImportPanel";
import {
  hostPayload,
  hostView,
  importPreview,
  recordOverview,
} from "./fixtures";
const render = (node: ReactNode) =>
  renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      {node}
    </QueryClientProvider>,
  );
const editor = (
  host: ReturnType<typeof hostView> | null,
  hostId: string | null = host?.id ?? null,
) =>
  render(
    <RecordHostEditor
      host={host}
      hostId={hostId}
      overview={recordOverview({ hosts: host ? [host] : [] })}
      terminalId={null}
      newTab={false}
      accept={(overview) => overview}
      onSaved={() => {}}
      onDeleted={() => {}}
      onDirty={() => {}}
    />,
  );
describe("records host controls", () => {
  it("starts new hosts in the library and disables connect until a persisted host exists", () => {
    const html = editor(null);
    expect(text(html)).toContain("New host");
    expect(text(html)).toContain("Library");
    expect(text(html)).not.toContain("Save in");
    expect(buttonTag(html, "Connect")).toContain(DISABLED);
    expect(buttonTag(html, "Create host")).toContain(DISABLED);
    expect(html).not.toContain("Pinned host key");
    expect(text(html)).toContain("Not saved yet");
    expect(text(html)).not.toContain(" · Saved");
  });
  it("shows blocked readiness and never enables a missing-key connection", () => {
    const html = editor(
      hostView({
        readiness: { kind: "needs_key", key_id: "a".repeat(32) },
        payload: hostPayload({ auth: "key", key_id: "a".repeat(32) }),
      }),
    );
    expect(text(html)).toContain("Needs key");
    expect(buttonTag(html, "Connect")).toContain(DISABLED);
    expect(text(html)).toContain("Missing key");
  });
  it("does not turn a removed or conflicting selected ID into a new-host form", () => {
    const html = editor(null, hostView().id);
    expect(text(html)).not.toContain("Create host");
    expect(text(html)).toContain("unavailable");
    expect(buttonTag(html, "Connect")).toContain(DISABLED);
  });
  it("shows all storage scopes in one library for duplicate aliases and a conflict for duplicate IDs", () => {
    const first = hostView();
    const second = hostView({
      id: "0000000000000002",
      scope: { kind: "space", space_id: "a".repeat(64) },
    });
    const overview = recordOverview({
      hosts: [first, second],
      spaces: [
        { id: "a".repeat(64), name: "Team", selected: true, missing: false },
      ],
    });
    const html = render(
      <RecordHostList
        overview={overview}
        selectedId={second.id}
        select={vi.fn()}
      />,
    );
    expect(text(html)).not.toContain("Local");
    expect(text(html)).not.toContain("Team");
    expect((text(html).match(/web/g) ?? []).length).toBe(2);
    expect(html).toContain('aria-pressed="true"');
    const conflict = render(
      <RecordHostList
        overview={{ ...overview, hosts: [first, { ...second, id: first.id }] }}
        selectedId={first.id}
        select={vi.fn()}
      />,
    );
    expect(text(conflict)).toContain("Conflicting host ID");
  });
});
describe("explicit import consent and key/account controls", () => {
  it("leaves every optional key copy unchecked despite will_copy metadata", () => {
    const preview = importPreview();
    preview.preview.key_references[0].will_copy = true;
    const html = render(
      <ImportReview
        preview={preview}
        copies={[]}
        setCopies={vi.fn()}
        busy={false}
      />,
    );
    expect(html).toContain('data-state="unchecked"');
    expect(html).not.toContain('data-state="checked"');
    expect(text(html)).toContain("Source files remain in place");
  });
  it("disables unresolved copy candidates and preserves warning locations", () => {
    const preview = importPreview();
    preview.preview.key_references[0].resolved_path = null;
    preview.preview.warnings = [
      {
        location: { path: "/fixture/config", line: 8 },
        keyword: "Match",
        reason: "Unsupported directive",
        blocks_connection: true,
        alias: "web",
      },
    ];
    const html = render(
      <ImportReview
        preview={preview}
        copies={[]}
        setCopies={vi.fn()}
        busy={false}
      />,
    );
    expect(html).toContain(DISABLED);
    expect(text(html)).toContain("/fixture/config:8");
    expect(text(html)).toContain("Unresolved key path");
  });
  it("offers an explicit synced-key download and refuses conflicting material", () => {
    const key = {
      id: "a".repeat(32),
      authority: "account" as const,
      synced: true,
      public: null,
      status: "needs_material" as const,
    };
    const html = render(
      <RecordsKeysPanel overview={recordOverview({ keys: [key] })} />,
    );
    expect(text(html)).toContain("Download synced key");
    const conflict = render(
      <RecordsKeysPanel
        overview={recordOverview({ keys: [{ ...key, status: "conflict" }] })}
      />,
    );
    expect(text(conflict)).not.toContain("Download synced key");
    expect(text(conflict)).toContain("metadata conflict");
  });
  it("offers sync again when account metadata survives an unpublished private key", () => {
    const key = {
      id: "a".repeat(32),
      authority: "account" as const,
      synced: false,
      public: null,
      status: "available" as const,
    };
    const html = render(
      <RecordsKeysPanel
        overview={recordOverview({
          keys: [key],
          account: { chain_id: "b".repeat(64), device_name: "Laptop" },
        })}
      />,
    );
    expect(buttonTag(html, "Sync key")).not.toContain(DISABLED);
    expect(text(html)).not.toContain("Stop syncing");
    expect(text(html)).toContain("Account key");
    expect(text(html)).not.toContain("Synced key");
  });
  it("disables sync toggling when authenticated sync status is unknown", () => {
    const key = {
      id: "a".repeat(32),
      authority: "account" as const,
      synced: null,
      public: null,
      status: "available" as const,
    };
    const html = render(
      <RecordsKeysPanel
        overview={recordOverview({
          keys: [key],
          account: { chain_id: "b".repeat(64), device_name: "Laptop" },
        })}
      />,
    );
    expect(buttonTag(html, "Sync state unavailable")).toContain(DISABLED);
    expect(text(html)).not.toContain("Stop syncing");
  });
  it("offers stop only for an explicitly enabled key without implying relay delivery", () => {
    const key = {
      id: "a".repeat(32),
      authority: "account" as const,
      synced: true,
      public: null,
      status: "available" as const,
    };
    const html = render(
      <RecordsKeysPanel
        overview={recordOverview({
          keys: [key],
          account: { chain_id: "b".repeat(64), device_name: "Laptop" },
        })}
      />,
    );
    expect(buttonTag(html, "Stop syncing")).not.toContain(DISABLED);
    expect(text(html)).toContain("Sync enabled");
    expect(text(html)).toContain("waiting for the relay");
  });
  it("keeps shared account controls disabled while shared writes are gated", () => {
    const html = render(
      <RecordsAccountPanel
        overview={recordOverview({ shared_writes_blocked: true })}
      />,
    );
    expect(buttonTag(html, "Create sync chain")).toContain(DISABLED);
    expect(buttonTag(html, "Join with sync code")).toContain(DISABLED);
    expect(text(html)).toContain("Sync changes are paused");
  });
});
