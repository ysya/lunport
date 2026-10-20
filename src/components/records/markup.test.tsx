import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { useState, type ReactNode } from "react";
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
vi.mock("react", async (original) => {
  const actual = await original<typeof import("react")>();
  return { ...actual, useState: vi.fn(actual.useState) };
});
// Render the selected state for the existing action/consent assertions below.
// The real collection now starts closed; its default state is tested separately.
function SelectedKeysPanel(props: Parameters<typeof RecordsKeysPanel>[0]) {
  vi.mocked(useState).mockReturnValueOnce([props.overview.keys[0]?.id ?? null, vi.fn()]);
  return <RecordsKeysPanel {...props} />;
}
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
  it("presents a duplicate as an editable new host without the source identity or credential status", () => {
    const source = hostView({ payload: hostPayload({ alias: "template", hostname: "template.invalid", user: "ops" }) });
    const html = render(<RecordHostEditor
      host={null} hostId={null} duplicateSource={source}
      overview={recordOverview({ hosts: [source] })}
      terminalId={null} newTab={false} accept={value => value}
      onSaved={() => {}} onDeleted={() => {}} onDirty={() => {}}
    />);
    expect(text(html)).toContain("Duplicate host");
    expect(html).toContain('value="template-copy"');
    expect(html).toContain('value="template.invalid"');
    expect(html).toContain('value="ops"');
    expect(text(html)).toContain("Copied settings from template.");
    expect(text(html)).toContain("Enter a password again");
    expect(text(html)).not.toContain("Server identity");
    expect(() => buttonTag(html, "Connect")).toThrow("no Connect button");
    expect(buttonTag(html, "Create host")).not.toContain(DISABLED);
  });
  it("uses progress rather than failure styling while setup is active", () => {
    const html = render(
      <RecordsAccountPanel
        overview={recordOverview({
          syncing: true,
          shared_writes_blocked: true,
          pending_account: {
            id: "a".repeat(32),
            kind: "join_account",
            phase: "publishing",
          },
        })}
      />,
    );
    expect(text(html)).toContain("Setting up sync…");
    expect(text(html)).not.toContain("Sync changes are paused");
    expect(html).not.toContain('role="alert"');
    expect(buttonTag(html, "Working…")).toContain(DISABLED);
    expect(text(html)).not.toContain("Sync code for recovery");
  });
  it("offers resumable setup without marking the journal itself as a failure", () => {
    const html = render(
      <RecordsAccountPanel
        overview={recordOverview({
          shared_writes_blocked: true,
          pending_account: {
            id: "a".repeat(32),
            kind: "join_account",
            phase: "publishing",
          },
        })}
      />,
    );
    expect(text(html)).toContain("Finish sync setup");
    expect(text(html)).toContain("Resume sync setup");
    expect(html).not.toContain('role="alert"');
  });
  it("starts new hosts in the library and offers creation before connection", () => {
    const html = editor(null);
    expect(text(html)).toContain("New host");
    expect(text(html)).toContain("Library");
    expect(text(html)).not.toContain("Save in");
    expect(() => buttonTag(html, "Connect")).toThrow("no Connect button");
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
    expect(buttonTag(html, "Verify server fingerprint")).not.toContain(DISABLED);
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
    expect(text(conflict)).toContain("ID conflict");
    expect(conflict).toContain('aria-label="Conflicting host ID"');
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
  it("opens the vault without automatically covering the collection", () => {
    const html = render(<RecordsKeysPanel overview={recordOverview({ keys: [{ id: "a".repeat(32), authority: "local", synced: false, public: null, status: "available" }] })} />);
    expect(html).not.toContain("<aside");
    expect(html).toContain('aria-pressed="false"');
  });
  it("routes every older key state to whole-library account setup without per-key sync or downloads", () => {
    for (const synced of [true, false, null]) for (const status of ["available", "needs_material", "conflict", "deleted"] as const) {
      const key = { id: "a".repeat(32), authority: "account" as const, synced, public: null, status };
      const html = render(<SelectedKeysPanel overview={recordOverview({ keys: [key], account: { chain_id: "b".repeat(64), device_name: "Laptop" } })} openSync={vi.fn()} />);
      const rendered = text(html);
      expect(buttonTag(html, "Set up automatic sync")).not.toContain(DISABLED);
      expect(rendered).toContain("All managed SSH private keys then sync automatically");
      expect(rendered).toContain("existing library is reviewed and preserved");
      for (const legacy of ["Download synced key", "Restore synced key", "Sync key", "Stop syncing", "Confirm sync", "Confirm stop"]) expect(rendered).not.toContain(legacy);
      if (status === "conflict") expect(rendered).toContain("metadata conflict");
    }
  });
  it("retains account-free key creation and import without starting automatic sync", () => {
    const html = render(<RecordsKeysPanel overview={recordOverview({ account: null, keys: [] })} openSync={vi.fn()} />);
    expect(buttonTag(html, "Generate key")).not.toContain(DISABLED);
    expect(buttonTag(html, "Import private key")).not.toContain(DISABLED);
    expect(text(html)).toContain("keep using your keys locally without signing in");
    expect(text(html)).not.toContain("Stop syncing");
  });
  it("uses automatic key sync after central cutover without legacy download or sharing controls", () => {
    const key = { id: "a".repeat(32), authority: "account" as const, synced: false, public: null, status: "needs_material" as const };
    for (const status of ["needs_material", "available", "conflict"] as const) {
      const html = render(<SelectedKeysPanel overview={recordOverview({ central_mode: true, account: { chain_id: "a".repeat(64), device_name: "Synthetic" }, keys: [{ ...key, status }] })} />);
      const rendered = text(html);
      for (const legacy of ["Download synced key", "Sync key", "Stop syncing", "This device only", "Sync disabled", "Sharing unknown"]) expect(rendered).not.toContain(legacy);
      expect(rendered).toContain("Automatic encrypted sync");
      if (status === "needs_material") expect(rendered).toContain("will become available automatically");
      if (status === "conflict") expect(rendered).toContain("identity conflict");
    }
  });
  it("explains hardware and agent references without promising to transfer their private keys", () => {
    for (const storage of ["hardware", "external_agent"] as const) {
      const html = render(<SelectedKeysPanel overview={recordOverview({ central_mode: true, keys: [{ id: "a".repeat(32), authority: "account", synced: false, public: null, status: "needs_material", storage }] })} />);
      expect(text(html)).toContain("Key reference syncs automatically");
      expect(text(html)).toContain(storage === "hardware" ? "Connect this key’s hardware device" : "Connect the SSH agent");
      expect(text(html)).not.toContain("will become available automatically");
      expect(text(html)).not.toContain("Download synced key");
      expect(html).not.toContain('data-attention="true"');
    }
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
