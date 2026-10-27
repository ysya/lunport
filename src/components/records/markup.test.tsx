import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { useState, type ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
import { stubBackend } from "@/lib/test-ipc";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { pamStatusQuery, type HostTransport, type PamStatusView } from "@/lib/transports";
import { RecordHostEditor } from "./HostEditor";
import { RecordHostList } from "./HostList";
import { HostPreview } from "./HostPreview";
import { RecordsKeysPanel } from "./KeysPanel";
import { RecordsAccountPanel } from "./AccountPanel";
import { ImportReview } from "./ImportPanel";
import {
  hostPayload,
  hostTransport,
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
afterEach(() => vi.unstubAllGlobals());
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
  it("does not revive the old sync-code setup while its journal is active", () => {
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
    expect(text(html)).toContain("Sync is optional");
    expect(text(html)).not.toContain("Setting up sync…");
    expect(text(html)).not.toContain("Sync changes are paused");
    expect(html).not.toContain('role="alert"');
    expect(text(html)).not.toContain("Create sync chain");
    expect(text(html)).not.toContain("Sync code for recovery");
  });
  it("keeps local use available without offering legacy setup resumption", () => {
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
    expect(text(html)).toContain("Manage hosts, keys, Groups and tunnel rules locally without an account");
    expect(text(html)).not.toContain("Resume sync setup");
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
  it("shows imported Group hierarchy and host membership with escaped names", () => {
    const preview = importPreview();
    preview.preview.groups = [
      { id: "0000000000000010", scope: { kind: "local" }, payload: { schema: 1, name: "<script>Ops</script>", parent_id: null, defaults: {} } },
      { id: "0000000000000011", scope: { kind: "local" }, payload: { schema: 1, name: "Production", parent_id: "0000000000000010", defaults: {} } },
      { id: "0000000000000012", scope: { kind: "local" }, payload: { schema: 1, name: "Empty", parent_id: null, defaults: {} } },
    ];
    preview.preview.candidates[0].payload.group_id = "0000000000000011";
    const html = render(<ImportReview preview={preview} copies={[]} setCopies={vi.fn()} busy={false} />);
    expect(text(html)).toContain("Groups to import (3)");
    expect(text(html)).toContain("Empty");
    expect(text(html)).toContain("Parent: &lt;script&gt;Ops&lt;/script&gt;");
    expect(text(html)).toContain("Group: Production");
    expect(html).not.toContain("<script>");
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
      expect(rendered).toContain("all managed SSH private keys then sync automatically");
      expect(rendered).toContain("unlock with your sync password");
      for (const legacy of ["Download synced key", "Restore synced key", "Sync key", "Stop syncing", "Confirm sync", "Confirm stop"]) expect(rendered).not.toContain(legacy);
      if (status === "conflict") expect(rendered).toContain("metadata conflict");
    }
  });
  it("offers deletion for usable and missing key material while retaining write gates", () => {
    const publicKey = { schema: 2 as const, name: "work", public_key: "ssh-ed25519 fixture", fingerprint: "SHA256:fixture", key_type: "ssh-ed25519", has_passphrase: false, created_at_ms: 1, origin_device_id: "d".repeat(32) };
    for (const status of ["available", "needs_material"] as const) {
      const keys = [{ id: "a".repeat(32), authority: "account" as const, synced: true, public: publicKey, status }];
      const available = render(<SelectedKeysPanel overview={recordOverview({ keys })} />);
      expect(buttonTag(available, "Delete key")).not.toContain(DISABLED);
      const blocked = render(<SelectedKeysPanel overview={recordOverview({ keys, shared_writes_blocked: true })} />);
      expect(buttonTag(blocked, "Delete key")).toContain(DISABLED);
    }
  });
  it("hides synced key tombstones from the collection", () => {
    const html = render(<SelectedKeysPanel overview={recordOverview({ keys: [{ id: "a".repeat(32), authority: "account", synced: true, public: null, status: "deleted" }] })} />);
    expect(html).not.toContain('data-key-id=');
    expect(html).not.toContain("Key details");
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
      if (status === "needs_material") expect(rendered).toContain("matching private key is not available");
      if (status === "conflict") expect(rendered).toContain("identity conflict");
    }
  });
  it("explains hardware and agent references without promising to transfer their private keys", () => {
    for (const storage of ["hardware", "external_agent"] as const) {
      const html = render(<SelectedKeysPanel overview={recordOverview({ central_mode: true, keys: [{ id: "a".repeat(32), authority: "account", synced: false, public: null, status: "needs_material", storage }] })} />);
      expect(text(html)).toContain("Key reference syncs automatically");
      expect(text(html)).toContain(storage === "hardware" ? "Connect this key’s hardware device" : "Connect the SSH agent");
      expect(text(html)).not.toContain("matching private key is not available");
      expect(text(html)).not.toContain("Download synced key");
      expect(html).not.toContain('data-attention="true"');
    }
  });
  it("removes the legacy account controls even when old shared writes are gated", () => {
    const html = render(
      <RecordsAccountPanel
        overview={recordOverview({ shared_writes_blocked: true })}
      />,
    );
    expect(text(html)).not.toContain("Create sync chain");
    expect(text(html)).not.toContain("Join with sync code");
    expect(text(html)).toContain("Sync is optional");
  });
});

describe("a host's route on its card and in its details", () => {
  const HOST = "0000000000000001";
  const web = hostView({ id: HOST, payload: hostPayload({ alias: "web-1", hostname: "10.0.0.8", user: "deploy" }) });
  const iap = hostTransport({ account: "ops@example.com" });
  const withGrant = hostTransport({ pam: { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: 1800, justification: null } });
  const library = (route: HostTransport | null): RecordOverview => recordOverview({ hosts: [web], transports: route ? [route] : [] });
  const list = (overview: RecordOverview) => render(<RecordHostList overview={overview} selectedId={null} select={vi.fn()} />);
  const preview = (host: RecordHostView, overview: RecordOverview, client = new QueryClient()) =>
    renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <HostPreview host={host} overview={overview} connect={vi.fn()} edit={vi.fn()} close={vi.fn()} busy={false} />
      </QueryClientProvider>,
    );
  /**
   * The details pane once the host's grant has been read, as it draws after the latest answer (or failure); `earlier` is what a read
   * before it had found.
   */
  async function settled(overview: RecordOverview, answer: (command: string) => unknown, earlier?: PamStatusView) {
    const calls = stubBackend(async (command) => answer(command));
    // A mounting pane reads the grant again whatever the last read found; this one draws what that read left, even a failure.
    const client = new QueryClient({ defaultOptions: { queries: { retryOnMount: false } } });
    if (earlier) client.setQueryData(pamStatusQuery(HOST).queryKey, earlier);
    await client.prefetchQuery(pamStatusQuery(HOST));
    return { html: preview(web, overview, client), calls };
  }
  const status = (state: string, entitlement: string | null, until: number | null = null, message: string | null = null) => ({
    entitlement,
    state,
    active_until_ms: until,
    message,
  });

  it("marks an IAP host's card, and names the route in its tooltip", () => {
    const html = list(library(iap));
    expect(html).toContain("</svg>IAP · deploy</span>");
    expect(html).toContain("lucide-cloud");
    expect(html).toContain('title="Google Cloud IAP · acme-prod-123456 / web-1"');
    expect(text(html)).not.toContain("SSH · deploy");
    // A host without a route reads as before, and an IAP host with no username shows the bare marker.
    const plain = list(library(null));
    expect(plain).toContain(">SSH · deploy</span>");
    expect(plain).toContain('title="SSH · deploy · 10.0.0.8:22"');
    expect(plain).not.toContain("IAP");
    expect(plain).not.toContain("lucide-cloud");
    const anonymous = hostView({ id: HOST, payload: hostPayload({ user: "" }) });
    expect(list(recordOverview({ hosts: [anonymous], transports: [iap] }))).toContain("</svg>IAP</span>");
  });

  it("leads the details with the IAP target and drops the address", () => {
    const html = preview(web, library(iap));
    expect(html).toContain("</svg>acme-prod-123456 / web-1</p>");
    expect(html).toContain("lucide-cloud");
    expect(html).not.toContain(">Address<");
    expect(html).not.toContain("10.0.0.8");
    const rows = text(html);
    expect(rows).toContain("Connect via Google Cloud IAP");
    expect(rows).toContain("Instance web-1 · asia-east1-b");
    expect(rows).toContain("Project acme-prod-123456");
    expect(rows).toContain("Google account ops@example.com");
    expect(rows).toContain("Checks OS Login");
    expect(rows).toContain("Username deploy Port 22 Group Ungrouped");
    // The account falls back to gcloud's active one, and Checks names only what applies.
    const bare = text(preview(web, library(hostTransport({ os_login: false }))));
    expect(bare).toContain("Google account gcloud's active account");
    expect(bare).not.toContain("Checks");
    expect(text(preview(web, library(withGrant)))).toContain("Checks OS Login · PAM grant");
    // An address host keeps its address.
    const plain = preview(web, library(null));
    expect(plain).toContain(">Address<");
    expect(plain).toContain('<p class="library-preview-address">10.0.0.8</p>');
    expect(plain).not.toContain("lucide-cloud");
    expect(text(plain)).not.toContain("Connect via");
  });

  it("checks an IAP host through IAP, and an address host at its port", () => {
    const iapPane = text(preview(web, library(iap)));
    expect(iapPane).toContain("Check through IAP");
    expect(iapPane).toContain("Check whether this computer reaches the instance's port through IAP with its Google sign-in.");
    expect(iapPane).not.toContain("Check port");
    const plain = text(preview(web, library(null)));
    expect(plain).toContain("Check port");
    expect(plain).not.toContain("Check through IAP");
  });

  it("shows the grant and disables Request grant while it is active", async () => {
    const until = new Date(2026, 9, 27, 10, 0).getTime();
    const { html, calls } = await settled(library(withGrant), () => status("active", "prod-operate", until));
    expect(calls).toEqual([["transports_pam_status", { hostId: HOST }]]);
    expect(text(html)).toContain("Access grant");
    expect(text(html)).toContain("prod-operate · Active until 10:00");
    expect(text(html)).toContain("Required: prod-operate, prod-admin");
    expect(buttonTag(html, "Request grant…")).toContain(DISABLED);
  });

  it("keeps Request grant off while a grant activates, and offers it when there is none", async () => {
    const activating = await settled(library(withGrant), () => status("activating", "prod-admin"));
    expect(text(activating.html)).toContain("prod-admin · Activating…");
    expect(buttonTag(activating.html, "Request grant…")).toContain(DISABLED);
    const none = await settled(library(withGrant), () => status("none", null));
    expect(text(none.html)).toContain("No active grant");
    expect(buttonTag(none.html, "Request grant…")).not.toContain(DISABLED);
  });

  it("says why the grant could not be read instead of saying there is none", async () => {
    const refused = "Privileged Access Manager refused the request: quota exceeded.";
    const answered = await settled(library(withGrant), () => status("error", null, null, refused));
    expect(text(answered.html)).toContain(refused);
    expect(text(answered.html)).not.toContain("No active grant");
    expect(buttonTag(answered.html, "Request grant…")).not.toContain(DISABLED);
    // A sentence about a grant on a named entitlement stands alone, as it does for one that names none.
    const named = await settled(library(withGrant), () => status("error", "prod-operate", null, refused));
    expect(text(named.html)).toContain(refused);
    expect(text(named.html)).not.toContain("prod-operate ·");
    // The command itself failing reads the same way.
    const failed = await settled(library(withGrant), () => {
      throw "Invalid host identity.";
    });
    expect(text(failed.html)).toContain("Invalid host identity.");
    expect(buttonTag(failed.html, "Request grant…")).not.toContain(DISABLED);
    // A read that fails after one that succeeded speaks for the grant: what the earlier one found may be gone by now.
    const lost = await settled(
      library(withGrant),
      () => {
        throw "Google did not answer.";
      },
      status("active", "prod-operate", new Date(2026, 9, 27, 10, 0).getTime()),
    );
    expect(text(lost.html)).toContain("Google did not answer.");
    expect(text(lost.html)).not.toContain("Active until");
    expect(buttonTag(lost.html, "Request grant…")).not.toContain(DISABLED);
  });

  it("waits for the first answer, and has no Access grant for a route without a PAM check", () => {
    const calls = stubBackend(async () => status("none", null));
    const waiting = preview(web, library(withGrant));
    expect(text(waiting)).toContain("Checking the grant…");
    expect(buttonTag(waiting, "Request grant…")).not.toContain(DISABLED);
    expect(text(preview(web, library(iap)))).not.toContain("Access grant");
    expect(text(preview(web, library(null)))).not.toContain("Access grant");
    // A server render reads nothing: the pane reads the grant once it is open.
    expect(calls).toEqual([]);
  });
});
