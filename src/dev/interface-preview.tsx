/** Development-only Vite entry. No native backend, real hosts, keys, or relay requests. */
import React, { useState } from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/sonner";
import { RecordsWorkspace } from "@/components/records/RecordsWorkspace";
import { HostKeyCard } from "@/components/HostKeyWindow";
import { ApprovalCard } from "@/components/AgentApprovalWindow";
import { AuthenticationCardView } from "@/components/AuthenticationWindow";
import { groupView, hostPayload, hostView, importPreview, recordOverview } from "@/components/records/fixtures";
import { recordsStatusKey, useRecordsStatus, type ImportPreviewResult, type RecordOverview } from "@/lib/records";
import { applyInitialMotionPreference, useApplyTheme } from "@/lib/theme";
import "@/index.css";

const fixtureInstalled = import.meta.hot?.data.interfaceFixtureInstalled === true;
if (!import.meta.env.DEV || ("__TAURI_INTERNALS__" in window && !fixtureInstalled)) throw new Error("Interface fixtures require a development browser.");

// Reload the complete fake backend on entry edits; component edits keep normal HMR.
if (fixtureInstalled) window.location.reload();
else {
  if (import.meta.hot) import.meta.hot.data.interfaceFixtureInstalled = true;

  const keyId = "a".repeat(32);
  const parent = groupView({ payload: { schema: 1, name: "Production", parent_id: null, defaults: { user: "deploy" } } });
  const child = groupView({ id: "0000000000000011", payload: { schema: 1, name: "API services", parent_id: parent.id, defaults: {} } });
  let overview: RecordOverview = recordOverview({
    generation: "1", groups: [parent, child],
    hosts: [
      hostView({ payload: hostPayload({ alias: "Production web", hostname: "web.example.com", group_id: child.id, auth: "key", key_id: keyId, tags: ["on-call"] }) }),
      hostView({ id: "0000000000000002", payload: hostPayload({ alias: "Database replica", hostname: "replica.us-east.production.example.com", group_id: parent.id, notes: "Read replica for reporting." }) }),
      hostView({ id: "0000000000000003", payload: hostPayload({ alias: "Bastion", hostname: "bastion.example.com", port: 2222, auth: "key", key_id: "b".repeat(32) }), readiness: { kind: "needs_key" } }),
    ],
    keys: [{ id: keyId, authority: "local", synced: false, status: "available", public: { schema: 1, name: "Work key", public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoOnlyDoNotUse work@example.com", fingerprint: "SHA256:DemoFingerprintForVisualReviewOnly", key_type: "ed25519", has_passphrase: false, created_at_ms: 1, origin_device_id: "d".repeat(32) } }, { id: "b".repeat(32), authority: "account", synced: true, public: null, status: "needs_material" }],
  });
  const scenario = new URLSearchParams(window.location.search).get("scenario");
  if (scenario === "sync-review") overview = { ...overview, account: { chain_id: "c".repeat(64), device_name: "Example laptop" } };
  if (scenario === "sync-pending") overview = { ...overview, shared_writes_blocked: true, pending_account: { id: "fixture-setup", kind: "join_account", phase: "publishing" } };
  const updateOverview = (patch: Partial<RecordOverview>) => {
    overview = { ...overview, ...patch, generation: String(BigInt(overview.generation) + 1n) };
    return overview;
  };
  const includeFixtureLibrary = (renames: { kind: string; id: string; name: string }[] = []) => {
    const scope = { kind: "space" as const, space_id: "e".repeat(64) };
    return updateOverview({
      library_enabled: true, library_scope: scope, shared_format_upgrade_required: false,
      spaces: [{ id: scope.space_id, name: "Example library", selected: true, missing: false }],
      hosts: overview.hosts.map((host) => {
        const alias = renames.find((rename) => rename.kind === "host" && rename.id === host.id)?.name ?? host.payload.alias;
        return { ...host, scope, payload: { ...host.payload, alias }, effective_payload: { ...host.effective_payload, alias } };
      }),
      groups: overview.groups.map((group) => ({ ...group, scope })),
    });
  };
  let reviewedImport: ImportPreviewResult | null = null;
  let previewSequence = 0;
  let callbackId = 1;
  const callbacks = new Map<number, unknown>();
  Object.defineProperty(window, "__TAURI_INTERNALS__", {
    value: {
      metadata: { currentWindow: { label: "main" }, currentWebview: { label: "main" } },
      transformCallback: (callback: unknown) => { const id = callbackId++; callbacks.set(id, callback); return id; },
      unregisterCallback: (id: number) => callbacks.delete(id),
      invoke: async (command: string, args: Record<string, unknown> = {}) => {
        if (command === "records_status") return { format: "records", legacy_paused: false, blocked_reason: null, overview };
        if (command === "app_platform") return "macos";
        if (command === "app_is_development") return true;
        if (command === "app_home_dir") return "/fixture";
        if (command === "connect_list_terminals") return [{ id: "fixture", label: "Example terminal with a long display name", supports_new_tab: true }];
        if (command === "plugin:event|listen") return callbackId++;
        if (command === "plugin:event|unlisten" || ["tray_set_visible", "app_set_close_to_tray", "config_set_backup_retention", "app_set_global_hotkey"].includes(command)) return;
        if (command === "app_take_quick_connect" || command === "plugin:autostart|is_enabled") return false;
        if (command === "records_import_pending" || command === "records_migration_pending") return [];
        if (command === "plugin:dialog|open") return "/fixture/config";
        if (command === "records_import_preview") {
          reviewedImport = importPreview({
            candidates: [
              { id: "0000000000000020", scope: { kind: "local" }, payload: hostPayload({ alias: "Imported staging", hostname: "staging.example.com", auth: "key", key_id: keyId }) },
              { id: "0000000000000021", scope: { kind: "local" }, payload: hostPayload({ alias: "Imported legacy server", hostname: "legacy.example.com", imported: { source: "/fixture/config", at_ms: 1, unsupported: [{ keyword: "Match", value: "exec demo", requires_review: true }] } }) },
            ],
            warnings: [{ location: { path: "/fixture/config", line: 12 }, keyword: "Match", reason: "Review this unsupported directive before connecting.", blocks_connection: true, alias: "Imported legacy server" }],
          });
          reviewedImport.token = `fixture-preview-${++previewSequence}`;
          return reviewedImport;
        }
        if (command === "records_import_cancel") { if (reviewedImport?.token === args.token) reviewedImport = null; return; }
        if (command === "records_import_confirm") {
          if (!reviewedImport || args.token !== reviewedImport.token) throw new Error("Preview expired. Preview the fixture again.");
          const preview = reviewedImport.preview;
          reviewedImport = null;
          updateOverview({ hosts: [...overview.hosts.filter((host) => !preview.candidates.some((candidate) => candidate.id === host.id)), ...preview.candidates.map((candidate) => hostView({ ...candidate, readiness: { kind: candidate.payload.imported ? "needs_review" : "ready" } }))] });
          return { overview, receipt: { import_id: "fixture-import", host_ids: preview.candidates.map((host) => host.id), copied_key_ids: (args.copyKeyIds as string[]).filter((id) => preview.key_references.some((reference) => reference.key_id === id && reference.resolved_path)) } };
        }
        if (command === "records_set_relay_url") return updateOverview({ relay_url: String(args.url) });
        if (command === "records_account_create" || command === "records_account_join" || command === "records_account_resume") {
          updateOverview({ account: { chain_id: "c".repeat(64), device_name: String(args.deviceName ?? "Example laptop") }, pending_account: null, shared_writes_blocked: false });
          includeFixtureLibrary();
          return command === "records_account_create" ? { overview, words: "DEMO ONLY — interface fixture, not a real sync code", complete: true, pending_error: null, operation_id: "fixture-setup" } : overview;
        }
        if (command === "records_account_words") return "DEMO ONLY — interface fixture, not a real sync code";
        if (command === "records_library_preview") return { token: "fixture-library-review", conflicts: [{ kind: "host", id: overview.hosts[0].id, current_name: overview.hosts[0].payload.alias, suggested_name: `${overview.hosts[0].payload.alias} (this device)` }], local_hosts: overview.hosts.length, local_groups: overview.groups.length };
        if (command === "records_library_enable") {
          const review = args.review as { token: string; renames: { kind: string; id: string; name: string }[] } | undefined;
          if (review?.token !== "fixture-library-review") throw new Error("Review the fixture library first.");
          return includeFixtureLibrary(review.renames);
        }
        if (command === "mcp_status") return { enabled: false, bridge_active: true, approval_mode: "ask", allowed_hosts: [], pending: [], recent: [], audit_error: null, executable: "/fixture/sshelter", last_client_at_ms: null, noninteractive_credentials_supported: false, noninteractive_credentials_notice: null };
        if (command === "records_key_generate") {
          overview = { ...overview, generation: String(Number(overview.generation) + 1), keys: [...overview.keys, { ...overview.keys[0], id: String(overview.keys.length + 10).padStart(32, "0"), public: { ...overview.keys[0].public!, name: String(args.name) } }] };
          return overview;
        }
        throw new Error(`Interface preview does not run native operation: ${command}`);
      },
    }
  });
  Object.defineProperty(window, "__TAURI_EVENT_PLUGIN_INTERNALS__", { value: { unregisterListener: () => { } } });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(recordsStatusKey, { format: "records", legacy_paused: false, blocked_reason: null, overview });
  function Preview() {
    useApplyTheme();
    const status = useRecordsStatus();
    const [answer, setAnswer] = useState("");
    if (scenario === "hostkey" || scenario === "hostkey-changed") return <HostKeyCard
      request={{ id: "fixture-hostkey", alias: "Production web", hostname: "web.example.com", port: 22, algorithm: "ssh-ed25519", fingerprint: "SHA256:DemoFingerprintForVisualReviewOnly", changed: scenario === "hostkey-changed" ? { fingerprint: "SHA256:PreviousDemoFingerprintForVisualReviewOnly", pinned_at_ms: 1700000000000 } : null }}
      busy={false} onAnswer={() => {}}
    />;
    if (scenario === "approval") return <ApprovalCard
      request={{ id: "fixture-approval", key_name: "Work key", key_fingerprint: "SHA256:DemoFingerprintForVisualReviewOnly", program_chain: ["Example client", "zsh", "ssh"], user: "deploy", host: "web.example.com", host_fingerprint: null, rememberable: true, remember_minutes: 240, needs_passphrase: true, passphrase_error: null, preapproved: false }}
      busy={false} onAnswer={() => {}}
    />;
    if (scenario === "authentication" || scenario === "authentication-expired") return <AuthenticationCardView
      request={{ id: "fixture-question", request_id: "fixture-connection", hop: { alias: "Production web", host_id: "0000000000000001", hostname: "web.example.com", user: "deploy", port: 22 }, kind: "password", text: "Password for deploy@web.example.com:", echo: false, remaining_ms: 90000 }}
      busy={false} armed remainingMs={scenario === "authentication-expired" ? 0 : 90000} answer={answer} onChange={setAnswer} onAnswer={() => setAnswer("")}
    />;
    return <>
      <RecordsWorkspace
        overview={status.data?.overview ?? overview}
        reload={() => void client.invalidateQueries({ queryKey: recordsStatusKey })}
      />
      <Toaster />
    </>;
  }
  applyInitialMotionPreference();
  ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode>
    <QueryClientProvider client={client}>
      <Preview />
    </QueryClientProvider>
  </React.StrictMode>);
}
