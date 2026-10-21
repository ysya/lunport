/** Development-only Vite entry. No native backend, real hosts, keys, or relay requests. */
import App from "@/App";
import { legacyPreviewRead } from "./legacy-fixtures";
import React, { useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/sonner";
import { RecordsWorkspace } from "@/components/records/RecordsWorkspace";
import { HostKeyCard } from "@/components/HostKeyWindow";
import { ApprovalCard } from "@/components/AgentApprovalWindow";
import { AuthenticationCardView } from "@/components/AuthenticationWindow";
import { groupView, hostPayload, hostView, importPreview, recordOverview } from "@/components/records/fixtures";
import type { CentralStatus } from "@/lib/central-sync";
import { recordsStatusKey, useRecordsStatus, type ImportPreviewResult, type RecordOverview } from "@/lib/records";
import { applyInitialAppearance, useApplyTheme } from "@/lib/theme";
import { useTerminalStore } from "@/stores/terminals";
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
  const failure = new URLSearchParams(window.location.search).get("failure");
  if (scenario === "vault") overview.keys = Array.from({ length: 25 }, (_, index) => ({ ...overview.keys[0], id: (index + 1).toString(16).padStart(32, "0"), public: { ...overview.keys[0].public!, name: index === 0 ? "Work key" : `Infrastructure key ${index + 1}` } }));
  if (scenario === "terminal-missing-key") overview = { ...overview,
    hosts: [hostView({ payload: hostPayload({ alias: "simple", auth: "key", key_id: keyId }) })],
    keys: [{ ...overview.keys[0], authority: "account", synced: true, status: "needs_material" }],
  };
  // Disposable in-memory credentials only; no OS store or remote SSH is used here.
  const passwords = new Map<string, string>();
  let passwordSaveFailed = false;
  if (scenario === "password" || scenario === "password-save-retry" || scenario === "host-duplicate") overview.hosts = overview.hosts.map((host, index) => ({ ...host, payload: { ...host.payload, alias: ["production-web", "database-replica", "bastion"][index] }, effective_payload: { ...host.effective_payload, alias: ["production-web", "database-replica", "bastion"][index] } }));
  let mcp = { enabled: false, bridge_active: true, approval_mode: "ask", allowed_hosts: [] as string[], allowed_groups: [] as string[], pending: [], recent: [], audit_error: null, executable: "/fixture/sshelter", last_client_at_ms: null, noninteractive_credentials_supported: false, noninteractive_credentials_notice: "Ask is required for interactive credentials." };
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
  let conflictResolved = false;
  let callbackId = 1;
  const callbacks = new Map<number, unknown>();
  Object.defineProperty(window, "__TAURI_INTERNALS__", {
    value: {
      metadata: { currentWindow: { label: "main" }, currentWebview: { label: "main" } },
      transformCallback: (callback: unknown) => { const id = callbackId++; callbacks.set(id, callback); return id; },
      unregisterCallback: (id: number) => callbacks.delete(id),
      invoke: async (command: string, args: Record<string, unknown> = {}) => {
        if (scenario === "terminal-missing-key" && command === "terminal_open") {
          const output = args.output as { onmessage: (buffer: ArrayBuffer) => void };
          const send = (event: object) => {
            const json = new TextEncoder().encode(JSON.stringify(event));
            const packet = new Uint8Array(json.length + 1); packet[0] = 1; packet.set(json, 1);
            output.onmessage(packet.buffer);
          };
          send({ type: "event", event: "error", kind: "host", text: `simple needs key ${keyId} material on this device.` });
          send({ type: "exited", code: null, signal: null }); send({ type: "closed" });
          return;
        }
        if (scenario === "terminal-missing-key" && ["terminal_close", "terminal_ack"].includes(command)) return;
        if (command === failure) throw new Error("Disposable fixture read failure. Retry after changing the preview scenario.");
        if (command === "secrets_has") return passwords.has(String(args.alias));
        if (command === "records_password_status") return passwords.has(String(args.hostId));
        if (command === "records_password_change") {
          if (scenario === "password-save-retry" && !passwordSaveFailed) {passwordSaveFailed=true;throw new Error("Disposable credential-store failure");}
          if (args.password === null) passwords.delete(String(args.hostId));else passwords.set(String(args.hostId),String(args.password));return;
        }
        if (command === "secrets_set") {
          if (scenario === "password-save-retry" && !passwordSaveFailed) { passwordSaveFailed = true; throw new Error("Disposable credential-store failure"); }
          passwords.set(String(args.alias), String(args.password)); return;
        }
        if (command === "secrets_delete") { passwords.delete(String(args.alias)); return; }
        if (command === "records_host_create") {
          const id = String(overview.hosts.length + 1).padStart(16, "0");
          return updateOverview({ hosts: [...overview.hosts, hostView({ id, scope: args.scope as RecordOverview["hosts"][number]["scope"], payload: args.payload as RecordOverview["hosts"][number]["payload"] })] });
        }
        if (command === "records_host_update") return updateOverview({ hosts: overview.hosts.map(host => host.id !== args.id ? host : hostView({ ...host, payload: args.payload as typeof host.payload, revision: { ...host.revision, version: String(BigInt(host.revision.version) + 1n) } })) });
        if (command === "records_key_rename") return updateOverview({ keys: overview.keys.map(key => key.id === args.keyId && key.public ? { ...key, public: { ...key.public, name: String(args.name) } } : key) });
        if (command === "config_load" && args.path === "/fixture/slow-config") await new Promise((resolve) => setTimeout(resolve, 1500));
        const fixture = legacyPreviewRead(command, args);
        if (fixture.handled) return fixture.value;
        if (command === "records_status") return { format: scenario === "legacy" ? "legacy" : "records", legacy_paused: false, blocked_reason: null, overview };
        if (command === "records_connect" && scenario === "host-interactions") {
          console.info("Fixture connection requested", String(args.hostId));
          return;
        }
        if (command === "records_saved_workspaces") return [
          {id:"original",active:false,service:null,hosts:21,groups:4,modified_ms:1700000000000,error:null},
          {id:"1".repeat(32),active:true,service:"https://sync.example.com",hosts:3,groups:2,modified_ms:1700100000000,error:null}
        ];
        if (command === "records_hosts_export") return {path:"/fixture/lunport-hosts.json",hosts:21,groups:4};
        if (command === "central_server_capabilities") return {passkey:true,oidc:false};
        if (["central_status","central_automatic_status","central_conflict_resolve"].includes(command) && ["sync-layout","sync-active","sync-conflicts","sync-cooldown","sync-revoked","sync-reconnect","sync-reconnecting","sync-failure"].includes(scenario ?? "")) {
          if (command === "central_conflict_resolve") conflictResolved = true;
          const active = scenario !== "sync-layout";
          const status={
            available: true, configured: true, phase: scenario === "sync-revoked" ? "revoked" : active ? "active" : "setup", service: "https://sync.example.com",
            account_id: "a".repeat(64), device_id: "b".repeat(32), root_fingerprint: active ? "c".repeat(64) : null,
            membership_head: active ? "d".repeat(64) : null, authorization_epoch: "1", has_session: true, account_authenticated:true, login_pending: false,
            needs_recovery: ["sync-revoked", "sync-reconnect", "sync-reconnecting"].includes(scenario ?? ""), replacement_pending: false, needs_reconciliation: false,
            can_sync: active && scenario !== "sync-revoked", pending: 0, conflicts: scenario === "sync-conflicts" && !conflictResolved ? 1 : 0,
            connecting: scenario === "sync-reconnecting", automatic_sync:true, cooldown_seconds: scenario === "sync-cooldown" ? 25 : 0,
            error: scenario === "sync-failure" ? "Invalid central sync protocol data." : null,
          } satisfies CentralStatus;
          return command === "central_automatic_status" ? {phase:active ? "ready" : "password_setup",status} : status;
        }
        if (command === "central_conflicts") return conflictResolved ? [] : [{id:"1".repeat(64),token:"2".repeat(64),kind:"host",name:"production-web",local:{hostname:"web-old.example.com",port:22,user:"deploy"},remote:{hostname:"web-new.example.com",port:2222,user:"deploy"},local_deleted:false,remote_deleted:false,remote_revision:"3",can_resolve:true,can_remote:true,can_copy:true}];
        if (command === "central_account_access") return {authorization_epoch:"1",barrier_pending:false,devices:[{id:"b".repeat(32),name:"Example laptop",created_at_ms:"1",state:"active",current:true}]};
        if (command === "central_devices") return {authorization_epoch:"1",membership_head:"d".repeat(64),devices:[{id:"b".repeat(32),name:"Example laptop",state:"approved",fingerprint:"SHA256:ExampleOnly",current:true}]};
        if (command === "app_platform") return new URLSearchParams(window.location.search).get("platform") === "windows" ? "windows" : "macos";
        if (command === "app_is_development") return true;
        if (command === "app_home_dir") return "/fixture";
        if (command === "connect_list_terminals") return [{ id: "fixture", label: "Example terminal with a long display name", supports_new_tab: true }];
        if (command === "plugin:event|listen") return callbackId++;
        if (command === "plugin:event|unlisten" || ["tray_set_visible", "app_set_close_to_tray", "config_set_backup_retention", "app_set_global_hotkey"].includes(command)) return;
        if (command === "app_take_quick_connect" || command === "plugin:autostart|is_enabled") return false;
        if (command === "records_import_pending" || command === "records_migration_pending") return [];
        if (command === "plugin:dialog|open") return String((args.options as { title?: string } | undefined)?.title ?? "").includes("private key") ? "/fixture/id_work" : "/fixture/config";
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
        if (command === "mcp_setup_overview") return { sandbox: true, executable: "/fixture/sshelter", clients: ["codex", "claude_code", "claude_desktop", "cursor", "vscode"].map(client => ({ client, state: "not_added", config_path: null, message: null })) };
        if (command === "mcp_status") return mcp;
        if (command === "mcp_set_enabled") return mcp = { ...mcp, enabled: args.enabled === true };
        if (command === "mcp_set_group_allowed") {
          if (args.generation !== overview.generation) throw new Error("The fixture library changed. Refresh AI Access and try again.");
          const scope = args.scope as { kind: string; space_id?: string };
          const key = scope.kind === "local" ? `local/${args.groupId}` : `space/${scope.space_id}/${args.groupId}`;
          return mcp = { ...mcp, allowed_groups: args.allowed ? [...new Set([...mcp.allowed_groups, key])] : mcp.allowed_groups.filter((id) => id !== key) };
        }
        if (command === "mcp_set_host_allowed") return mcp = { ...mcp, allowed_hosts: args.allowed ? [...new Set([...mcp.allowed_hosts, String(args.alias)])] : mcp.allowed_hosts.filter((id) => id !== args.alias) };
        if (command === "mcp_set_approval_mode") return mcp = { ...mcp, approval_mode: String(args.approvalMode) };
        if (command === "records_key_generate" || command === "records_key_import" || command === "records_key_import_file") {
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
    useEffect(() => {
      if (scenario !== "terminal-missing-key") return;
      useTerminalStore.getState().open({ host: { id: overview.hosts[0].id }, name: "simple", address: "deploy@fixture.invalid:22", historyKey: "fixture" });
      return () => useTerminalStore.getState().reset();
    }, []);
    if (scenario === "legacy") return <App />;
    if (scenario === "hostkey" || scenario === "hostkey-changed") return <HostKeyCard
      request={{ user: "deploy", id: "fixture-hostkey", alias: "Production web", hostname: "web.example.com", port: 22, algorithm: "ssh-ed25519", fingerprint: "SHA256:DemoFingerprintForVisualReviewOnly", changed: scenario === "hostkey-changed" ? { fingerprint: "SHA256:PreviousDemoFingerprintForVisualReviewOnly", pinned_at_ms: 1700000000000 } : null }}
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
  applyInitialAppearance();
  ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode>
    <QueryClientProvider client={client}>
      <Preview />
    </QueryClientProvider>
  </React.StrictMode>);
}
