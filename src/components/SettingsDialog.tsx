import { auditRows } from "@/lib/mcp-audit-rows";
import { useEffect, useRef, useState } from "react";
import type { ComponentType } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Bot,
  Copy,
  FolderCog,
  Monitor,
  Moon,
  RefreshCw,
  Settings2,
  SlidersHorizontal,
  Sun,
  SunMoon,
  TerminalSquare,
} from "lucide-react";

import {
  disable as autostartDisable,
  enable as autostartEnable,
  isEnabled as autostartIsEnabled,
} from "@tauri-apps/plugin-autostart";

import { useUiStore, type SettingsCategory } from "@/stores/ui";
import { useSettingsStore } from "@/stores/settings";
import { useHostsQuery, useLoadConfig, usePlatform, useTerminals, useIsDevelopment } from "@/lib/queries";
import { tauriInvoke } from "@/lib/ipc";
import { useUpdaterState, updateInProgress } from "@/lib/updater";
import { UpdatesPane } from "@/components/UpdatesPane";
import { copyText } from "@/lib/clipboard";
import { isImeKey } from "@/lib/ime";
import {
  exportSettings,
  pickSettingsImport,
  applySettingsImport,
  type SettingsEnvelope,
} from "@/lib/settings-io";
import {
  FONT_SIZE_OPTIONS,
  LINT_RULES,
  quickConnectLabel,
  terminalSupportsNewTab,
  type ThemePref,
} from "@/lib/settings-logic";
import { cn } from "@/lib/utils";
import { isWildcardOnly } from "@/lib/host-display";
import {
  useMcpStatus,
  useSetMcpEnabled,
  useSetMcpHostAllowed,
  useSetMcpApprovalMode,
} from "@/lib/mcp";

import { Dialog, DialogContent, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Section, SettingsGroup, SettingsRow } from "@/components/settings-primitives";
import { SyncPane } from "@/components/SyncPane";
import { revealHidden } from "@/lib/sync-approvals";
import { chooseMcpMode } from "@/lib/mcp-flow";
import { McpAttribution } from "@/components/McpAttribution";
import { groupPath } from "@/components/records/group-tree";
import type { RecordOverview } from "@/lib/records";

export function SettingsCategoryPane({
  category,
  recordOverview,
  onOpenImport,
  onOpenSync,
}: {
  category: SettingsCategory;
  recordOverview?: RecordOverview;
  onOpenImport?: () => void;
  onOpenSync?: () => void;
}) {
  if (category === "general") return <GeneralPane />;
  if (category === "updates") return <UpdatesPane />;
  if (category === "appearance") return <AppearancePane />;
  if (category === "connection") return <ConnectionPane />;
  if (category === "files")
    return recordOverview ? (
      <Section
        title="Local data"
        description="Hosts and keys are managed in this workspace. Import an SSH configuration to copy selected entries; the original files stay in place."
      >
        <Button variant="outline" onClick={onOpenImport}>
          Import SSH configuration…
        </Button>
      </Section>
    ) : (
      <FilesPane />
    );
  if (category === "ai")
    return recordOverview ? (
      <McpPane
        records
        hosts={recordOverview.hosts.map((host) => ({
          id: host.id,
          alias: revealHidden(host.payload.alias),
          hostname: revealHidden(host.effective_payload.hostname),
          user: revealHidden(host.effective_payload.user),
          port: host.effective_payload.port,
          groupPath: revealHidden(groupPath(recordOverview, host.payload.group_id, host.scope)),
        }))}
      />
    ) : (
      <LegacyMcpPane />
    );
  if (category === "sync")
    return recordOverview ? (
      <Section
        title="Sync chain"
        description="Manage your relay, sync code and shared spaces in the Sync workspace."
      >
        <Button variant="outline" onClick={onOpenSync}>
          Open sync workspace
        </Button>
      </Section>
    ) : (
      <SyncPane />
    );
  if (recordOverview)
    return (
      <Section
        title="Workspace capabilities"
        description="This workspace uses SSHelter's built-in SSH engine. Hosts and keys stay local unless you explicitly share them into a sync chain."
      >
        <p className="text-sm text-muted-foreground">
          MCP can inspect individually allowed hosts and execute SSH commands with Ask approval or explicitly acknowledged Auto-log. Group defaults never grant AI access. MCP authentication is request-scoped and Auto-log never prompts or trusts a new server.
        </p>
      </Section>
    );
  return <AdvancedPane />;
}

/** Radix Select values must be non-empty; this sentinel round-trips to `null`. */
const TERMINAL_DEFAULT = "__default__";
/** Sentinel for "keep all backups" (backupRetention = null). */
const RETENTION_ALL = "__all__";

const CATEGORIES: {
  id: SettingsCategory;
  label: string;
  icon: ComponentType<{ className?: string }>;
  badge?: string;
}[] = [
  { id: "general", label: "General", icon: Settings2 },
  { id: "updates", label: "Updates", icon: RefreshCw },
  { id: "appearance", label: "Appearance", icon: SunMoon },
  { id: "connection", label: "Connection", icon: TerminalSquare },
  { id: "files", label: "Files & Backups", icon: FolderCog },
  { id: "ai", label: "AI Access", icon: Bot },
  { id: "sync", label: "Sync", icon: RefreshCw, badge: "Beta" },
  { id: "advanced", label: "Advanced", icon: SlidersHorizontal },
];

/**
 * The Settings window (⌘,): a System-Settings-style sidebar + detail layout.
 * Preferences persist via `useSettingsStore` (zustand persist); the ones the
 * backend also needs (tray, close-to-tray, retention) are mirrored with
 * fire-and-forget invokes here and re-sent on launch by
 * `useSyncBackendSettings`. Open state lives in the UI store so the toolbar
 * gear, the ⌘K palette, and the ⌘, shortcut can all drive it.
 */
export function SettingsDialog({ recordOverview, onOpenImport, onOpenSync }: {
  recordOverview?: RecordOverview;
  onOpenImport?: () => void;
  onOpenSync?: () => void;
} = {}) {
  const contentRef = useRef<HTMLDivElement>(null);
  const open = useUiStore((s) => s.settingsOpen);
  const setOpen = useUiStore((s) => s.setSettingsOpen);
  const category = useUiStore((s) => s.settingsCategory);
  const setCategory = useUiStore((s) => s.setSettingsCategory);

  // Global ⌘, / Ctrl+, shortcut — the macOS-standard Preferences accelerator.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "," && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen(true);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [setOpen]);

  const updatePhase = useUpdaterState((state) => state.phase);
  const updateAttention = updatePhase === "available" || updateInProgress(updatePhase);
  const active = CATEGORIES.find((c) => c.id === category) ?? CATEGORIES[0];

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent ref={contentRef} className="app-shell gap-0 overflow-hidden p-0 sm:max-w-2xl"
        onOpenAutoFocus={(event) => {
          const active = contentRef.current?.querySelector<HTMLButtonElement>('button[aria-current="true"]');
          if (active) { event.preventDefault(); active.focus(); }
        }}>
        <DialogDescription className="sr-only">Manage application preferences and software updates.</DialogDescription>
        <div className="flex h-[480px] max-h-[80vh] max-sm:flex-col">
          {/* Sidebar — category list. */}
          <aside className="flex w-44 shrink-0 flex-col gap-0.5 border-r bg-muted/40 p-2 max-sm:w-full max-sm:border-r-0 max-sm:border-b">
            <DialogTitle className="px-2 pt-1 pb-2 text-sm font-semibold select-none">
              Settings
            </DialogTitle>
            <nav aria-label="Settings categories" className="flex flex-col gap-0.5 max-sm:flex-row max-sm:overflow-x-auto max-sm:pb-1">
              {CATEGORIES.map((c) => {
                const Icon = c.icon;
                const isActive = c.id === category;
                return (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => setCategory(c.id)}
                    aria-current={isActive ? "true" : undefined}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors select-none cursor-default max-sm:w-auto max-sm:shrink-0",
                      "focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
                      isActive
                        ? "bg-primary/12 text-foreground"
                        : "text-muted-foreground hover:bg-muted/70 hover:text-foreground",
                    )}
                  >
                    <Icon className="size-4 shrink-0" />
                    {c.label}
                    {c.id === "updates" && updateAttention && <span aria-hidden="true" className="ml-auto size-1.5 rounded-full bg-primary" />}
                    {c.badge && (
                      <Badge variant="outline" className="ml-auto h-4 px-1 text-[10px] font-normal">
                        {c.badge}
                      </Badge>
                    )}
                  </button>
                );
              })}
            </nav>
          </aside>

          {/* Detail pane — scrollable. */}
          <div className="flex min-h-0 min-w-0 flex-1 flex-col">
            <header className="shrink-0 border-b px-5 py-3 select-none">
              <h2 className="text-sm font-semibold">{active.label}</h2>
            </header>
            <div key={category} className="min-h-0 flex-1 space-y-5 overflow-y-auto px-5 py-4">
              <SettingsCategoryPane category={category} recordOverview={recordOverview} onOpenImport={onOpenImport} onOpenSync={onOpenSync} />
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------------- */
/* Panes                                                                     */
/* ------------------------------------------------------------------------- */

function GeneralPane() {
  const trayVisible = useSettingsStore((s) => s.trayVisible);
  const setTrayVisible = useSettingsStore((s) => s.setTrayVisible);
  const closeToTray = useSettingsStore((s) => s.closeToTray);
  const setCloseToTray = useSettingsStore((s) => s.setCloseToTray);
  const globalHotkey = useSettingsStore((s) => s.globalHotkey);
  const setGlobalHotkey = useSettingsStore((s) => s.setGlobalHotkey);
  const platform = usePlatform();
  const { data: isDevelopment } = useIsDevelopment();
  const integrationsAllowed = isDevelopment === false;
  // Launch-at-login reflects the OS state (NOT a persisted flag): queried
  // fresh every time this pane mounts; null = still loading → switch disabled.
  const [launchAtLogin, setLaunchAtLogin] = useState<boolean | null>(null);
  // A validated-but-unconfirmed settings import (drives the overwrite AlertDialog).
  const [pendingImport, setPendingImport] = useState<SettingsEnvelope | null>(null);

  useEffect(() => {
    if (!integrationsAllowed) return;
    autostartIsEnabled()
      .then(setLaunchAtLogin)
      .catch((e) => {
        setLaunchAtLogin(null);
        console.warn("[settings] autostart state query failed:", e);
      });
  }, [integrationsAllowed]);

  const onTray = (visible: boolean) => {
    setTrayVisible(visible);
    tauriInvoke<void>("tray_set_visible", { visible }).catch((e) =>
      toast.error("Could not update menu bar icon", { description: String(e) }),
    );
  };
  const onCloseToTray = (enabled: boolean) => {
    setCloseToTray(enabled);
    tauriInvoke<void>("app_set_close_to_tray", { enabled }).catch((e) =>
      toast.error("Could not update close behavior", { description: String(e) }),
    );
  };

  // Optimistic toggle, then re-read the ACTUAL state — the OS is the source
  // of truth (the user can also flip this in System Settings → Login Items).
  const onLaunchAtLogin = async (enabled: boolean) => {
    const prev = launchAtLogin;
    setLaunchAtLogin(enabled);
    try {
      if (enabled) await autostartEnable();
      else await autostartDisable();
      setLaunchAtLogin(await autostartIsEnabled());
    } catch (e) {
      setLaunchAtLogin(prev);
      toast.error("Could not update launch at login", { description: String(e) });
    }
  };

  const onExport = async () => {
    try {
      const path = await exportSettings();
      if (path) toast.success("Settings exported", { description: path });
    } catch (e) {
      toast.error("Could not export settings", { description: String(e) });
    }
  };

  // Pick + validate first; the destructive overwrite waits for the AlertDialog.
  const onImport = async () => {
    try {
      const envelope = await pickSettingsImport();
      if (envelope) setPendingImport(envelope);
    } catch (e) {
      toast.error("Could not import settings", {
        description: e instanceof Error ? e.message : String(e),
      });
    }
  };

  const confirmImport = async () => {
    const envelope = pendingImport;
    setPendingImport(null);
    if (!envelope) return;
    try {
      await applySettingsImport(envelope);
      toast.success("Settings imported");
    } catch (e) {
      toast.error("Could not apply imported settings", { description: String(e) });
    }
  };

  return (
    <>
      <Section title="Menu bar">
        <SettingsGroup>
          <SettingsRow id="set-tray" label="Show menu bar icon">
            <Switch id="set-tray" checked={trayVisible} onCheckedChange={onTray} />
          </SettingsRow>
          <SettingsRow
            id="set-close-to-tray"
            label="Keep running in menu bar when window closes"
          >
            <Switch
              id="set-close-to-tray"
              checked={closeToTray}
              onCheckedChange={onCloseToTray}
            />
          </SettingsRow>
          <SettingsRow
            id="set-launch-login"
            label="Launch at login"
            description="Reflects the system Login Items state."
          >
            <Switch
              id="set-launch-login"
              checked={launchAtLogin === true}
              disabled={!integrationsAllowed || launchAtLogin === null}
              onCheckedChange={onLaunchAtLogin}
            />
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="Quick connect"
        description="Brings SSHelter to the front with the command palette open, from any app."
      >
        <SettingsGroup>
          <SettingsRow id="set-global-hotkey" label="Global quick-connect hotkey">
            <div className="flex items-center gap-2.5">
              <kbd className="rounded-sm border bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                {quickConnectLabel(platform.data)}
              </kbd>
              <Switch
                id="set-global-hotkey"
                checked={globalHotkey}
                onCheckedChange={setGlobalHotkey}
              />
            </div>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="Language"
        description="More languages are planned. SSH keywords always stay in English."
      >
        <SettingsGroup>
          <SettingsRow label="Language">
            <Select value="en" disabled>
              <SelectTrigger className="h-7 w-[10rem] text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="en">English</SelectItem>
              </SelectContent>
            </Select>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="Data"
        description="Preferences only — your SSH config, keys, and hosts are never included."
      >
        <SettingsGroup>
          <SettingsRow
            label="Diagnostic logs"
            description="Local startup and error logs. Hosts, credentials and sync codes are excluded."
          >
            <Button type="button" variant="secondary" size="sm" className="h-7"
              onClick={() => tauriInvoke<void>("app_open_diagnostics").catch(() => toast.error("Could not open diagnostic logs"))}>
              Open logs
            </Button>
          </SettingsRow>
          <SettingsRow
            label="Export settings"
            description="Save all preferences to a JSON file."
          >
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="h-7"
              onClick={onExport}
            >
              Export…
            </Button>
          </SettingsRow>
          <SettingsRow
            label="Import settings"
            description="Replace all preferences from a JSON file."
          >
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="h-7"
              onClick={onImport}
            >
              Import…
            </Button>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      {/* Confirm-before-overwrite: the picked file is already validated. */}
      <AlertDialog
        open={pendingImport !== null}
        onOpenChange={(open) => {
          if (!open) setPendingImport(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Replace all settings?</AlertDialogTitle>
            <AlertDialogDescription>
              Importing replaces every SSHelter preference with the contents of
              the selected file. Your SSH config files are not affected.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={confirmImport}>Import</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function AppearancePane() {
  const theme = useSettingsStore((s) => s.theme);
  const setTheme = useSettingsStore((s) => s.setTheme);
  const fontSize = useSettingsStore((s) => s.fontSize);
  const setFontSize = useSettingsStore((s) => s.setFontSize);
  const showHostTags = useSettingsStore((s) => s.showHostTags);
  const setShowHostTags = useSettingsStore((s) => s.setShowHostTags);
  return (
    <Section
      title="Appearance"
      description="“System” follows your OS light/dark preference. Text size scales the whole interface."
    >
      <SettingsGroup>
        <SettingsRow label="Theme">
          <ThemeSegmented value={theme} onChange={setTheme} />
        </SettingsRow>
        <SettingsRow id="set-font-size" label="Text size">
          <Select
            value={String(fontSize)}
            onValueChange={(v) => setFontSize(Number(v))}
          >
            <SelectTrigger id="set-font-size" className="h-7 w-[10rem] text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {FONT_SIZE_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={String(o.value)}>
                  {o.label}
                  <span className="ml-1 font-mono text-xs text-muted-foreground">
                    {o.value}px
                  </span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </SettingsRow>
        <SettingsRow
          id="set-show-host-tags"
          label="Show tags in host list"
          description="Tag chips on sidebar rows when grouping by file."
        >
          <Switch
            id="set-show-host-tags"
            checked={showHostTags}
            onCheckedChange={setShowHostTags}
          />
        </SettingsRow>
      </SettingsGroup>
    </Section>
  );
}

function ConnectionPane() {
  const terminalId = useSettingsStore((s) => s.terminalId);
  const setTerminalId = useSettingsStore((s) => s.setTerminalId);
  const newTabConnect = useSettingsStore((s) => s.newTabConnect);
  const setNewTabConnect = useSettingsStore((s) => s.setNewTabConnect);
  const terminals = useTerminals();

  const supportsNewTab = terminalSupportsNewTab(terminalId, terminals.data ?? []);

  return (
    <Section
      title="Connection"
      description="Where SSHelter opens a connection. “System default” uses your OS default terminal (or the first detected)."
    >
      <SettingsGroup>
        <SettingsRow label="Default terminal">
          <Select
            value={terminalId ?? TERMINAL_DEFAULT}
            onValueChange={(v) => setTerminalId(v === TERMINAL_DEFAULT ? null : v)}
          >
            <SelectTrigger className="h-7 w-[11rem] text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={TERMINAL_DEFAULT}>System default</SelectItem>
              {(terminals.data ?? []).map((t) => (
                <SelectItem key={t.id} value={t.id}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </SettingsRow>
        <SettingsRow
          id="set-new-tab"
          label="Open connections in a new tab"
          description={
            supportsNewTab
              ? "Opens a tab in an existing window instead of a new window."
              : "The selected terminal doesn’t support opening new tabs."
          }
        >
          <Switch
            id="set-new-tab"
            checked={newTabConnect}
            onCheckedChange={setNewTabConnect}
            disabled={!supportsNewTab}
          />
        </SettingsRow>
      </SettingsGroup>
    </Section>
  );
}

function FilesPane() {
  const configPath = useSettingsStore((s) => s.configPath);
  const setConfigPath = useSettingsStore((s) => s.setConfigPath);
  const backupRetention = useSettingsStore((s) => s.backupRetention);
  const setBackupRetention = useSettingsStore((s) => s.setBackupRetention);

  const loadConfig = useLoadConfig();
  const queryClient = useQueryClient();

  const [draft, setDraft] = useState(configPath ?? "");
  useEffect(() => setDraft(configPath ?? ""), [configPath]);

  // Persist only on a SUCCESSFUL load so a broken path never sticks: on error
  // the old working document (and persisted path) stay intact and the
  // existing "Failed to load config" toast fires from useLoadConfig.
  const applyPath = () => {
    const next = draft.trim() === "" ? null : draft.trim();
    loadConfig.mutate(next, {
      onSuccess: () => {
        setConfigPath(next);
        queryClient.invalidateQueries({ queryKey: ["config"] });
        toast.success("Config loaded", {
          description: next ?? "~/.ssh/config",
        });
      },
    });
  };

  const onRetention = (v: string) => {
    const limit = v === RETENTION_ALL ? null : Number(v);
    setBackupRetention(limit);
    tauriInvoke<void>("config_set_backup_retention", { limit }).catch((e) =>
      toast.error("Could not update backup retention", { description: String(e) }),
    );
  };

  return (
    <>
      <Section
        title="Config file"
        description="The ssh_config file SSHelter edits. Leave empty for ~/.ssh/config."
      >
        <SettingsGroup>
          <div className="flex items-center gap-1.5 px-3 py-2">
            <Input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="~/.ssh/config"
              aria-label="Config file path"
              spellCheck={false}
              className="h-7 flex-1 border-0 bg-transparent px-2 font-mono text-sm shadow-none focus-visible:bg-muted/60 focus-visible:ring-0 dark:bg-transparent"
              onKeyDown={(e) => {
                if (isImeKey(e)) return;
                if (e.key === "Enter") applyPath();
              }}
            />
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="h-7 shrink-0"
              onClick={applyPath}
              disabled={loadConfig.isPending || (draft.trim() || "") === (configPath ?? "")}
            >
              {loadConfig.isPending ? "Loading…" : "Apply"}
            </Button>
          </div>
        </SettingsGroup>
      </Section>

      <Section
        title="Backups"
        description="A backup is written before every change. Older backups beyond the limit are pruned."
      >
        <SettingsGroup>
          <SettingsRow label="Backup retention">
            <Select
              value={backupRetention === null ? RETENTION_ALL : String(backupRetention)}
              onValueChange={onRetention}
            >
              <SelectTrigger className="h-7 w-[10rem] text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="10">Keep last 10</SelectItem>
                <SelectItem value="20">Keep last 20</SelectItem>
                <SelectItem value="50">Keep last 50</SelectItem>
                <SelectItem value={RETENTION_ALL}>Keep all</SelectItem>
              </SelectContent>
            </Select>
          </SettingsRow>
        </SettingsGroup>
      </Section>
    </>
  );
}

function shellQuoted(value: string, platform: string | undefined): string {
  if (platform === "windows") {
    return `"${value.replace(/"/g, '`"')}"`;
  }
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function LegacyMcpPane() {
  const query = useHostsQuery();
  return <McpPane hosts={(query.data?.hosts ?? []).filter(host => !isWildcardOnly(host)).map(host => ({ id: host.alias, alias: host.alias, hostname: host.hostname, user: host.user }))} />;
}

export function McpPane({ hosts, records = false }: {
  hosts: Array<{id: string; alias: string; hostname: string | null; user: string | null; port?: number; groupPath?: string}>;
  records?: boolean;
}) {
  const status = useMcpStatus(2_000);
  const platform = usePlatform();
  const setEnabled = useSetMcpEnabled();
  const setHostAllowed = useSetMcpHostAllowed();
  const setMode = useSetMcpApprovalMode();
  const [riskOpen, setRiskOpen] = useState(false);
  const [riskAcknowledged, setRiskAcknowledged] = useState(false);
  const applyMode = (approvalMode: "ask" | "auto_log", riskAcknowledged: boolean) =>
    setMode.mutate({ approvalMode, riskAcknowledged }, {
      onSuccess: () => {
        setRiskOpen(false);
        setRiskAcknowledged(false);
      },
    });
  const allowed = new Set(status.data?.allowed_hosts ?? []);
  const setupCommand = status.data
    ? `codex mcp add sshelter -- ${shellQuoted(status.data.executable, platform.data)} --mcp`
    : "";

  const copySetup = async () => {
    try {
      await copyText(setupCommand);
      toast.success("Codex setup command copied");
    } catch (error) {
      toast.error("Could not copy setup command", { description: String(error) });
    }
  };

  return (
    <>
      <Section
        title="MCP access"
        description={records ? "AI clients can propose new connections for your review. Existing hosts require individual permission before inspection, fingerprint verification or command execution." : "Let local AI clients request SSH actions through SSHelter. Remote commands require an Allow once decision here."}
      >
        <SettingsGroup>
          <SettingsRow
            id="set-mcp-enabled"
            label="Enable AI access"
            description="Disabling immediately denies every pending request."
          >
            <Switch
              id="set-mcp-enabled"
              checked={status.data?.enabled === true}
              disabled={!status.data || status.isError || setEnabled.isPending}
              onCheckedChange={(enabled) => setEnabled.mutate(enabled)}
            />
          </SettingsRow>
          <SettingsRow
            label={records ? "Local MCP broker" : "Local approval bridge"}
            description={
              status.data?.last_client_at_ms
                ? `Last MCP activity ${new Date(status.data.last_client_at_ms).toLocaleString()}`
                : "Waiting for a local MCP client."
            }
          >
            <Badge variant={status.data?.bridge_active ? "secondary" : "outline"}>
              {status.data?.bridge_active ? "Ready" : "Unavailable"}
            </Badge>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      {records ? (
        <Section
          title="Command approval"
          description="Ask reviews each complete command before execution. Switching mode cancels active requests."
        >
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant={status.data?.approval_mode === "ask" ? "secondary" : "outline"}
              disabled={!status.data || setMode.isPending}
              onClick={() => {
                setRiskOpen(false);
                setRiskAcknowledged(false);
                chooseMcpMode("ask", false, applyMode);
              }}
            >Ask</Button>
            <Button
              variant={status.data?.approval_mode === "auto_log" ? "secondary" : "outline"}
              disabled={!status.data || setMode.isPending || status.data.approval_mode === "auto_log"}
              onClick={() => {
                setRiskAcknowledged(false);
                if (chooseMcpMode("auto_log", false, applyMode)) setRiskOpen(true);
              }}
            >Auto-log</Button>
          </div>
          <p className="mt-2 break-words text-xs text-muted-foreground">
            {status.data?.noninteractive_credentials_notice}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Auto-log command execution never opens authentication or trust windows. Use Verify server fingerprint in the host editor, or the separate MCP verify_host_key tool, to review a server key. Missing credentials or 2FA require Ask.
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            If background sync remains unavailable after a hidden launch, open SSHelter from the tray or launch the app normally, then retry. MCP approval does not activate background sync.
          </p>
        </Section>
      ) : (
        <p className="text-xs text-muted-foreground">
          Legacy uses Ask: each command requires Allow once. Auto-log is available in Records workspaces.
        </p>
      )}
      <AlertDialog
        open={riskOpen}
        onOpenChange={open => {
          setRiskOpen(open);
          if (!open) setRiskAcknowledged(false);
        }}
      >
        <AlertDialogContent onEscapeKeyDown={event => { if (setMode.isPending) event.preventDefault(); }}>
          <AlertDialogHeader>
            <AlertDialogTitle>Allow commands without review?</AlertDialogTitle>
            <AlertDialogDescription>
              Auto-log lets local MCP clients execute arbitrary shell commands on every individually allowed host without asking you first. Commands can delete files, change services or send data elsewhere. The audit records public metadata, not command output; logging cannot undo an action.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={riskAcknowledged}
              disabled={setMode.isPending}
              onChange={event => setRiskAcknowledged(event.target.checked)}
            />
            I understand that allowed hosts can be changed or lose data without a per-command review.
          </label>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={setMode.isPending}>Cancel</AlertDialogCancel>
            <Button
              disabled={!riskAcknowledged || setMode.isPending}
              onClick={() => chooseMcpMode("auto_log", riskAcknowledged, applyMode)}
            >{setMode.isPending ? "Applying…" : "Enable Auto-log"}</Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <Section
        title="Connect Codex"
        description="Run this once in a terminal. Codex will launch or reconnect to the SSHelter approval center when needed."
      >
        <div className="flex items-center gap-2 rounded-lg border bg-muted/30 p-2">
          <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap px-1 font-mono text-xs">
            {setupCommand || "Loading…"}
          </code>
          <Button
            type="button"
            variant="secondary"
            size="icon"
            className="size-7 shrink-0"
            aria-label="Copy Codex setup command"
            disabled={!setupCommand}
            onClick={copySetup}
          >
            <Copy className="size-3.5" />
          </Button>
        </div>
      </Section>

      <Section
        title="Allowed hosts"
        description={records ? "Select individual host IDs. Groups and inherited settings never grant access; Legacy alias permissions do not apply." : "Only explicitly selected aliases are visible to MCP clients. SSH config tags do not grant access."}
      >
        <div className="[&_label]:break-all [&_p]:break-all"><SettingsGroup>
          {hosts.length === 0 ? (
            <p className="px-3 py-3 text-sm text-muted-foreground">No SSH hosts loaded.</p>
          ) : (
            hosts.map((host) => (
              <SettingsRow
                key={host.id}
                id={`mcp-host-${host.id}`}
                label={host.alias}
                description={`${host.hostname ? `${host.user ? `${host.user}@` : ""}${host.hostname}${host.port ? `:${host.port}` : ""}` : "Uses the alias as its destination."}${records ? ` · ID: ${host.id} · Group: ${host.groupPath || "Ungrouped"}` : ""}`}
                mono
              >
                <Switch
                  id={`mcp-host-${host.id}`}
                  checked={allowed.has(host.id)}
                  disabled={!status.data || setHostAllowed.isPending}
                  onCheckedChange={(value) =>
                    setHostAllowed.mutate({ alias: host.id, allowed: value })
                  }
                />
              </SettingsRow>
            ))
          )}
        </SettingsGroup></div>
      </Section>

      <Section
        title="Recent activity"
        description="Latest 10 public audit entries, retained across restarts. Authorization does not mean command success. Output and authentication answers are never logged."
      >
        {status.data?.audit_error && <p role="alert" className="mb-2 break-words text-xs text-destructive">Audit persistence error: {status.data.audit_error}. Completed commands are not retried.</p>}
        {status.isError && <p role="alert" className="mb-2 text-xs text-destructive">AI access status is unavailable. Retry after the app reconnects.</p>}
        <SettingsGroup>
          {(status.data?.recent.length ?? 0) === 0 ? (
            <p className="px-3 py-3 text-sm text-muted-foreground">No AI commands yet.</p>
          ) : (
            auditRows(status.data?.recent ?? []).map(({ entry, key }) => (
              <div key={key} className="space-y-1 px-3 py-2">
                <div className="flex items-center justify-between gap-3">
                  <span className="min-w-0 break-all font-mono text-xs">{revealHidden(entry.alias)}</span>
                  <span className="break-words text-xs">{entry.client} · {entry.mode} · {entry.outcome.split("_").join(" ")}</span>
                </div>
                <p className="break-all text-xs text-muted-foreground">
                  ID: {entry.host_id ?? "Unknown"}
                  {entry.outcome.startsWith("host_")
                    ? " · Connection management · No remote command"
                    : ` · Ended: ${entry.ended ?? "unknown"} · Exit: ${entry.exit_code ?? "unknown"} · Signal: ${entry.signal ?? "none reported"}`}
                </p>
                <McpAttribution requestedBy={entry.requested_by} requesterId={entry.requester_id} clientInfo={entry.client_info} />
                <p className="truncate font-mono text-xs text-muted-foreground" title={entry.command}>
                  {entry.command}
                </p>
              </div>
            ))
          )}
        </SettingsGroup>
      </Section>

      <p className="text-xs text-muted-foreground">
        This controls requests made through SSHelter MCP. It cannot prevent software running as
        your OS account from invoking another SSH client directly.
      </p>
    </>
  );
}

const DRIFT_INTERVALS = [15, 30, 60] as const;

function AdvancedPane() {
  const discoverKnownHosts = useSettingsStore((s) => s.discoverKnownHosts);
  const setDiscoverKnownHosts = useSettingsStore((s) => s.setDiscoverKnownHosts);
  const discoverTailscale = useSettingsStore((s) => s.discoverTailscale);
  const setDiscoverTailscale = useSettingsStore((s) => s.setDiscoverTailscale);
  const driftAutoCheck = useSettingsStore((s) => s.driftAutoCheck);
  const setDriftAutoCheck = useSettingsStore((s) => s.setDriftAutoCheck);
  const driftIntervalSec = useSettingsStore((s) => s.driftIntervalSec);
  const setDriftIntervalSec = useSettingsStore((s) => s.setDriftIntervalSec);
  const lintRules = useSettingsStore((s) => s.lintRules);
  const setLintRule = useSettingsStore((s) => s.setLintRule);

  return (
    <>
      <Section
        title="Discovery sources"
        description="Where the Discover dialog finds host candidates."
      >
        <SettingsGroup>
          <SettingsRow id="set-discover-kh" label="known_hosts" mono>
            <Switch
              id="set-discover-kh"
              checked={discoverKnownHosts}
              onCheckedChange={setDiscoverKnownHosts}
            />
          </SettingsRow>
          <SettingsRow id="set-discover-ts" label="Tailscale">
            <Switch
              id="set-discover-ts"
              checked={discoverTailscale}
              onCheckedChange={setDiscoverTailscale}
            />
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="External changes"
        description="SSHelter always re-checks when the window regains focus."
      >
        <SettingsGroup>
          <SettingsRow id="set-drift-auto" label="Check for external changes automatically">
            <Switch
              id="set-drift-auto"
              checked={driftAutoCheck}
              onCheckedChange={setDriftAutoCheck}
            />
          </SettingsRow>
          <SettingsRow label="Check every">
            <Select
              value={String(driftIntervalSec)}
              onValueChange={(v) => setDriftIntervalSec(Number(v))}
              disabled={!driftAutoCheck}
            >
              <SelectTrigger className="h-7 w-[8rem] text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {DRIFT_INTERVALS.map((sec) => (
                  <SelectItem key={sec} value={String(sec)}>
                    {sec} seconds
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="Lint rules"
        description="Disabled rules are hidden from the lint report and the toolbar badge."
      >
        <SettingsGroup>
          {LINT_RULES.map((rule) => (
            <SettingsRow key={rule.id} id={`set-lint-${rule.id}`} label={rule.label}>
              <Switch
                id={`set-lint-${rule.id}`}
                checked={lintRules[rule.id] !== false}
                onCheckedChange={(v) => setLintRule(rule.id, v)}
              />
            </SettingsRow>
          ))}
        </SettingsGroup>
      </Section>
    </>
  );
}

/* ------------------------------------------------------------------------- */
/* Shared bits                                                               */
/* ------------------------------------------------------------------------- */

const THEME_OPTIONS: { value: ThemePref; label: string; icon: typeof Sun }[] = [
  { value: "system", label: "System", icon: Monitor },
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
];

/** A compact three-option segmented control for the theme preference. */
function ThemeSegmented({
  value,
  onChange,
}: {
  value: ThemePref;
  onChange: (theme: ThemePref) => void;
}) {
  return (
    <div
      role="radiogroup"
      aria-label="Theme"
      className="flex items-center gap-0.5 rounded-md bg-muted p-0.5"
    >
      {THEME_OPTIONS.map((opt) => {
        const active = value === opt.value;
        const Icon = opt.icon;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(opt.value)}
            className={cn(
              "flex items-center gap-1.5 rounded-[5px] px-2.5 py-1 text-sm transition-colors cursor-default",
              active
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            <Icon className="size-3.5" />
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

export default SettingsDialog;
