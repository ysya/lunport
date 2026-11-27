import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
  Bot,
  Info,
  FolderCog,
  Monitor,
  Moon,
  RefreshCw,
  Settings2,
  SlidersHorizontal,
  Search,
  ArrowRight,
  ArrowLeft,
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
import { usePlatform, useTerminals, useIsDevelopment } from "@/lib/queries";
import { tauriInvoke } from "@/lib/ipc";
import { useUpdaterState, updateInProgress } from "@/lib/updater";
import { UpdatesPane } from "@/components/UpdatesPane";
import { AboutPane } from "@/components/AboutPane";
import { isImeKey } from "@/lib/ime";
import {
  exportSettings,
  pickSettingsImport,
  applySettingsImport,
  type SettingsEnvelope,
} from "@/lib/settings-io";
import {
  FONT_SIZE_OPTIONS,
  quickConnectLabel,
  terminalSupportsNewTab,
  IN_APP_TERMINAL,
  clampTerminalFontSize,
  type ThemePref,
} from "@/lib/settings-logic";
import { cn } from "@/lib/utils";
import {
  useMcpStatus,
  useSetMcpEnabled,
  mcpGroupKey,
  mcpHostGroups,
  useSetMcpApprovalMode,
  useSetMcpTransferLimit,
} from "@/lib/mcp";

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
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { searchSettings, settingsDestinations, settingsSectionId } from "@/lib/settings-navigation";
import { Section, SettingsGroup, SettingsRow } from "@/components/settings-primitives";
import { revealHidden } from "@/lib/reveal-hidden";
import { chooseMcpMode } from "@/lib/mcp-flow";
import { McpActivitySummary } from "@/components/McpActivitySummary";
import { useNow } from "@/lib/use-now";
import { groupPath, groupAncestors } from "@/components/records/group-tree";
import { groupComparator } from "@/components/records/group-order";
import type { RecordOverview } from "@/lib/records";
import { KnownHostsManager } from "@/components/records/KnownHostsManager";
import { ColorThemePicker } from "@/components/ColorThemePicker";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { McpDatabaseAccess } from "@/components/McpDatabaseAccess";
import { McpClientSetup } from "@/components/McpClientSetup";
import { McpHostAccess, type McpAccessHost, type McpAccessGroup } from "@/components/McpHostAccess";

export function SettingsCategoryPane({
  category,
  recordOverview,
  onOpenImport,
  onOpenDataTools,
  onOpenSync,
  onOpenActivity,
  initialAiSection,
  aiDatabaseId,
}: {
  category: SettingsCategory;
  initialAiSection?: string | null;
  aiDatabaseId?: string | null;
  recordOverview: RecordOverview;
  onOpenImport?: () => void;
  onOpenDataTools?: () => void;
  onOpenSync?: () => void;
  onOpenActivity?: () => void;
}) {
  if (category === "general") return <GeneralPane />;
  if (category === "updates") return <UpdatesPane />;
  if (category === "about") return <AboutPane />;
  if (category === "appearance") return <AppearancePane />;
  if (category === "connection") return <ConnectionPane recordOverview={recordOverview} />;
  if (category === "files") return <>
    <Section title="Library & workspace tools" description="Use the library locally without an account. Signing in and unlocking enables automatic encrypted sync, including saved SSH passwords and all managed SSH keys. Import copies settings and leaves the source files in place.">
      <SettingsGroup>
        <SettingsRow label="Import hosts and Groups" description="Review SSH configuration, host exports or saved workspaces before adding settings."><Button variant="outline" size="sm" onClick={onOpenImport}>Open import…</Button></SettingsRow>
        <SettingsRow label="Automatic sync" description="Manage your account, devices and self-hosted server in the Sync workspace."><Button variant="outline" size="sm" onClick={onOpenSync}>Open sync</Button></SettingsRow>
        <SettingsRow label="Host and Group settings" description="Export this library or choose a retained workspace. Passwords, SSH private keys and account credentials are excluded."><Button variant="outline" size="sm" onClick={onOpenDataTools}>Export / saved workspaces…</Button></SettingsRow>
      </SettingsGroup>
    </Section>
    <PreferencesDataPane />
  </>;
  if (category === "ai")
    return (
      <McpPane
        key={initialAiSection ?? aiDatabaseId ?? "ai"}
        records
        recordOverview={recordOverview}
        databaseId={initialAiSection ? null : aiDatabaseId ?? null}
        initialSection={initialAiSection}
        openActivity={onOpenActivity}
        generation={recordOverview.generation}
        groups={[...recordOverview.groups].sort(groupComparator(recordOverview.group_order?.ids ?? [])).map((group) => {
          const chain = groupAncestors(recordOverview, group.id, group.scope);
          return {
            id: group.id, name: revealHidden(group.payload.name), scope: group.scope,
            key: mcpGroupKey(group.scope, group.id),
            path: revealHidden(groupPath(recordOverview, group.id, group.scope)),
            error: chain.error,
            ancestorKeys: chain.groups.slice(1).map((parent) => mcpGroupKey(parent.scope, parent.id)),
          };
        })}
        hosts={recordOverview.hosts.map((host) => ({
          id: host.id,
          alias: revealHidden(host.payload.alias),
          hostname: revealHidden(host.effective_payload.hostname),
          user: revealHidden(host.effective_payload.user),
          port: host.effective_payload.port,
          groupPath: revealHidden(groupPath(recordOverview, host.payload.group_id, host.scope)),
          groupKeys: mcpHostGroups(recordOverview, host).map((group) => mcpGroupKey(group.scope, group.id)),
        }))}
      />
    );
  if (category === "sync")
    return (
      <Section
        title="Encrypted sync"
        description="Manage your account, approved devices and sync server in the Sync workspace."
      >
        <Button variant="outline" onClick={onOpenSync}>
          Open sync workspace
        </Button>
      </Section>
    );
  return <>
    <DiagnosticsPane />
    <Section title="Workspace capabilities" description="This workspace uses Lunport's built-in SSH engine. Use hosts and keys locally without an account, or enable encrypted library sync across your approved devices.">
      <p className="text-sm leading-relaxed text-muted-foreground">MCP can inspect hosts allowed individually or through explicitly allowed Groups, and execute SSH commands with Ask approval or explicitly acknowledged Auto-log. Cloud SQL databases can be allowed individually in AI access; direct SQL writes always require confirmation. Connection defaults alone never grant AI access. Both modes can request credentials through Lunport’s native windows for the current connection.</p>
    </Section>
  </>;
}

/** Radix Select values must be non-empty; this sentinel round-trips to `null`. */
const TERMINAL_DEFAULT = "__default__";

const CATEGORY_ICONS = { general: Settings2, appearance: SunMoon, connection: TerminalSquare, files: FolderCog, ai: Bot, sync: RefreshCw, updates: RefreshCw, advanced: SlidersHorizontal, about: Info };

/**
 * The Settings page (⌘,): a sidebar + detail view that keeps the workspace mounted.
 * Preferences persist via `useSettingsStore` (zustand persist); the ones the
 * backend also needs (tray, close-to-tray, retention) are mirrored with
 * fire-and-forget invokes here and re-sent on launch by
 * `useSyncBackendSettings`. Open state lives in the UI store so the toolbar
 * gear, the ⌘K palette, and the ⌘, shortcut can all drive it.
 */
export function SettingsPage({ recordOverview, onOpenImport, onOpenDataTools, onOpenSync, onOpenActivity }: {
  recordOverview: RecordOverview;
  onOpenImport?: () => void;
  onOpenDataTools?: () => void;
  onOpenSync?: () => void;
  onOpenActivity?: () => void;
}) {
  const contentRef = useRef<HTMLElement>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const open = useUiStore((s) => s.settingsOpen);
  const setOpen = useUiStore((s) => s.setSettingsOpen);
  const category = useUiStore((s) => s.settingsCategory);
  const aiDatabaseId = useUiStore((s) => s.settingsAiDatabaseId);
  const setCategory = useUiStore((s) => s.setSettingsCategory);
  const platform = usePlatform();

  useEffect(() => {
    if (!open) return;
    const origin = document.activeElement;
    returnFocusRef.current = origin instanceof HTMLElement && origin !== document.body && !contentRef.current?.contains(origin) ? origin : null;
    const frame = useUiStore.getState().settingsAiDatabaseId ? null
      : requestAnimationFrame(() => contentRef.current?.querySelector<HTMLButtonElement>('button[aria-current="page"]')?.focus());
    return () => {
      if (frame !== null) cancelAnimationFrame(frame);
      requestAnimationFrame(() => {
        const previous = returnFocusRef.current;
        if (previous?.isConnected && !previous.closest("[inert]")) previous.focus();
        else document.querySelector<HTMLButtonElement>('button[aria-label="Settings"]')?.focus();
      });
    };
  }, [open]);

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
  const categories = settingsDestinations();
  const active = categories.find((item) => item.id === category) ?? categories.find((item) => item.id === "files")!;
  const [search, setSearch] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [target, setTarget] = useState<string | null>(null);
  const [filesVisited, setFilesVisited] = useState(false);
  const results = searchSettings(search);
  const searching = search.trim().length > 0;

  useEffect(() => {
    if (open && active.id === "files") setFilesVisited(true);
  }, [open, active.id]);
  useEffect(() => {
    if (!open) { setSearch(""); setTarget(null); setFilesVisited(false); }
  }, [open]);
  useEffect(() => {
    if (!open || searching || (active.id === "ai" && aiDatabaseId && !target)) return;
    const frame = requestAnimationFrame(() => {
      if (target) {
        const section = contentRef.current?.querySelector<HTMLElement>(`#${target}`);
        section?.scrollIntoView({ block: "start", behavior: "instant" });
        section?.focus({ preventScroll: true });
      } else scrollRef.current?.scrollTo({ top: 0 });
    });
    return () => cancelAnimationFrame(frame);
  }, [active.id, aiDatabaseId, open, searching, target]);
  const close = (next: boolean) => setOpen(next);
  const navigate = (next: SettingsCategory) => { setSearch(""); setTarget(null); setCategory(next); };
  const jump = (next: SettingsCategory, anchor: string | null) => { navigate(next); setTarget(anchor ?? "settings-category-title"); };

  if (!open) return null;
  return <>
      <main ref={contentRef} className={cn("app-shell settings-page", platform.data === "macos" && "is-macos")} aria-labelledby="settings-page-title"
        onKeyDown={(event) => {
          if (event.defaultPrevented || isImeKey(event) || !event.currentTarget.contains(event.target as Node)) return;
          if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "f") { event.preventDefault(); event.stopPropagation(); searchRef.current?.focus(); }
          if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close(false); }
        }}>
        <header className="settings-page-header" data-tauri-drag-region>
          <Button variant="ghost" size="sm" aria-label="Back to workspace" onClick={() => close(false)}><ArrowLeft className="size-4" />Back</Button>
          <h1 id="settings-page-title">Settings</h1>
          <p>Records library</p>
        </header>
        <div className="settings-layout">
          <aside className="settings-navigation">
            <div className="settings-search"><Search className="size-3.5" aria-hidden="true" /><Input ref={searchRef} value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search settings…" aria-label="Search settings" onKeyDown={(event) => {
              if (isImeKey(event)) return;
              if (event.key === "Escape" && search) { event.preventDefault(); event.stopPropagation(); setSearch(""); }
              if (event.key === "Enter" && results[0]) { event.preventDefault(); jump(results[0].category, results[0].target); }
            }} /></div>
            <nav aria-label="Settings categories" onKeyDown={(event) => {
              if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
              const buttons = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>("button"));
              const current = buttons.indexOf(document.activeElement as HTMLButtonElement);
              if (current < 0) return;
              event.preventDefault();
              const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : (current + (event.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length;
              buttons[next]?.focus();
            }}>
              {(["Application", "Workspace", "Maintenance"] as const).map((group) => <div className="settings-nav-group" key={group}>
                <p>{group}</p>
                {categories.filter((item) => item.group === group).map((item) => {
                  const Icon = CATEGORY_ICONS[item.id];
                  return <button key={item.id} type="button" aria-current={!searching && active.id === item.id ? "page" : undefined} onClick={() => navigate(item.id)}>
                    <Icon className="size-4 shrink-0" aria-hidden="true" /><span>{item.label}</span>
                    {item.id === "updates" && updateAttention && <span aria-label="Update needs attention" className="ml-auto size-1.5 shrink-0 rounded-full bg-primary" />}
                  </button>;
                })}
              </div>)}
            </nav>
          </aside>
          <div className="settings-detail">
            <header className="settings-category-header"><h2 id="settings-category-title" tabIndex={-1}>{searching ? "Search results" : active.label}</h2><p>{searching ? `${results.length} matching sections` : active.description}</p></header>
            <div className="settings-content" ref={scrollRef}>
              {(filesVisited || active.id === "files") && <div hidden={searching || active.id !== "files"} className="settings-pane"><SettingsCategoryPane category="files" recordOverview={recordOverview} onOpenImport={onOpenImport} onOpenDataTools={onOpenDataTools} onOpenSync={onOpenSync} /></div>}
              {searching ? <div className="settings-results">
                {results.length ? results.map((result) => <button key={`${result.category}-${result.title}`} type="button" onClick={() => jump(result.category, result.target)}>
                  <span><small>{result.categoryLabel}</small><strong>{result.title}</strong><span>{result.detail}</span></span><ArrowRight className="size-4 shrink-0" aria-hidden="true" />
                </button>) : <div className="app-empty-state"><h2>No matching settings</h2><p>Try a preference name such as “theme”, “terminal” or “logs”.</p><Button variant="outline" size="sm" onClick={() => { setSearch(""); searchRef.current?.focus(); }}>Clear search</Button></div>}
              </div> : <>
                {active.id !== "files" && <div className="settings-pane" key={active.id}><SettingsCategoryPane category={active.id} recordOverview={recordOverview} onOpenImport={onOpenImport} onOpenDataTools={onOpenDataTools} onOpenSync={onOpenSync} onOpenActivity={onOpenActivity} initialAiSection={target} aiDatabaseId={aiDatabaseId} /></div>}
              </>}
            </div>
          </div>
        </div>
      </main>
  </>;
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


  return (
    <>
      <Section title="Startup & window">
        <SettingsGroup>
          <SettingsRow id="set-tray" label={platform.data === "macos" ? "Show menu bar icon" : "Show system tray icon"}>
            <Switch id="set-tray" checked={trayVisible} onCheckedChange={onTray} />
          </SettingsRow>
          <SettingsRow
            id="set-close-to-tray"
            label="Keep running when the window closes"
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
            description={!integrationsAllowed ? "OS startup integration is unavailable in development builds." : "Reflects your system startup settings."}
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
        description="Brings Lunport to the front with the command palette open, from any app."
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
            <span className="text-sm text-muted-foreground">English</span>
          </SettingsRow>
        </SettingsGroup>
      </Section>


    </>
  );
}

function PreferencesDataPane() {
  // A validated-but-unconfirmed settings import (drives the overwrite AlertDialog).
  const [pendingImport, setPendingImport] = useState<SettingsEnvelope | null>(null);
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

  return <>
      <Section
        title="Preferences transfer"
        description="Preferences only — your SSH config, keys, and hosts are never included."
      >
        <SettingsGroup>
          <SettingsRow
            label="Export app preferences"
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
            label="Import app preferences"
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
              Importing replaces every Lunport preference with the contents of
              the selected file. Your SSH config files are not affected.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={confirmImport}>Import</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
  </>;
}

function DiagnosticsPane() {
  return <Section title="Diagnostic logs" description="Local diagnostics for troubleshooting this installation."><SettingsGroup>
          <SettingsRow
            label="Diagnostic logs"
            description="Local startup and error logs. Hosts, credentials and sync codes are excluded."
          >
            <Button type="button" variant="secondary" size="sm" className="h-7"
              onClick={() => tauriInvoke<void>("app_open_diagnostics").catch(() => toast.error("Could not open diagnostic logs"))}>
              Open logs
            </Button>
          </SettingsRow>

  </SettingsGroup></Section>;
}

function AppearancePane() {
  const theme = useSettingsStore((s) => s.theme);
  const setTheme = useSettingsStore((s) => s.setTheme);
  const fontSize = useSettingsStore((s) => s.fontSize);
  const setFontSize = useSettingsStore((s) => s.setFontSize);
  const showHostTags = useSettingsStore((s) => s.showHostTags);
  const setShowHostTags = useSettingsStore((s) => s.setShowHostTags);
  const motion = useSettingsStore((s) => s.motion);
  const setMotion = useSettingsStore((s) => s.setMotion);
  return (
    <><Section title="Color theme" description="Choose a palette for Lunport and its in-app terminal. External terminals keep their own themes.">
      <SettingsGroup>
        <SettingsRow label="Appearance" description="System follows your OS light or dark mode.">
          <ThemeSegmented value={theme} onChange={setTheme} />
        </SettingsRow>
      </SettingsGroup>
      <ColorThemePicker />
    </Section>
    <Section
      title="Display"
      description="Text size scales the whole interface."
    >
      <SettingsGroup>
        <SettingsRow id="set-font-size" label="Text size">
          <Select
            value={String(fontSize)}
            onValueChange={(v) => setFontSize(Number(v))}
          >
            <SelectTrigger id="set-font-size" className="settings-select">
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
        <SettingsRow id="set-motion" label="Motion" description="System follows your OS preference for reduced motion.">
          <Select value={motion === "reduced" ? "reduced" : "system"} onValueChange={(value) => setMotion(value === "reduced" ? "reduced" : "system")}>
            <SelectTrigger id="set-motion" className="settings-select"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="system">System</SelectItem>
              <SelectItem value="reduced">Reduced</SelectItem>
            </SelectContent>
          </Select>
        </SettingsRow>
        <SettingsRow
          id="set-show-host-tags"
          label="Show tags in host list"
          description="Show tags alongside hosts in the list."
        >
          <Switch
            id="set-show-host-tags"
            checked={showHostTags}
            onCheckedChange={setShowHostTags}
          />
        </SettingsRow>
      </SettingsGroup>
    </Section></>
  );
}

function ConnectionPane({ recordOverview }: { recordOverview: RecordOverview }) {
  const terminalId = useSettingsStore((s) => s.terminalId);
  const setTerminalId = useSettingsStore((s) => s.setTerminalId);
  const newTabConnect = useSettingsStore((s) => s.newTabConnect);
  const setNewTabConnect = useSettingsStore((s) => s.setNewTabConnect);
  const terminals = useTerminals();
  const terminalFontSize = useSettingsStore((s) => clampTerminalFontSize(s.terminalFontSize));
  const setTerminalFontSize = useSettingsStore((s) => s.setTerminalFontSize);
  const cursorBlink = useSettingsStore((s) => s.terminalCursorBlink !== false);
  const setCursorBlink = useSettingsStore((s) => s.setTerminalCursorBlink);
  const confirmTerminalClose = useSettingsStore((s) => s.confirmTerminalClose !== false);
  const setConfirmTerminalClose = useSettingsStore((s) => s.setConfirmTerminalClose);

  const supportsNewTab = terminalSupportsNewTab(terminalId, terminals.data ?? []);

  return (
    <><Section
      title="Terminal"
      description="Connect inside Lunport or open an external terminal. Existing terminal sessions stay connected when you switch views."
    >
      <SettingsGroup>
        <SettingsRow id="set-terminal" label="Default terminal">
          <Select
            value={terminalId ?? TERMINAL_DEFAULT}
            onValueChange={(v) => setTerminalId(v === TERMINAL_DEFAULT ? null : v)}
          >
            <SelectTrigger id="set-terminal" className="settings-select">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={IN_APP_TERMINAL}>Lunport (in app)</SelectItem>
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
            terminalId === IN_APP_TERMINAL
              ? "Lunport opens each connection in its own session tab."
              : supportsNewTab
              ? "Opens a tab in an existing window instead of a new window."
              : "The selected terminal doesn’t support opening new tabs."
          }
        >
          <Switch
            id="set-new-tab"
            checked={terminalId === IN_APP_TERMINAL || newTabConnect}
            onCheckedChange={setNewTabConnect}
            disabled={!supportsNewTab}
          />
        </SettingsRow>
      </SettingsGroup>
    </Section>
    <Section title="In-app terminal" description="Colors follow Appearance. Search with ⌘F / Ctrl+F, switch sessions with Ctrl+Tab, and zoom with ⌘ / Ctrl + or −.">
      <SettingsGroup>
        <SettingsRow id="set-terminal-font" label="Terminal text size" description="Applies to all in-app terminal tabs without reconnecting.">
          <Select value={String(terminalFontSize)} onValueChange={(value) => setTerminalFontSize(Number(value))}>
            <SelectTrigger id="set-terminal-font" className="settings-select"><SelectValue /></SelectTrigger>
            <SelectContent>{Array.from({ length: 15 }, (_, i) => i + 10).map((size) => <SelectItem key={size} value={String(size)}>{size} px</SelectItem>)}</SelectContent>
          </Select>
        </SettingsRow>
        <SettingsRow id="set-terminal-cursor" label="Blink cursor" description="Reduced-motion preferences take priority."><Switch id="set-terminal-cursor" checked={cursorBlink} onCheckedChange={setCursorBlink} /></SettingsRow>
        <SettingsRow id="set-terminal-close-confirmation" label="Confirm before closing a terminal" description="Ask before ending a connected or connecting in-app session."><Switch id="set-terminal-close-confirmation" checked={confirmTerminalClose} onCheckedChange={setConfirmTerminalClose} /></SettingsRow>
      </SettingsGroup>
      <p className="mt-3 text-xs leading-relaxed text-muted-foreground">Switching tabs keeps SSH connected. Closing a tab, reloading the workspace, quitting or installing an update ends its session. Reconnect starts a new shell.</p>
    </Section>
    <FileTransferSettings />
    <Section title="Known hosts" description="Inspect trusted server fingerprints and manage local OpenSSH host keys.">
      <SettingsGroup><SettingsRow label="Saved server identities" description="Review fingerprints, verify a server again, or forget an old identity."><KnownHostsManager overview={recordOverview} /></SettingsRow></SettingsGroup>
    </Section></>
  );
}

function FileTransferSettings() {
  const status = useMcpStatus();
  const setTransferLimit = useSetMcpTransferLimit();
  const [transferLimitInput, setTransferLimitInput] = useState(() => String(status.data?.max_transfer_mib ?? 1024));
  useEffect(() => {
    if (status.data) setTransferLimitInput(String(status.data.max_transfer_mib));
  }, [status.data?.max_transfer_mib]);
  const transferLimit = Number(transferLimitInput);
  const transferLimitValid = /^\d+$/.test(transferLimitInput) && Number.isSafeInteger(transferLimit) && transferLimit >= 1 && transferLimit <= 10_240;
  return <Section title="File transfers" description="Set the largest single file you or an AI client can upload or download through Lunport SCP on this device.">
    <SettingsGroup>
      <SettingsRow id="set-mcp-transfer-limit" label="Single-file transfer limit" description="1–10,240 MiB. The default is 1,024 MiB; changing the limit cancels active AI transfers and applies to new Files transfers.">
        <form className="flex items-center gap-2" onSubmit={(event) => {
          event.preventDefault();
          if (transferLimitValid && !status.isError && status.data && transferLimit !== status.data.max_transfer_mib) setTransferLimit.mutate(transferLimit);
        }}>
          <Input aria-label="Single-file transfer limit in MiB" type="number" min={1} max={10_240} step={1} value={transferLimitInput}
            onChange={(event) => setTransferLimitInput(event.target.value)} className="w-28" disabled={!status.data || status.isError || setTransferLimit.isPending} />
          <span className="text-sm text-muted-foreground">MiB</span>
          <Button type="submit" size="sm" variant="outline" disabled={!status.data || status.isError || setTransferLimit.isPending || !transferLimitValid || transferLimit === status.data.max_transfer_mib}>Save limit</Button>
        </form>
      </SettingsRow>
    </SettingsGroup>
  </Section>;
}

export function McpPane({
  hosts, groups = [], generation, records = false, recordOverview, initialSection, databaseId = null, openActivity,
}: {
  hosts: McpAccessHost[];
  generation?: string;
  groups?: McpAccessGroup[];
  records?: boolean;
  recordOverview?: RecordOverview;
  initialSection?: string | null;
  databaseId?: string | null;
  openActivity?: () => void;
}) {
  const status = useMcpStatus(2_000);
  const now = useNow();
  const setEnabled = useSetMcpEnabled();
  const setMode = useSetMcpApprovalMode();
  const [riskOpen, setRiskOpen] = useState(false);
  const [riskAcknowledged, setRiskAcknowledged] = useState(false);
  const policy = status.isError ? undefined : status.data;
  const tab = initialSection === settingsSectionId("AI operation approval") && records ? "approvals"
    : initialSection === settingsSectionId("Connect an AI tool") ? "clients" : "resources";

  const applyMode = (approvalMode: "ask" | "auto_log", riskAcknowledged: boolean) =>
    setMode.mutate({ approvalMode, riskAcknowledged }, {
      onSuccess: () => {
        setRiskOpen(false);
        setRiskAcknowledged(false);
      },
    });

  return <>
    <div id={settingsSectionId("MCP access")} tabIndex={-1}>
      <SettingsGroup>
        <SettingsRow
          id="set-mcp-enabled"
          label="Enable AI access"
          description="Controls local MCP requests on this device. Turning it off cancels pending requests and keeps your saved rules."
        >
          <Switch id="set-mcp-enabled" checked={policy?.enabled === true} disabled={!policy || setEnabled.isPending}
            onCheckedChange={(enabled) => setEnabled.mutate(enabled)} />
        </SettingsRow>
        {status.isError && <div role="alert" className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm text-destructive">
          AI access status is unavailable.<Button size="sm" variant="outline" onClick={() => void status.refetch()}>Retry</Button>
        </div>}
        {policy?.enabled && !policy.bridge_active && <p role="status" className="px-3 py-2 text-xs text-warning">The local AI service is unavailable. Restart Lunport to connect tools.</p>}
      </SettingsGroup>
    </div>
    <Tabs defaultValue={tab} aria-label="AI access settings" className="gap-4">
      <TabsList variant="line" aria-label="AI access settings" className="w-full justify-start border-b pb-1">
        <TabsTrigger value="resources" className="flex-none px-3">Resources</TabsTrigger>
        {records && <TabsTrigger value="approvals" className="flex-none px-3">Approvals</TabsTrigger>}
        <TabsTrigger value="clients" className="flex-none px-3">Clients</TabsTrigger>
      </TabsList>
      <TabsContent value="resources">
        <McpHostAccess
          hosts={hosts}
          groups={groups}
          generation={generation}
          records={records}
          status={policy}
          unavailable={status.isError}
          showDatabases={databaseId !== null || initialSection === settingsSectionId("Cloud SQL access")}
          cloudSql={recordOverview && <McpDatabaseAccess overview={recordOverview} status={policy} databaseId={databaseId} />}
        />
      </TabsContent>
      {records && <TabsContent value="approvals">
        <Section title="AI operation approval" description="Choose how this device reviews requests from its AI tools. Switching mode cancels active requests.">
          <div role="group" aria-label="Approval mode" className="flex flex-wrap items-center gap-2">
            <Button
              variant={policy?.approval_mode === "ask" ? "secondary" : "outline"}
              aria-pressed={policy?.approval_mode === "ask"}
              disabled={!policy || setMode.isPending}
              onClick={() => chooseMcpMode("ask", false, applyMode)}
            >Ask</Button>
            <Button
              variant={policy?.approval_mode === "auto_log" ? "secondary" : "outline"}
              aria-pressed={policy?.approval_mode === "auto_log"}
              disabled={!policy || setMode.isPending || policy.approval_mode === "auto_log"}
              onClick={() => {
                setRiskAcknowledged(false);
                if (chooseMcpMode("auto_log", false, applyMode)) setRiskOpen(true);
              }}
            >Auto-log</Button>
          </div>
          <dl className="mt-4 divide-y rounded-lg border bg-card/30">
            <div className="space-y-1 px-3 py-2.5">
              <dt className="text-sm font-medium">Follows the selected mode</dt>
              <dd className="text-xs text-muted-foreground">Ask shows the command, paths or SQL before it runs. Auto-log runs ordinary SSH commands, transfers, direct SQL reads and tunnel or database starts without per-operation review.</dd>
            </div>
            <div className="space-y-1 px-3 py-2.5">
              <dt className="text-sm font-medium">Always asks</dt>
              <dd className="text-xs text-muted-foreground">Direct SQL writes, dedicated sudo commands and changes to saved connection records require approval. Production SQL writes also request system authorization where available.</dd>
            </div>
            <div className="space-y-1 px-3 py-2.5">
              <dt className="text-sm font-medium">Connection prompts</dt>
              <dd className="text-xs text-muted-foreground">Lunport may ask for credentials, 2FA, server identity verification or a PAM grant in either mode.</dd>
              {policy?.noninteractive_credentials_notice && <dd className="text-xs text-muted-foreground">{policy.noninteractive_credentials_notice}</dd>}
            </div>
          </dl>
        </Section>
      </TabsContent>}
      <TabsContent value="clients">
        <McpClientSetup fallbackExecutable={policy?.executable} connectionNote={
          !policy ? undefined : !policy.enabled ? "AI access is off. Turn it on when you’re ready to use connected tools."
            : !policy.bridge_active ? "The local AI service is unavailable."
            : policy.last_client_at_ms ? "Last AI tool activity " + new Date(policy.last_client_at_ms).toLocaleString()
            : "Ready for a local AI tool to connect."
        } />
      </TabsContent>
    </Tabs>
    <AlertDialog
      open={riskOpen}
      onOpenChange={open => {
        setRiskOpen(open);
        if (!open) setRiskAcknowledged(false);
      }}
    >
      <AlertDialogContent onEscapeKeyDown={event => { if (setMode.isPending) event.preventDefault(); }}>
        <AlertDialogHeader>
          <AlertDialogTitle>Allow AI operations without review?</AlertDialogTitle>
          <AlertDialogDescription>
            Auto-log lets local MCP clients execute ordinary shell commands and transfer files on allowed hosts, including current and future Group members. It also lets them start tunnels or databases and run direct SQL reads on allowed databases without asking you first. The dedicated sudo tool still asks each time, but ordinary commands can also use sudo if the remote account permits it. Commands can delete files or change services, and transfers can replace remote files or copy files to this computer. The audit records public metadata, not command output or file contents; logging cannot undo an action.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={riskAcknowledged}
            disabled={setMode.isPending}
            onChange={event => setRiskAcknowledged(event.target.checked)}
          />
          I understand that Auto-log can change or expose data without per-operation review.
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
    <Section title="Activity" description="See the outcome of each recorded AI request.">
      {policy?.audit_error && <p role="alert" className="mb-2 break-words text-xs text-destructive">Audit persistence error: {revealHidden(policy.audit_error)}. Completed commands are not retried.</p>}
      <SettingsGroup><McpActivitySummary latest={policy?.recent[0]} now={now} open={openActivity} /></SettingsGroup>
    </Section>
  </>;
}

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
      aria-label="Appearance"
      onKeyDown={(event) => {
        if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        const current = THEME_OPTIONS.findIndex((option) => option.value === value);
        const next = event.key === "Home" ? 0 : event.key === "End" ? THEME_OPTIONS.length - 1 : (current + (["ArrowRight", "ArrowDown"].includes(event.key) ? 1 : -1) + THEME_OPTIONS.length) % THEME_OPTIONS.length;
        onChange(THEME_OPTIONS[next].value);
        event.currentTarget.querySelectorAll<HTMLButtonElement>('button')[next]?.focus();
      }}
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
            tabIndex={active ? 0 : -1}
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

export default SettingsPage;
