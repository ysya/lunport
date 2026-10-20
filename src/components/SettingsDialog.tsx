import { auditRows } from "@/lib/mcp-audit-rows";
import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
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
  LINT_RULES,
  quickConnectLabel,
  terminalSupportsNewTab,
  IN_APP_TERMINAL,
  clampTerminalFontSize,
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
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { searchSettings, settingsDestinations, type SettingsMode } from "@/lib/settings-navigation";
import { Section, SettingsGroup, SettingsRow } from "@/components/settings-primitives";
import { CentralAccountSection } from "@/components/records/CentralAccountPanel";
import { revealHidden } from "@/lib/sync-approvals";
import { chooseMcpMode } from "@/lib/mcp-flow";
import { McpAttribution } from "@/components/McpAttribution";
import { groupPath } from "@/components/records/group-tree";
import type { RecordOverview } from "@/lib/records";
import { KnownHostsManager } from "@/components/records/KnownHostsManager";
import { ColorThemePicker } from "@/components/ColorThemePicker";
import { McpClientSetup } from "@/components/McpClientSetup";

export function SettingsCategoryPane({
  category,
  recordOverview,
  onOpenImport,
  onOpenSync,
  onConfigDirtyChange,
  onConfigBusyChange,
}: {
  onConfigDirtyChange?: (dirty: boolean) => void;
  onConfigBusyChange?: (busy: boolean) => void;
  category: SettingsCategory;
  recordOverview?: RecordOverview;
  onOpenImport?: () => void;
  onOpenSync?: () => void;
}) {
  if (category === "general") return <GeneralPane />;
  if (category === "updates") return <UpdatesPane />;
  if (category === "about") return <AboutPane />;
  if (category === "appearance") return <AppearancePane />;
  if (category === "connection") return <ConnectionPane recordOverview={recordOverview} />;
  if (category === "files") return <>
    {recordOverview ? <Section title="Library & workspace tools" description="Hosts and keys stay in this local library unless you explicitly share them. Import copies selected entries and leaves the source files in place.">
      <SettingsGroup>
        <SettingsRow label="Import SSH configuration" description="Review hosts and keys before adding them to the library."><Button variant="outline" size="sm" onClick={onOpenImport}>Open import…</Button></SettingsRow>
        <SettingsRow label="Library sync" description="Manage your relay, devices and shared library in the Sync workspace."><Button variant="outline" size="sm" onClick={onOpenSync}>Open sync</Button></SettingsRow>
      </SettingsGroup>
    </Section> : <FilesPane onDirtyChange={onConfigDirtyChange} onBusyChange={onConfigBusyChange} />}
    <PreferencesDataPane />
  </>;
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
        title="Encrypted sync"
        description="Manage your account, approved devices and sync server in the Sync workspace."
      >
        <Button variant="outline" onClick={onOpenSync}>
          Open sync workspace
        </Button>
      </Section>
    ) : (
      <CentralAccountSection />
    );
  return <>
    <DiagnosticsPane />
    {recordOverview ? <Section title="Workspace capabilities" description="This workspace uses Lunport's built-in SSH engine. Use hosts and keys locally without an account, or enable encrypted library sync across your approved devices.">
      <p className="text-sm leading-relaxed text-muted-foreground">MCP can inspect individually allowed hosts and execute SSH commands with Ask approval or explicitly acknowledged Auto-log. Group defaults never grant AI access. MCP authentication is request-scoped and Auto-log never prompts or trusts a new server.</p>
    </Section> : <AdvancedPane />}
  </>;
}

/** Radix Select values must be non-empty; this sentinel round-trips to `null`. */
const TERMINAL_DEFAULT = "__default__";
/** Sentinel for "keep all backups" (backupRetention = null). */
const RETENTION_ALL = "__all__";

const CATEGORY_ICONS = { general: Settings2, appearance: SunMoon, connection: TerminalSquare, files: FolderCog, ai: Bot, sync: RefreshCw, updates: RefreshCw, advanced: SlidersHorizontal, about: Info };

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
  const returnFocusRef = useRef<HTMLElement | null>(null);
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
  const mode: SettingsMode = recordOverview ? "records" : "legacy";
  const categories = settingsDestinations(mode);
  const active = categories.find((item) => item.id === category) ?? categories.find((item) => item.id === "files")!;
  const [search, setSearch] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [target, setTarget] = useState<string | null>(null);
  const [filesVisited, setFilesVisited] = useState(false);
  const [syncVisited, setSyncVisited] = useState(false);
  const [configDirty, setConfigDirty] = useState(false);
  const [configBusy, setConfigBusy] = useState(false);
  const [confirmClose, setConfirmClose] = useState(false);
  const results = searchSettings(search, mode);
  const searching = search.trim().length > 0;

  useEffect(() => {
    if (open && active.id === "files") setFilesVisited(true);
    if (open && active.id === "sync") setSyncVisited(true);
  }, [open, active.id]);
  useEffect(() => {
    if (!open) { setSearch(""); setFilesVisited(false); setSyncVisited(false); setConfigDirty(false); setConfigBusy(false); setConfirmClose(false); }
  }, [open]);
  useEffect(() => {
    if (!open || searching) return;
    const frame = requestAnimationFrame(() => {
      if (target) {
        const section = contentRef.current?.querySelector<HTMLElement>(`#${target}`);
        section?.scrollIntoView({ block: "start", behavior: "instant" });
        section?.focus({ preventScroll: true });
      } else scrollRef.current?.scrollTo({ top: 0 });
    });
    return () => cancelAnimationFrame(frame);
  }, [active.id, open, searching, target]);
  const close = (next: boolean) => {
    if (!next && configBusy) return;
    if (!next && configDirty) setConfirmClose(true);
    else setOpen(next);
  };
  const navigate = (next: SettingsCategory) => { setSearch(""); setTarget(null); setCategory(next); };
  const jump = (next: SettingsCategory, anchor: string | null) => { navigate(next); setTarget(anchor ?? "settings-category-title"); };

  return <>
    <Dialog open={open} onOpenChange={close}>
      <DialogContent ref={contentRef} className="app-shell settings-dialog" showCloseButton={!configBusy}
        onKeyDown={(event) => {
          if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "f") { event.preventDefault(); event.stopPropagation(); searchRef.current?.focus(); }
        }}
        onOpenAutoFocus={(event) => {
          const origin = document.activeElement;
          returnFocusRef.current = origin instanceof HTMLElement && origin !== document.body && !contentRef.current?.contains(origin) ? origin : null;
          const activeButton = contentRef.current?.querySelector<HTMLButtonElement>('button[aria-current="page"]');
          if (activeButton) { event.preventDefault(); activeButton.focus(); }
        }}
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          const origin = returnFocusRef.current;
          if (origin?.isConnected) origin.focus();
          else document.querySelector<HTMLButtonElement>('button[aria-label="Settings"]')?.focus();
        }}>
        <header className="settings-window-header">
          <div><DialogTitle>Settings</DialogTitle><DialogDescription>{recordOverview ? "Records library" : "OpenSSH files"} · Preferences for this installation</DialogDescription></div>
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
              {(filesVisited || active.id === "files") && <div hidden={searching || active.id !== "files"} className="settings-pane"><SettingsCategoryPane category="files" recordOverview={recordOverview} onOpenImport={onOpenImport} onOpenSync={onOpenSync} onConfigDirtyChange={setConfigDirty} onConfigBusyChange={setConfigBusy} /></div>}
              {!recordOverview && (syncVisited || active.id === "sync") && <div hidden={searching || active.id !== "sync"} className="settings-pane"><SettingsCategoryPane category="sync" /></div>}
              {searching ? <div className="settings-results">
                {results.length ? results.map((result) => <button key={`${result.category}-${result.title}`} type="button" onClick={() => jump(result.category, result.target)}>
                  <span><small>{result.categoryLabel}</small><strong>{result.title}</strong><span>{result.detail}</span></span><ArrowRight className="size-4 shrink-0" aria-hidden="true" />
                </button>) : <div className="app-empty-state"><h2>No matching settings</h2><p>Try a preference name such as “theme”, “terminal” or “logs”.</p><Button variant="outline" size="sm" onClick={() => { setSearch(""); searchRef.current?.focus(); }}>Clear search</Button></div>}
              </div> : <>
                {active.id !== "files" && active.id !== "sync" && <div className="settings-pane" key={active.id}><SettingsCategoryPane category={active.id} recordOverview={recordOverview} onOpenImport={onOpenImport} onOpenSync={onOpenSync} /></div>}
              </>}
            </div>
          </div>
        </div>
        <footer className="settings-window-footer">{configBusy ? <span role="status">Loading SSH configuration… Keep this window open until loading finishes.</span> : "Switches and selections apply immediately. Use Apply or Save where shown; imports require confirmation."}</footer>
      </DialogContent>
    </Dialog>
    <AlertDialog open={confirmClose} onOpenChange={setConfirmClose}>
      <AlertDialogContent onCloseAutoFocus={(event) => { if (open && configDirty) { event.preventDefault(); setCategory("files"); requestAnimationFrame(() => contentRef.current?.querySelector<HTMLInputElement>('input[aria-label="Config file path"]')?.focus()); } }}><AlertDialogHeader><AlertDialogTitle>Discard the config path draft?</AlertDialogTitle><AlertDialogDescription>The new path has not been applied. Your current SSH configuration stays loaded.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Keep editing</AlertDialogCancel><AlertDialogAction onClick={() => { setConfirmClose(false); setOpen(false); }}>Discard draft</AlertDialogAction></AlertDialogFooter></AlertDialogContent>
    </AlertDialog>
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

function ConnectionPane({recordOverview}: {recordOverview?:RecordOverview}) {
  const terminalId = useSettingsStore((s) => s.terminalId);
  const setTerminalId = useSettingsStore((s) => s.setTerminalId);
  const newTabConnect = useSettingsStore((s) => s.newTabConnect);
  const setNewTabConnect = useSettingsStore((s) => s.setNewTabConnect);
  const terminals = useTerminals();
  const terminalFontSize = useSettingsStore((s) => clampTerminalFontSize(s.terminalFontSize));
  const setTerminalFontSize = useSettingsStore((s) => s.setTerminalFontSize);
  const cursorBlink = useSettingsStore((s) => s.terminalCursorBlink !== false);
  const setCursorBlink = useSettingsStore((s) => s.setTerminalCursorBlink);

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
    <Section title="In-app terminal" description="Colors follow Appearance. Search with ⌘F / Ctrl+F, switch sessions with Ctrl+Tab, and zoom with ⌘ / Ctrl + or −. Closing a running session asks for confirmation.">
      <SettingsGroup>
        <SettingsRow id="set-terminal-font" label="Terminal text size" description="Applies to all in-app terminal tabs without reconnecting.">
          <Select value={String(terminalFontSize)} onValueChange={(value) => setTerminalFontSize(Number(value))}>
            <SelectTrigger id="set-terminal-font" className="settings-select"><SelectValue /></SelectTrigger>
            <SelectContent>{Array.from({ length: 15 }, (_, i) => i + 10).map((size) => <SelectItem key={size} value={String(size)}>{size} px</SelectItem>)}</SelectContent>
          </Select>
        </SettingsRow>
        <SettingsRow id="set-terminal-cursor" label="Blink cursor" description="Reduced-motion preferences take priority."><Switch id="set-terminal-cursor" checked={cursorBlink} onCheckedChange={setCursorBlink} /></SettingsRow>
      </SettingsGroup>
      <p className="mt-3 text-xs leading-relaxed text-muted-foreground">Switching tabs keeps SSH connected. Closing a tab, reloading the workspace, quitting or installing an update ends its session. Reconnect starts a new shell.</p>
    </Section>
    {recordOverview && <Section title="Known hosts" description="Inspect trusted server fingerprints and manage local OpenSSH host keys.">
      <SettingsGroup><SettingsRow label="Saved server identities" description="Review fingerprints, verify a server again, or forget an old identity."><KnownHostsManager overview={recordOverview} /></SettingsRow></SettingsGroup>
    </Section>}</>
  );
}

function FilesPane({ onDirtyChange, onBusyChange }: { onDirtyChange?: (dirty: boolean) => void; onBusyChange?: (busy: boolean) => void }) {
  const configPath = useSettingsStore((s) => s.configPath);
  const setConfigPath = useSettingsStore((s) => s.setConfigPath);
  const backupRetention = useSettingsStore((s) => s.backupRetention);
  const setBackupRetention = useSettingsStore((s) => s.setBackupRetention);

  const loadConfig = useLoadConfig();
  const queryClient = useQueryClient();

  const [draft, setDraft] = useState(configPath ?? "");
  useEffect(() => setDraft(configPath ?? ""), [configPath]);
  const dirty = (draft.trim() || "") !== (configPath ?? "");
  useEffect(() => { onDirtyChange?.(dirty); }, [dirty, onDirtyChange]);
  useEffect(() => { onBusyChange?.(loadConfig.isPending); }, [loadConfig.isPending, onBusyChange]);

  // Persist only on a SUCCESSFUL load so a broken path never sticks: on error
  // the old working document (and persisted path) stay intact and the
  // existing "Failed to load config" toast fires from useLoadConfig.
  const applyPath = () => {
    if (loadConfig.isPending) return;
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
        description="The ssh_config file Lunport edits. Leave empty for ~/.ssh/config."
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
          <SettingsRow id="set-backup-retention" label="Backup retention">
            <Select
              value={backupRetention === null ? RETENTION_ALL : String(backupRetention)}
              onValueChange={onRetention}
            >
              <SelectTrigger id="set-backup-retention" className="settings-select">
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

function LegacyMcpPane() {
  const query = useHostsQuery();
  return <McpPane hosts={(query.data?.hosts ?? []).filter(host => !isWildcardOnly(host)).map(host => ({ id: host.alias, alias: host.alias, hostname: host.hostname, user: host.user }))} />;
}

export function McpPane({ hosts, records = false }: {
  hosts: Array<{id: string; alias: string; hostname: string | null; user: string | null; port?: number; groupPath?: string}>;
  records?: boolean;
}) {
  const status = useMcpStatus(2_000);
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
  const [hostSearch, setHostSearch] = useState("");
  const matchingHosts = hosts.filter((host) => `${host.alias} ${host.hostname ?? ""} ${host.user ?? ""} ${host.id} ${host.groupPath ?? ""}`.toLowerCase().includes(hostSearch.trim().toLowerCase()));

  return (
    <>
      <McpClientSetup fallbackExecutable={status.data?.executable} connectionNote={
        !status.data ? undefined : !status.data.enabled ? "AI access is off. Turn it on when you’re ready to use connected tools."
          : !status.data.bridge_active ? "The local AI service is unavailable. Restart Lunport and refresh the tool’s setup."
          : status.data.last_client_at_ms ? `Last AI tool activity ${new Date(status.data.last_client_at_ms).toLocaleString()}`
          : "Ready for a local AI tool to connect."
      } accessControl={
        <SettingsGroup>
          {status.isError && <div role="alert" className="space-y-2 p-3"><p className="text-sm text-destructive">AI access status is unavailable.</p><Button size="sm" variant="outline" onClick={() => void status.refetch()}>Retry</Button></div>}
          <SettingsRow
            id="set-mcp-enabled"
            label="Enable AI access"
            description="Only individually allowed hosts are available. Turning this off cancels pending requests."
          >
            <Switch
              id="set-mcp-enabled"
              checked={status.data?.enabled === true}
              disabled={!status.data || status.isError || setEnabled.isPending}
              onCheckedChange={(enabled) => setEnabled.mutate(enabled)}
            />
          </SettingsRow>
        </SettingsGroup>
      } />

      {records ? (
        <Section
          title="Command approval"
          description="Ask reviews each complete command before execution. Switching mode cancels active requests."
        >
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant={status.data?.approval_mode === "ask" ? "secondary" : "outline"}
              aria-pressed={status.data?.approval_mode === "ask"}
              disabled={!status.data || setMode.isPending}
              onClick={() => {
                setRiskOpen(false);
                setRiskAcknowledged(false);
                chooseMcpMode("ask", false, applyMode);
              }}
            >Ask</Button>
            <Button
              variant={status.data?.approval_mode === "auto_log" ? "secondary" : "outline"}
              aria-pressed={status.data?.approval_mode === "auto_log"}
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
            If background sync remains unavailable after a hidden launch, open Lunport from the tray or launch the app normally, then retry. MCP approval does not activate background sync.
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
        title="Allowed hosts"
        description={records ? "Select individual host IDs. Groups and inherited settings never grant access; Legacy alias permissions do not apply." : "Only explicitly selected aliases are visible to MCP clients. SSH config tags do not grant access."}
      >
        <div className="mb-3 space-y-2"><Input type="search" value={hostSearch} onChange={(event) => setHostSearch(event.target.value)} placeholder="Search hosts, destinations or IDs…" aria-label="Search AI host permissions" /><p className="text-xs text-muted-foreground" role="status">{matchingHosts.length} of {hosts.length} hosts · {hosts.filter((host) => allowed.has(host.id)).length} allowed</p></div>
        <div className="[&_label]:break-all [&_p]:break-all"><SettingsGroup>
          {hosts.length === 0 ? (
            <p className="px-3 py-3 text-sm text-muted-foreground">No SSH hosts loaded.</p>
          ) : matchingHosts.length === 0 ? <p className="p-3 text-sm text-muted-foreground">No hosts match this search.</p> : (
            matchingHosts.map((host) => (
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
        This controls requests made through Lunport MCP. It cannot prevent software running as
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
        description="Lunport always re-checks when the window regains focus."
      >
        <SettingsGroup>
          <SettingsRow id="set-drift-auto" label="Check for external changes automatically">
            <Switch
              id="set-drift-auto"
              checked={driftAutoCheck}
              onCheckedChange={setDriftAutoCheck}
            />
          </SettingsRow>
          <SettingsRow id="set-drift-interval" label="Check every">
            <Select
              value={String(driftIntervalSec)}
              onValueChange={(v) => setDriftIntervalSec(Number(v))}
              disabled={!driftAutoCheck}
            >
              <SelectTrigger id="set-drift-interval" className="settings-select">
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

export default SettingsDialog;
