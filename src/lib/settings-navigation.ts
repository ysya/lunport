import type { SettingsCategory } from "@/stores/ui";

export type SettingsMode = "records" | "legacy";
export type SettingsDestination = {
  id: SettingsCategory;
  label: string;
  description: string;
  group: "Application" | "Workspace" | "Maintenance";
};

/** Mode-specific destinations, shared by navigation and search. IDs retain existing deep links. */
export function settingsDestinations(mode: SettingsMode): SettingsDestination[] {
  return [
    { id: "general", label: "General", description: "Startup, window behavior and shortcuts.", group: "Application" },
    { id: "appearance", label: "Appearance", description: "Theme, text size and motion.", group: "Application" },
    { id: "connection", label: "Connections", description: "Choose where terminal connections open.", group: "Application" },
    { id: "files", label: mode === "records" ? "Local data" : "Files & backups", description: mode === "records" ? "Your local library, workspace tools and preferences." : "SSH configuration, backups and preferences.", group: "Workspace" },
    { id: "ai", label: "AI access", description: "Connect clients, allow individual hosts and review activity.", group: "Workspace" },
    ...(mode === "legacy" ? [{ id: "sync" as const, label: "Sync", description: "Manage encrypted spaces and devices.", group: "Workspace" as const }] : []),
    { id: "updates", label: "Updates", description: "Installed version, release channel and update status.", group: "Maintenance" },
    { id: "advanced", label: mode === "records" ? "Diagnostics" : "Discovery & checks", description: mode === "records" ? "Local diagnostic logs and workspace capabilities." : "Discovery sources, external changes and config checks.", group: "Maintenance" },
    { id: "about", label: "About", description: "Lunport, project links and license.", group: "Maintenance" },
  ];
}

export function settingsSectionId(title: string) {
  return `settings-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/-$/, "")}`;
}

type SearchEntry = { category: SettingsCategory; title: string; detail: string; section: string; modes?: SettingsMode[] };
const SEARCH_ENTRIES: SearchEntry[] = [
  { category: "general", title: "Startup & window", detail: "Menu bar, tray icon, close behavior and launch at login", section: "Startup & window" },
  { category: "general", title: "Quick connect", detail: "Global keyboard hotkey shortcut", section: "Quick connect" },
  { category: "general", title: "Language", detail: "Interface language: English", section: "Language" },
  { category: "appearance", title: "Display", detail: "System, light or dark theme; text and font size; reduced motion; host tags", section: "Display" },
  { category: "connection", title: "Terminal", detail: "Default terminal and new tab connections", section: "Terminal" },
  { category: "files", title: "Library & workspace tools", detail: "Local hosts and keys, import SSH configuration and open Sync", section: "Library & workspace tools", modes: ["records"] },
  { category: "files", title: "Config file", detail: "OpenSSH ssh_config path and apply", section: "Config file", modes: ["legacy"] },
  { category: "files", title: "Backups", detail: "Backup retention and keep all snapshots", section: "Backups", modes: ["legacy"] },
  { category: "files", title: "Preferences transfer", detail: "Export settings to JSON or import and replace preferences", section: "Preferences transfer" },
  { category: "ai", title: "MCP access", detail: "Enable AI access and local approval broker status", section: "MCP access" },
  { category: "ai", title: "Command approval", detail: "Ask and Auto-log risk acknowledgement", section: "Command approval", modes: ["records"] },
  { category: "ai", title: "Connect Codex", detail: "Copy MCP client setup command", section: "Connect Codex" },
  { category: "ai", title: "Allowed hosts", detail: "Search individual hosts and grant or revoke AI permissions", section: "Allowed hosts" },
  { category: "ai", title: "Recent activity", detail: "Public audit log and command results", section: "Recent activity" },
  { category: "sync", title: "Sync", detail: "Relay, device, encrypted spaces, key sharing and recovery", section: "", modes: ["legacy"] },
  { category: "updates", title: "Software update", detail: "Installed version, check, download, install and restart", section: "" },
  { category: "updates", title: "Update preferences", detail: "Stable or Beta release channel and automatic checks", section: "Update preferences" },
  { category: "about", title: "About Lunport", detail: "Your SSH workspace, version, GitHub, release notes, support, license and Frank Sung", section: "" },
  { category: "advanced", title: "Diagnostic logs", detail: "Open local startup and error logs", section: "Diagnostic logs" },
  { category: "advanced", title: "Workspace capabilities", detail: "Built-in SSH engine, local data and AI access boundaries", section: "Workspace capabilities", modes: ["records"] },
  { category: "advanced", title: "Discovery sources", detail: "Discover known_hosts and Tailscale candidates", section: "Discovery sources", modes: ["legacy"] },
  { category: "advanced", title: "External changes", detail: "Automatic SSH config drift checks and interval", section: "External changes", modes: ["legacy"] },
  { category: "advanced", title: "Lint rules", detail: "Config errors, warnings and enabled checks", section: "Lint rules", modes: ["legacy"] },
];

export function searchSettings(query: string, mode: SettingsMode) {
  const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!tokens.length) return [];
  const destinations = settingsDestinations(mode);
  return SEARCH_ENTRIES.filter((entry) => {
    if (entry.modes && !entry.modes.includes(mode)) return false;
    const destination = destinations.find((item) => item.id === entry.category);
    const text = `${destination?.label} ${entry.title} ${entry.detail}`.toLowerCase();
    return tokens.every((token) => text.includes(token));
  }).map((entry) => ({ ...entry, categoryLabel: destinations.find((item) => item.id === entry.category)!.label, target: entry.section ? settingsSectionId(entry.section) : null }));
}
