import type { SettingsCategory } from "@/stores/ui";

export type SettingsDestination = {
  id: SettingsCategory;
  label: string;
  description: string;
  group: "Application" | "Workspace" | "Maintenance";
};

/** The Settings destinations, shared by navigation and search. IDs retain existing deep links. */
export function settingsDestinations(): SettingsDestination[] {
  return [
    { id: "general", label: "General", description: "Startup, window behavior and shortcuts.", group: "Application" },
    { id: "appearance", label: "Appearance", description: "Color themes, light and dark mode, text size and motion.", group: "Application" },
    { id: "connection", label: "Connections", description: "Terminal preferences and trusted server identities.", group: "Application" },
    { id: "files", label: "Local data", description: "Your local library, workspace tools and preferences.", group: "Workspace" },
    { id: "ai", label: "AI access", description: "Connect clients, allow hosts or Groups and review activity.", group: "Workspace" },
    { id: "updates", label: "Updates", description: "Installed version, release channel and update status.", group: "Maintenance" },
    { id: "advanced", label: "Diagnostics", description: "Local diagnostic logs and workspace capabilities.", group: "Maintenance" },
    { id: "about", label: "About", description: "Lunport, project links and license.", group: "Maintenance" },
  ];
}

export function settingsSectionId(title: string) {
  return `settings-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/-$/, "")}`;
}

type SearchEntry = { category: SettingsCategory; title: string; detail: string; section: string };
const SEARCH_ENTRIES: SearchEntry[] = [
  { category: "general", title: "Startup & window", detail: "Menu bar, tray icon, close behavior and launch at login", section: "Startup & window" },
  { category: "general", title: "Quick connect", detail: "Global keyboard hotkey shortcut", section: "Quick connect" },
  { category: "general", title: "Language", detail: "Interface language: English", section: "Language" },
  { category: "appearance", title: "Color theme", detail: "Lunport, Nord, Dracula, Catppuccin, Tokyo Night, Solarized; palette colors; system, light or dark mode", section: "Color theme" },
  { category: "appearance", title: "Display", detail: "Text and font size; reduced motion; host tags", section: "Display" },
  { category: "connection", title: "Terminal", detail: "Default terminal and new tab connections", section: "Terminal" },
  { category: "connection", title: "In-app terminal", detail: "SSH sessions, terminal font text size, blink cursor, search, keyboard shortcuts and colors", section: "In-app terminal" },
  { category: "connection", title: "Known hosts", detail: "Server identities, trusted host fingerprints and OpenSSH known_hosts", section: "Known hosts" },
  { category: "files", title: "Library & workspace tools", detail: "Local hosts, Groups and keys, import or export settings, saved workspaces and automatic Sync", section: "Library & workspace tools" },
  { category: "files", title: "Preferences transfer", detail: "Export settings to JSON or import and replace preferences", section: "Preferences transfer" },
  { category: "ai", title: "MCP access", detail: "Enable AI access and local approval broker status", section: "MCP access" },
  { category: "ai", title: "AI operation approval", detail: "Ask and Auto-log command and file transfer review", section: "AI operation approval" },
  { category: "ai", title: "File transfers", detail: "Adjust the single-file SCP transfer limit", section: "File transfers" },
  { category: "ai", title: "Connect Codex", detail: "Copy MCP client setup command", section: "Connect Codex" },
  { category: "ai", title: "Allowed hosts", detail: "Allow individual hosts or Groups and subgroups; grant or revoke AI permissions", section: "Allowed hosts" },
  { category: "ai", title: "Activity", detail: "Latest AI activity and the AI activity page with every result", section: "Activity" },
  { category: "updates", title: "Software update", detail: "Installed version, check, download, install and restart", section: "" },
  { category: "updates", title: "Update preferences", detail: "Stable or Beta release channel and automatic checks", section: "Update preferences" },
  { category: "about", title: "About Lunport", detail: "Your SSH workspace, version, GitHub, release notes, support, license and Frank Sung", section: "" },
  { category: "advanced", title: "Diagnostic logs", detail: "Open local startup and error logs", section: "Diagnostic logs" },
  { category: "advanced", title: "Workspace capabilities", detail: "Built-in SSH engine, local data and AI access boundaries", section: "Workspace capabilities" },
];

export function searchSettings(query: string) {
  const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!tokens.length) return [];
  const destinations = settingsDestinations();
  return SEARCH_ENTRIES.filter((entry) => {
    const destination = destinations.find((item) => item.id === entry.category);
    const text = `${destination?.label} ${entry.title} ${entry.detail}`.toLowerCase();
    return tokens.every((token) => text.includes(token));
  }).map((entry) => ({ ...entry, categoryLabel: destinations.find((item) => item.id === entry.category)!.label, target: entry.section ? settingsSectionId(entry.section) : null }));
}
