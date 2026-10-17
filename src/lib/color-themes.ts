import type { ResolvedTheme } from "./settings-logic";

/** App surfaces adapted from the credited palettes; see theme-notices.txt. */
export type ColorPalette = Record<
  | "--background" | "--foreground" | "--card" | "--popover"
  | "--muted" | "--muted-foreground" | "--accent"
  | "--primary" | "--primary-foreground" | "--border" | "--input"
  | "--success" | "--destructive" | "--warning" | "--warning-foreground"
  | "--sidebar" | "--sidebar-accent",
  string
>;

export const COLOR_THEMES = [
  {
    id: "lunport", name: "Lunport", description: "Original",
    light: {
      "--background": "#f6f7f9", "--foreground": "#20242b",
      "--card": "#ffffff", "--popover": "#ffffff",
      "--muted": "#eceef2", "--muted-foreground": "#626a76", "--accent": "#e8ebf0",
      "--primary": "#1d4ed8", "--primary-foreground": "#ffffff",
      "--border": "#d9dde4", "--input": "#c7cdd7",
      "--success": "#18794e", "--destructive": "#bf303b", "--warning": "#936100", "--warning-foreground": "#ffffff",
      "--sidebar": "#edeff3", "--sidebar-accent": "#e1e5ec",
    },
    dark: {
      "--background": "#111214", "--foreground": "#eef0f4",
      "--card": "#1b1d21", "--popover": "#23252a",
      "--muted": "#22252b", "--muted-foreground": "#a8aeb8", "--accent": "#2b2e35",
      "--primary": "#82b1ff", "--primary-foreground": "#10213d",
      "--border": "#34373f", "--input": "#41454f",
      "--success": "#78d6a0", "--destructive": "#ff8087", "--warning": "#ffc533", "--warning-foreground": "#2a2000",
      "--sidebar": "#17191d", "--sidebar-accent": "#2b2e35",
    },
  },
  {
    id: "nord", name: "Nord", description: "Arctic blue",
    light: {
      "--background": "#eceff4", "--foreground": "#2e3440",
      "--card": "#e5e9f0", "--popover": "#eceff4",
      "--muted": "#d8dee9", "--muted-foreground": "#4c566a", "--accent": "#d8dee9",
      "--primary": "#45688f", "--primary-foreground": "#ffffff",
      "--border": "#c0c8d6", "--input": "#a5b0c2",
      "--success": "#41652c", "--destructive": "#a3414b", "--warning": "#836118", "--warning-foreground": "#ffffff",
      "--sidebar": "#e5e9f0", "--sidebar-accent": "#d8dee9",
    },
    dark: {
      "--background": "#2e3440", "--foreground": "#eceff4",
      "--card": "#3b4252", "--popover": "#3b4252",
      "--muted": "#3b4252", "--muted-foreground": "#d8dee9", "--accent": "#434c5e",
      "--primary": "#88c0d0", "--primary-foreground": "#2e3440",
      "--border": "#4c566a", "--input": "#66738a",
      "--success": "#a3be8c", "--destructive": "#ed9ca5", "--warning": "#ebcb8b", "--warning-foreground": "#2e3440",
      "--sidebar": "#2e3440", "--sidebar-accent": "#434c5e",
    },
  },
  {
    id: "dracula", name: "Dracula", description: "Purple accent",
    light: {
      "--background": "#fffbeb", "--foreground": "#1f1f1f",
      "--card": "#efeddc", "--popover": "#fffbeb",
      "--muted": "#ece9df", "--muted-foreground": "#6c664b", "--accent": "#dedccf",
      "--primary": "#644ac9", "--primary-foreground": "#fffbeb",
      "--border": "#ceccc0", "--input": "#bcbab3",
      "--success": "#14710a", "--destructive": "#b83224", "--warning": "#79630e", "--warning-foreground": "#fffbeb",
      "--sidebar": "#efeddc", "--sidebar-accent": "#dedccf",
    },
    dark: {
      "--background": "#282a36", "--foreground": "#f8f8f2",
      "--card": "#343746", "--popover": "#343746",
      "--muted": "#343746", "--muted-foreground": "#b4b9d6", "--accent": "#44475a",
      "--primary": "#bd93f9", "--primary-foreground": "#282a36",
      "--border": "#44475a", "--input": "#6272a4",
      "--success": "#50fa7b", "--destructive": "#ff8585", "--warning": "#f1fa8c", "--warning-foreground": "#282a36",
      "--sidebar": "#21222c", "--sidebar-accent": "#44475a",
    },
  },
  {
    id: "catppuccin", name: "Catppuccin", description: "Soft pastels",
    light: {
      "--background": "#eff1f5", "--foreground": "#4c4f69",
      "--card": "#e6e9ef", "--popover": "#eff1f5",
      "--muted": "#dce0e8", "--muted-foreground": "#5c5f77", "--accent": "#ccd0da",
      "--primary": "#822edf", "--primary-foreground": "#ffffff",
      "--border": "#bcc0cc", "--input": "#9ca0b0",
      "--success": "#3d6823", "--destructive": "#bd0b33", "--warning": "#8c5800", "--warning-foreground": "#ffffff",
      "--sidebar": "#e6e9ef", "--sidebar-accent": "#ccd0da",
    },
    dark: {
      "--background": "#1e1e2e", "--foreground": "#cdd6f4",
      "--card": "#313244", "--popover": "#313244",
      "--muted": "#313244", "--muted-foreground": "#bac2de", "--accent": "#45475a",
      "--primary": "#cba6f7", "--primary-foreground": "#1e1e2e",
      "--border": "#45475a", "--input": "#585b70",
      "--success": "#a6e3a1", "--destructive": "#f38ba8", "--warning": "#f9e2af", "--warning-foreground": "#1e1e2e",
      "--sidebar": "#181825", "--sidebar-accent": "#45475a",
    },
  },
  {
    id: "tokyo-night", name: "Tokyo Night", description: "Midnight blue",
    light: {
      "--background": "#e1e2e7", "--foreground": "#343b59",
      "--card": "#d5d8e2", "--popover": "#e1e2e7",
      "--muted": "#d0d5e3", "--muted-foreground": "#4c5679", "--accent": "#c4c8da",
      "--primary": "#3255a8", "--primary-foreground": "#ffffff",
      "--border": "#b4b5c4", "--input": "#8990b3",
      "--success": "#32623b", "--destructive": "#a8243b", "--warning": "#805321", "--warning-foreground": "#ffffff",
      "--sidebar": "#d0d5e3", "--sidebar-accent": "#c4c8da",
    },
    dark: {
      "--background": "#1a1b26", "--foreground": "#c0caf5",
      "--card": "#24283b", "--popover": "#24283b",
      "--muted": "#24283b", "--muted-foreground": "#a9b1d6", "--accent": "#292e42",
      "--primary": "#7aa2f7", "--primary-foreground": "#1a1b26",
      "--border": "#3b4261", "--input": "#565f89",
      "--success": "#9ece6a", "--destructive": "#f7768e", "--warning": "#e0af68", "--warning-foreground": "#1a1b26",
      "--sidebar": "#16161e", "--sidebar-accent": "#292e42",
    },
  },
  {
    id: "solarized", name: "Solarized", description: "Warm & muted",
    light: {
      "--background": "#fdf6e3", "--foreground": "#073642",
      "--card": "#eee8d5", "--popover": "#fdf6e3",
      "--muted": "#eee8d5", "--muted-foreground": "#536970", "--accent": "#e3ddca",
      "--primary": "#006f68", "--primary-foreground": "#fdf6e3",
      "--border": "#c8c3b2", "--input": "#93a1a1",
      "--success": "#526b00", "--destructive": "#b52d2b", "--warning": "#826200", "--warning-foreground": "#fdf6e3",
      "--sidebar": "#eee8d5", "--sidebar-accent": "#e3ddca",
    },
    dark: {
      "--background": "#002b36", "--foreground": "#eee8d5",
      "--card": "#073642", "--popover": "#073642",
      "--muted": "#073642", "--muted-foreground": "#93a1a1", "--accent": "#104450",
      "--primary": "#70c7bf", "--primary-foreground": "#002b36",
      "--border": "#31545e", "--input": "#536970",
      "--success": "#bbc85b", "--destructive": "#f28d88", "--warning": "#d9b650", "--warning-foreground": "#002b36",
      "--sidebar": "#002630", "--sidebar-accent": "#104450",
    },
  },
] as const satisfies readonly {
  id: string; name: string; description: string; light: ColorPalette; dark: ColorPalette;
}[];

export type ColorThemeId = (typeof COLOR_THEMES)[number]["id"];

/** Older settings have no palette; unknown imported IDs use the original theme. */
export function getColorTheme(value: unknown) {
  return COLOR_THEMES.find((theme) => theme.id === value) ?? COLOR_THEMES[0];
}

export function applyColorTheme(root: HTMLElement, value: unknown, mode: ResolvedTheme): void {
  const theme = getColorTheme(value);
  root.dataset.colorTheme = theme.id;
  const palette = theme[mode];
  const colors = { ...palette, "--chart-3": palette["--input"], "--chart-4": palette["--border"], "--chart-5": palette["--muted"] };
  for (const [property, color] of Object.entries(colors)) {
    // Let the original CSS remain the fallback, including when returning from a preset.
    if (theme.id === "lunport") root.style.removeProperty(property);
    else root.style.setProperty(property, color);
  }
}
