import { useEffect } from "react";
import type { ReactNode } from "react";
import { Moon, Sun } from "lucide-react";

import { useUiStore, type Theme } from "@/stores/ui";
import { useTerminals } from "@/lib/queries";
import { cn } from "@/lib/utils";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Section, SettingsGroup } from "@/components/settings-primitives";

/** Radix Select values must be non-empty; this sentinel round-trips to `null`. */
const TERMINAL_DEFAULT = "__default__";

/**
 * The Settings sheet (⌘,). Holds persistent *preferences* — appearance and the
 * default terminal — so the toolbar can stay focused on *actions*. Open state
 * lives in the UI store so the toolbar gear, the ⌘K palette, and the ⌘,
 * shortcut can all drive it.
 */
export function SettingsDialog() {
  const open = useUiStore((s) => s.settingsOpen);
  const setOpen = useUiStore((s) => s.setSettingsOpen);

  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);
  const terminalId = useUiStore((s) => s.terminalId);
  const setTerminalId = useUiStore((s) => s.setTerminalId);
  const terminals = useTerminals();

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

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Settings</DialogTitle>
          <DialogDescription>Preferences are saved on this machine.</DialogDescription>
        </DialogHeader>

        <div className="space-y-5">
          {/* Appearance — theme as a small segmented control. */}
          <Section title="Appearance">
            <SettingsGroup>
              <SettingsRow label="Theme">
                <ThemeSegmented value={theme} onChange={setTheme} />
              </SettingsRow>
            </SettingsGroup>
          </Section>

          {/* Connection — which terminal new connections launch into. */}
          <Section
            title="Connection"
            description="Where SSHelter opens a connection. “System default” uses your OS default terminal (or the first detected)."
          >
            <SettingsGroup>
              <SettingsRow label="Default terminal">
                <Select
                  value={terminalId ?? TERMINAL_DEFAULT}
                  onValueChange={(v) =>
                    setTerminalId(v === TERMINAL_DEFAULT ? null : v)
                  }
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
            </SettingsGroup>
          </Section>

          {/* Language — reserved for future i18n; English-only for now. */}
          <Section
            title="Language"
            description="More languages are planned. SSH keywords always stay in English."
          >
            <SettingsGroup>
              <SettingsRow label="Language">
                <Select value="en" disabled>
                  <SelectTrigger className="h-7 w-[11rem] text-sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="en">English</SelectItem>
                  </SelectContent>
                </Select>
              </SettingsRow>
            </SettingsGroup>
          </Section>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/** A single settings row: label on the left, control on the right. */
function SettingsRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 px-3 py-2">
      <span className="shrink-0 text-sm text-muted-foreground">{label}</span>
      {children}
    </div>
  );
}

const THEME_OPTIONS: { value: Theme; label: string; icon: typeof Sun }[] = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
];

/** A compact two-option segmented control for the theme preference. */
function ThemeSegmented({
  value,
  onChange,
}: {
  value: Theme;
  onChange: (theme: Theme) => void;
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
