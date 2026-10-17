import { useId, type CSSProperties } from "react";
import { Check } from "lucide-react";
import { COLOR_THEMES, getColorTheme } from "@/lib/color-themes";
import { useSettingsStore } from "@/stores/settings";
import themeNotices from "@/lib/theme-notices.txt?raw";

export function ColorThemePicker() {
  const name = useId();
  const selected = getColorTheme(useSettingsStore((state) => state.colorTheme)).id;
  const setColorTheme = useSettingsStore((state) => state.setColorTheme);
  return <>
    <fieldset className="color-theme-picker">
      <legend className="sr-only">Color theme</legend>
      {COLOR_THEMES.map((theme) => <label className="color-theme-option" key={theme.id}>
        <input type="radio" name={name} value={theme.id} aria-label={theme.name}
          checked={selected === theme.id} onChange={() => setColorTheme(theme.id)} />
        <span className="color-theme-choice">
          {(["light", "dark"] as const).map((mode) => <span key={mode} aria-hidden="true"
            className="color-theme-preview" data-mode={mode} style={theme[mode] as CSSProperties}>
            <span className="color-theme-mini-nav"><i /><i /><i /></span>
            <span className="color-theme-mini-content"><i /><span><b /><b /></span></span>
          </span>)}
          <span className="color-theme-caption"><span><strong>{theme.name}</strong><small>{theme.description}</small></span>
            {selected === theme.id && <Check className="size-4 shrink-0 text-primary" aria-hidden="true" />}
          </span>
        </span>
      </label>)}
    </fieldset>
    <details className="color-theme-credits"><summary>Theme credits</summary><pre>{themeNotices}</pre></details>
  </>;
}
