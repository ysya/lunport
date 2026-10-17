# Built-in app color themes — preview

The Appearance settings now separate color palette from System / Light / Dark mode. Six presets are available: Lunport (the existing default), Nord, Dracula (Alucard in light mode), Catppuccin (Latte/Mocha), Tokyo Night (Day/Night) and Solarized. Changes apply immediately and persist in the existing local settings envelope. Older settings retain their mode and original palette; an unknown imported palette falls back to Lunport. No dependency, native credential, record or sync format changes are required.

The same semantic colors cover the workspace, sidebar, compact host cards, settings, portaled menus and standalone SSH prompts. Remaining fixed warning/success classes in Legacy, sync, key and update screens now use semantic theme tokens. The default light warning color is slightly darker for readable small text. External terminals retain their own themes.

## Sources and adaptation

- [Nord](https://www.nordtheme.com/docs/colors-and-palettes/)
- [Dracula and Alucard](https://draculatheme.com/spec)
- [Catppuccin](https://catppuccin.com/palette/)
- [Tokyo Night](https://github.com/folke/tokyonight.nvim)
- [Solarized](https://ethanschoonover.com/solarized/)

Surface roles, secondary text and semantic accents are adapted for the app rather than copied from syntax highlighting. Attribution and full license texts ship in `src/lib/theme-notices.txt` and are readable under Appearance → Theme credits.

## Validation

- TypeScript, 88 frontend test files / 1,093 tests and the production Vite build pass. The existing bundle-size advisory remains.
- All twelve palette/mode combinations were exercised through the actual Settings dialog. Checked state and computed body colors match; no horizontal settings overflow occurred.
- Native radio keyboard navigation (Nord → ArrowRight → Dracula), selection persistence after reload, and a Solarized Light portaled font-size menu were verified.
- At the native minimum 800×560 window and largest 17px text, the dialog remains inside the viewport; all theme choices and the content pane have no horizontal overflow. Content scrolls inside the dialog.
- Palette tests require at least 4.5:1 for main/secondary/accent/success/error/warning text on canvas, card, popover and sidebar surfaces, plus primary and warning button text pairs.
- Browser checks are recorded in [browser-checks.json](browser-checks.json).

## Actual component captures

The local development harness mounts the repository's RecordHostList, LibraryNavigation, HostPreview, SettingsDialog and useApplyTheme with twenty synthetic hosts. No production data, native authentication or live SSH connections were used. The small Funlingo overlay at the right edge belongs to the browser extension.

- [Nord Dark settings](settings-nord-dark.jpg)
- [Nord Dark host cards](hosts-nord-dark.jpg)
- [Catppuccin Dark host cards](hosts-catppuccin-dark.jpg)
- [Solarized Light settings](settings-solarized-light.jpg)
- [Minimum window / largest text](settings-minimum-800x560.jpg)

Draft visual preview only; no merge or release.
