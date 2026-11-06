# Embedded terminal screen regression

Lunport pins `@wterm/dom` and `@wterm/ghostty` to 0.5.4. The pnpm patch for
`@wterm/dom` addresses [upstream issue #245](https://github.com/vercel-labs/wterm/issues/245):
a focused terminal's hidden textarea retains a scrollback-relative position
when history is cleared or Vim/vi enters the alternate screen. That textarea
keeps the scroll container tall, so the viewport follows it into empty space.
The terminal grid still contains the output. This reproduces with English
output as well as `zh_TW.UTF-8`.

The same conditional `syncInputPosition` implementation is present in
[upstream 0.5.9](https://github.com/vercel-labs/wterm/blob/v0.5.9/packages/@wterm/dom/src/input.ts).
The patch keeps the hidden input aligned with the live cursor after rendering,
including outside IME composition. Remove it only after an upstream release
passes the regression tests.

`tests/browser/terminal-qa.mjs` starts Vite and tests Chromium and WebKit with
the real WTerm renderer and Ghostty WASM. It covers focused scrollback followed
by alternate-screen entry, history clearing, and captured Ubuntu Vim/vi output.
Assertions check viewport position, visible rows, Chinese text, keyboard input,
and restoration of shell history on exit. The unpatched package fails the
alternate-screen viewport assertion; the patched package passes all eight cases.
CI runs this script after the regular frontend tests and build.

Run locally with Playwright and its Chromium/WebKit browsers available:

```sh
node tests/browser/terminal-qa.mjs
```

As with `central-keys-qa.mjs`, `PLAYWRIGHT_MODULE` can point at an external
Playwright module and `QA_CHROMIUM_PATH` at an installed Chrome executable.
`TERMINAL_QA_BROWSERS` selects engines (default `chromium,webkit`), and
`TERMINAL_QA_URL` reuses a running Vite server. No browser tooling is added to
application dependencies.

The fixture contains output from a temporary Ubuntu 24.04 container running
`vim` and `vi` with `TERM=xterm-256color`, `LANG=zh_TW.UTF-8`, and a 102 × 31 PTY.
Each opened a synthetic UTF-8 file containing English and Traditional Chinese.
The capture uses `-i NONE -n -R` to avoid viminfo, swap files, and writes;
system Vim configuration remains enabled. No user files or SSH data are included.
