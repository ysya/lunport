// `defineConfig`/`configDefaults` from "vitest/config" (not "vite"): same
// identity-function `defineConfig` at runtime, but its .d.ts augments Vite's
// `UserConfig` with the `test` field so the block below type-checks.
import { configDefaults, defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [react(), tailwindcss()],

  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },

  test: {
    // relay/ is a separate Cloudflare Workers sub-project: its own
    // vitest.config.ts (the @cloudflare/vitest-plugin pool), its own `npm
    // test`, and its own CI job (.github/workflows/relay.yml). Without this,
    // the root `vitest run` also picks up relay/test/*.test.ts and fails them
    // (they need that pool to resolve the `cloudflare:workers` module).
    exclude: [...configDefaults.exclude, "relay/**"],
  },
}));
