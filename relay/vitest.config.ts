import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" } })],
  test: {
    // .github/scripts 的測試由 node --test 執行(CI 的 update-script job),不屬於 workerd 測試。
    exclude: [...configDefaults.exclude, ".github/**"],
    // 多個測試檔平行執行時,長的請求迴圈(上千次請求)偶爾會慢上好幾秒,預設 5 秒逾時會隨機失敗。
    testTimeout: 30_000,
  },
});
