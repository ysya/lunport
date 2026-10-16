// One vector geometry supplies the interface, favicon, native app and macOS tray icons.
// Run with `node scripts/generate-brand-icons.mjs` after installing the pinned Tauri CLI.
import { readFile, writeFile, mkdir, mkdtemp, copyFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const root = fileURLToPath(new URL("../", import.meta.url));
const mark = JSON.parse(await readFile(path.join(root, "src/brand/lunport-mark.json"), "utf8"));
const symbol = (colors) => mark.paths.map((d, index) => `<path d="${d}" fill="${colors[index % colors.length]}"/>`).join("");
const svg = (viewBox, body) => `<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="${viewBox}">${body}</svg>\n`;
const app = svg("0 0 100 100", `<defs><linearGradient id="surface" gradientUnits="userSpaceOnUse" x1="15" y1="5" x2="85" y2="100"><stop stop-color="#253658"/><stop offset="1" stop-color="#121D33"/></linearGradient></defs><rect x="3" y="3" width="94" height="94" rx="21" fill="url(#surface)"/><rect x="3.5" y="3.5" width="93" height="93" rx="20.5" fill="none" stroke="#B5CAFF" stroke-opacity=".12"/>${symbol(["#C4D7FF", "#86ADFF"])}`);
const monochrome = svg("16 16 68 68", symbol(["#000"]));
const iconDir = path.join(root, "src-tauri/icons");
const cli = path.join(root, "node_modules/@tauri-apps/cli/tauri.js");
const scratch = await mkdtemp(path.join(tmpdir(), "lunport-icons-"));
try {
  await mkdir(iconDir, { recursive: true });
  await writeFile(path.join(root, "public/lunport-icon.svg"), app);
  await writeFile(path.join(iconDir, "tray.svg"), monochrome);
  execFileSync(process.execPath, [cli, "icon", path.join(root, "public/lunport-icon.svg"), "--output", path.join(scratch, "app")], { cwd: root, stdio: "inherit" });
  const nativeFiles = ["32x32.png", "128x128.png", "128x128@2x.png", "icon.png", "icon.icns", "icon.ico", "StoreLogo.png", ...[30, 44, 71, 89, 107, 142, 150, 284, 310].map((size) => `Square${size}x${size}Logo.png`)];
  for (const file of nativeFiles) await copyFile(path.join(scratch, "app", file), path.join(iconDir, file));
  // tray-icon displays at 18 points on macOS: use 2× artwork and no app background.
  execFileSync(process.execPath, [cli, "icon", path.join(iconDir, "tray.svg"), "--output", path.join(scratch, "tray"), "--png", "36"], { cwd: root, stdio: "inherit" });
  await copyFile(path.join(scratch, "tray/36x36.png"), path.join(iconDir, "tray.png"));
} finally {
  await rm(scratch, { recursive: true, force: true });
}
