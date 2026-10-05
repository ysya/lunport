import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// An Enter that commits an IME composition (Chinese, Japanese, Korean input) must not also submit or
// apply: every key handler that acts on Enter checks `isImeKey` first (see ./ime.ts). This scans the
// components so a new Enter handler cannot forget it.
function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : [];
  });
}

describe("Enter handlers", () => {
  it("check isImeKey before acting on Enter", () => {
    const unguarded: string[] = [];
    let handlers = 0;
    for (const file of sourceFiles("src")) {
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, i) => {
        if (!/key === "Enter"/.test(line)) return;
        handlers += 1;
        if (!lines.slice(Math.max(0, i - 3), i + 1).some((l) => l.includes("isImeKey("))) {
          unguarded.push(`${file}:${i + 1}`);
        }
      });
    }
    expect(handlers).toBeGreaterThan(0);
    expect(unguarded).toEqual([]);
  });
});
