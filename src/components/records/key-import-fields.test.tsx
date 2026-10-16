import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
import { KeyImportFields } from "./KeyImportFields";
import { clearKeyDraft, type KeyDraft } from "./panel-actions";

const render = (patch: Partial<KeyDraft> = {}) => renderToStaticMarkup(
  <KeyImportFields draft={{ ...clearKeyDraft(), ...patch }} update={vi.fn()} choose={vi.fn()} />,
);
describe("private key import sources", () => {
  it("starts with file selection and does not render inactive pasted private material", () => {
    const html = render({ privateText: "INACTIVE_PRIVATE_SENTINEL" });
    expect(text(html)).toContain("Choose a file…");
    expect(text(html)).toContain("No file selected.");
    expect(html).toContain('role="tablist"');
    expect(html).not.toContain("INACTIVE_PRIVATE_SENTINEL");
    expect(html).not.toContain("<textarea");
  });
  it("shows the chosen path with hidden characters revealed and permits changing the file", () => {
    const html = render({ path: "/fixture/id_\u202Ework" });
    expect(text(html)).toContain("/fixture/id_⟨U+202E⟩work");
    expect(text(html)).toContain("Choose another file…");
  });
  it("keeps Paste available with a named input and disables selection while busy", () => {
    const html = render({ source: "paste", busy: true });
    expect(html).toContain("<textarea");
    expect(text(html)).toContain("Private key");
    expect(html).toContain('aria-label="Private key source"');
    expect(buttonTag(render({ busy: true }), "Choose a file…")).toContain(DISABLED);
  });
});
