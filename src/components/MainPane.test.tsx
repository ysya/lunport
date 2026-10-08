import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { MainPaneContent } from "./MainPane";

const hosts = <form id="host-editor-form">web</form>;
const keyDetail = <section id="key-detail">id_mac</section>;
const pane = (keychain: boolean) => renderToStaticMarkup(<MainPaneContent keychain={keychain} hosts={hosts} keyDetail={keyDetail} />);

describe("the main pane", () => {
  it("shows the host editor in Hosts, and no key's detail", () => {
    const html = pane(false);
    expect(html).toContain('<form id="host-editor-form">web</form>');
    expect(html).not.toContain("hidden");
    expect(html).not.toContain("key-detail");
  });

  it("keeps the host editor mounted, only hidden, while the Keychain shows: its unsaved edits live in its form", () => {
    const html = pane(true);
    expect(html).toContain('hidden=""');
    expect(html).toContain('<form id="host-editor-form">web</form>');
    expect(html).toContain('<section id="key-detail">id_mac</section>');
    // The hidden wrapper holds the editor, not the key's detail.
    expect(html.indexOf("host-editor-form")).toBeGreaterThan(html.indexOf('hidden=""'));
    expect(html.indexOf("key-detail")).toBeGreaterThan(html.indexOf("</div>"));
  });
});
