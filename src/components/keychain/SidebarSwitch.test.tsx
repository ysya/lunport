import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { SidebarView } from "@/stores/ui";
import { SidebarSwitchView } from "./SidebarSwitch";
import { buttonTag, buttonsIn, textIn } from "./test-markup";

describe("the sidebar switch", () => {
  it("marks the view that shows", () => {
    const html = renderToStaticMarkup(<SidebarSwitchView view="keychain" onView={() => {}} />);
    expect(buttonTag(html, "Keychain")).toContain('aria-pressed="true"');
    expect(buttonTag(html, "Hosts")).toContain('aria-pressed="false"');
  });

  it("switches to the view that is pressed", () => {
    const views: SidebarView[] = [];
    const buttons = buttonsIn(SidebarSwitchView({ view: "hosts", onView: (v) => views.push(v) }));
    expect(buttons.map(textIn)).toEqual(["Hosts", "Keychain"]);
    buttons.forEach((b) => b.props.onClick!());
    expect(views).toEqual(["hosts", "keychain"]);
  });
});
