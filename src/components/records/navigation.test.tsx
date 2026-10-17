import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { LibraryNavigation } from "./LibraryNavigation";
import { groupView, recordOverview } from "./fixtures";
const navigationState = vi.hoisted(() => ({
  librarySidebarCollapsed: false,
  collapsedRecordGroups: [] as string[],
  toggleRecordGroup: () => { },
}));

vi.mock("@/stores/ui", () => ({
  useUiStore: (selector: (state: typeof navigationState) => unknown) => selector(navigationState),
}));

afterEach(() => { navigationState.librarySidebarCollapsed = false; navigationState.collapsedRecordGroups = []; });

function navigation() {
  const parent = groupView();
  const child = groupView({ id: "0000000000000011", payload: { schema: 1, name: "API", parent_id: parent.id, defaults: {} } });
  return renderToStaticMarkup(<LibraryNavigation
    overview={recordOverview({ groups: [parent, child] })}
    panel="hosts"
    filter={{ kind: "all" }}
    navigate={vi.fn()}
    changeFilter={vi.fn()}
    createGroup={vi.fn()}
  />);
}

describe("Records navigation controls", () => {
  it("keeps group navigation separate from its disclosure and removes closed children from interaction", () => {
    navigationState.collapsedRecordGroups = ["local:0000000000000010"];
    const html = navigation();
    expect(html).toContain('aria-label="Expand Operations"');
    expect(html).toContain('aria-expanded="false"');
    expect(html).toContain('data-open="false" inert="" aria-hidden="true"');
    expect(html).toContain('aria-label="Operations (0)"');
    expect(html).toContain('aria-label="API (0)"');
  });
  it("keeps named top-level navigation while removing Groups and Tags from a collapsed rail's focus order", () => {
    navigationState.librarySidebarCollapsed = true;
    const html = navigation();
    expect(html).toContain('data-collapsed="true"');
    expect(html).toContain('aria-label="All hosts (1)"');
    expect(html).toMatch(/class="library-nav-collections[^\"]*" inert="" aria-hidden="true"/);
    expect(html).not.toContain('aria-label="Settings"');
  });
});
