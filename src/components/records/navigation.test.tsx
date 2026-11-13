import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { LibraryNavigation } from "./LibraryNavigation";
import { groupView, hostPayload, hostTransport, hostView, recordOverview } from "./fixtures";
const navigationState = vi.hoisted(() => ({
  librarySidebarCollapsed: false,
}));

vi.mock("@/stores/ui", () => ({
  useUiStore: (selector: (state: typeof navigationState) => unknown) => selector(navigationState),
}));

afterEach(() => { navigationState.librarySidebarCollapsed = false; });

function navigation() {
  const parent = groupView();
  const child = groupView({ id: "0000000000000011", payload: { schema: 1, name: "API", parent_id: parent.id, defaults: {} } });
  return renderToStaticMarkup(<LibraryNavigation
    overview={recordOverview({ groups: [parent, child], hosts: [hostView({ payload: hostPayload({ tags: ["production"] }) })] })}
    panel="hosts"
    navigate={vi.fn()}
    changeFilter={vi.fn()}
  />);
}

describe("Records navigation controls", () => {
  it("shows one Hosts destination without group and tag navigation", () => {
    const html = navigation();
    expect(html).toContain('aria-label="Hosts (1)"');
    expect(html).not.toContain('aria-label="Groups"');
    expect(html).not.toContain('aria-label="Tags"');
    expect(html).not.toContain('class="library-nav-collections');
  });
  it("the sidebar groups connection pages after AI activity", () => {
    const html = navigation();
    const tunnels = html.indexOf('aria-label="Tunnels"');
    const activity = html.indexOf('aria-label="AI activity"');
    expect(tunnels).toBeGreaterThan(-1);
    expect(activity).toBeLessThan(html.indexOf(">Connections</div>"));
    expect(tunnels).toBeGreaterThan(html.indexOf(">Connections</div>"));
    expect(tunnels).toBeLessThan(html.indexOf(">Cloud</div>"));
  });

  it("names Google Cloud without a count, whatever routes the library holds", () => {
    const html = renderToStaticMarkup(<LibraryNavigation
      overview={recordOverview({ transports: [hostTransport()] })}
      panel="transports"
      navigate={vi.fn()}
      changeFilter={vi.fn()}
    />);
    expect(html).toContain('aria-label="Google Cloud"');
    expect(html).not.toContain('aria-label="Google Cloud (');
    // The rows with a count keep it.
    expect(html).toContain('aria-label="Hosts (1)"');
  });

  it("lists the cloud providers under a Cloud heading of their own, Google Cloud first", () => {
    const html = renderToStaticMarkup(<LibraryNavigation
      overview={recordOverview()}
      panel="hosts"
      navigate={vi.fn()}
      changeFilter={vi.fn()}
    />);
    const cloud = html.slice(html.indexOf('aria-label="Cloud providers"'));
    expect(html).toContain(">Cloud</div>");
    expect(cloud).toContain('aria-label="Google Cloud"');
    // Google Cloud is no longer among the library's own rows.
    expect(html.slice(html.indexOf('aria-label="Workspace sections"'), html.indexOf('aria-label="Cloud providers"'))).not.toContain("Google Cloud");
  });

  it("keeps Hosts available in the collapsed rail", () => {
    navigationState.librarySidebarCollapsed = true;
    const html = navigation();
    expect(html).toContain('data-collapsed="true"');
    expect(html).toContain('aria-label="Hosts (1)"');
    expect(html).not.toContain('aria-label="Settings"');
  });
});
