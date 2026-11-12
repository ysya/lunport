import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { RecordHostList, browseGroupNodes } from "./HostList";
import { groupView, hostPayload, hostView, recordOverview } from "./fixtures";
import { buildRecordTree } from "./group-tree";
import type { LibraryFilter } from "./library-view";

const parent = groupView();
const child = groupView({ id: "0000000000000011", payload: { schema: 1, name: "API", parent_id: parent.id, defaults: {} } });
const host = hostView({ payload: hostPayload({ group_id: child.id, tags: ["production"] }) });
const overview = recordOverview({ hosts: [host], groups: [parent, child] });
const render = (filter: LibraryFilter, data = overview) => renderToStaticMarkup(
  <RecordHostList overview={data} selectedId={null} select={vi.fn()} filter={filter} changeFilter={vi.fn()} createGroup={vi.fn()} />,
);

describe("Hosts browsing", () => {
  it("keeps the group collection visible beside the all-hosts list", () => {
    const html = render({ kind: "all" });
    expect(html).toContain('aria-label="Host collections"');
    expect(html).toContain('aria-label="Open group Operations"');
    expect(html).toContain('data-host-id="' + host.id + '"');
  });
  it("offers All hosts, Groups, and Tags in the persistent collection pane", () => {
    const html = render({ kind: "all" });
    expect(html).toContain('aria-label="Host collections"');
    expect(html).toContain('aria-label="Host collection filters"');
    expect(html).toContain('>All hosts</span>');
    expect(html).toContain('>Groups</button>');
    expect(html).toContain('>Tags</button>');
  });
  it("shows root groups and Ungrouped beside the host list", () => {
    const html = render({ kind: "all" });
    expect(html).toContain('aria-label="Open group Operations"');
    expect(html).toContain('>Ungrouped</span>');
    expect(html).toContain('data-host-id="' + host.id + '"');
  });
  it("offers an expand control for nested groups in the group index", () => {
    const html = render({ kind: "groups" });
    expect(html).toContain('aria-label="Expand group Operations"');
    expect(html).toContain('aria-expanded="false"');
  });
  it("shows searchable tags with host counts in the collection pane", () => {
    const html = render({ kind: "all" });
    expect(html).toContain('aria-label="Find groups or tags"');
    expect(html).toContain('>production</span><small>1</small>');
  });
  it("keeps the selected group and tag as Hosts filters", () => {
    const grouped = render({ kind: "group", id: parent.id });
    expect(grouped).toContain('aria-label="Open group Operations" aria-current="page"');
    expect(grouped).not.toContain('data-host-id="' + host.id + '"');
    expect(grouped).toContain("No hosts directly in this group");
    expect(render({ kind: "group", id: child.id })).toContain('data-host-id="' + host.id + '"');
    const tagged = render({ kind: "tag", id: "production" });
    expect(tagged).toContain('>production</span><small>1</small>');
    expect(tagged).toContain('data-host-id="' + host.id + '"');
  });
  it("shows the full group path in a cross-group host list", () => {
    const html = render({ kind: "all" });
    expect(html).toContain('title="Operations / API"');
  });
  it("shows multiple ancestor groups as navigable breadcrumbs", () => {
    const grandchild = groupView({
      id: "0000000000000012",
      payload: { schema: 1, name: "Database", parent_id: child.id, defaults: {} },
    });
    const html = render(
      { kind: "group", id: grandchild.id },
      recordOverview({ groups: [parent, child, grandchild] }),
    );
    expect(html).toContain('aria-label="Go to group Operations"');
    expect(html).toContain('aria-label="Go to group API"');
    expect(html).toContain('aria-current="location">Database</span>');
    expect(html.indexOf('aria-label="Go to group Operations"')).toBeLessThan(
      html.indexOf('aria-label="Go to group API"'),
    );
  });
  it("keeps group cards available for pointer ordering", () => {
    const html = renderToStaticMarkup(<RecordHostList overview={overview} selectedId={null} select={vi.fn()}
      filter={{ kind: "groups" }} changeFilter={vi.fn()} reorder={vi.fn()} />);
    expect(html).toContain(`data-group-row="${parent.id}" data-reorderable="true"`);
  });
  it("searches group names directly without treating host names as group matches", () => {
    const roots = buildRecordTree(overview);
    expect(browseGroupNodes(roots, "API").map((node) => node.group.id)).toEqual([child.id]);
    expect(browseGroupNodes(roots, "web")).toEqual([]);
    expect(browseGroupNodes(roots, "").map((node) => node.group.id)).toEqual([parent.id]);
  });
});
