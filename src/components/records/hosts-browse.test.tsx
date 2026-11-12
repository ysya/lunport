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
  it("offers All hosts, Groups, and Tags inside the Hosts page", () => {
    const html = render({ kind: "all" });
    expect(html).toContain('aria-label="Host browse"');
    expect(html).toContain('aria-label="Browse all hosts"');
    expect(html).toContain('aria-label="Browse groups"');
    expect(html).toContain('aria-label="Browse tags"');
  });
  it("shows root groups and Ungrouped without displaying every host in the group index", () => {
    const html = render({ kind: "groups" } as LibraryFilter);
    expect(html).toContain('aria-label="Open group Operations"');
    expect(html).toContain('aria-label="Open ungrouped hosts"');
    expect(html).not.toContain('data-host-id="' + host.id + '"');
  });
  it("offers an expand control for nested groups in the group index", () => {
    const html = render({ kind: "groups" });
    expect(html).toContain('aria-label="Expand group Operations"');
    expect(html).toContain('aria-expanded="false"');
  });
  it("shows searchable tags with host counts without displaying every host in the tag index", () => {
    const html = render({ kind: "tags" } as LibraryFilter);
    expect(html).toContain('aria-label="Search tags"');
    expect(html).toContain('aria-label="Open tag production (1 host)"');
    expect(html).not.toContain('data-host-id="' + host.id + '"');
  });
  it("keeps the selected group and tag as Hosts filters", () => {
    const grouped = render({ kind: "group", id: parent.id });
    expect(grouped).toContain('aria-label="Browse groups" aria-current="page"');
    expect(grouped).toContain('aria-label="Open group API"');
    const tagged = render({ kind: "tag", id: "production" });
    expect(tagged).toContain('aria-label="Browse tags" aria-current="page"');
    expect(tagged).toContain('data-host-id="' + host.id + '"');
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
