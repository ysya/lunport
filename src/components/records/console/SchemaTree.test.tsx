import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SchemaTree as Tree } from "@/bindings/SchemaTree";
import { DISABLED, text } from "@/components/keychain/test-markup";
import { SchemaTree } from "./SchemaTree";

const tree = (truncated = false): Tree => ({
  truncated,
  schemas: [
    {
      name: "public",
      relations: [
        {
          name: "orders",
          kind: "table",
          columns: [
            { name: "id", type_name: "bigint", primary_key: true },
            { name: "status", type_name: "text", primary_key: false },
          ],
        },
        { name: "open_orders", kind: "view", columns: [{ name: "id", type_name: "bigint", primary_key: false }] },
      ],
      functions: [],
    },
    { name: "audit", relations: [], functions: [{ name: "touch", arguments: "integer" }] },
  ],
});

function render(props: Partial<Parameters<typeof SchemaTree>[0]> = {}) {
  return renderToStaticMarkup(<SchemaTree tree={tree()} error={null} canRefresh onRefresh={vi.fn()} canBrowse onBrowse={vi.fn()} preview={null} {...props} />);
}

describe("SchemaTree", () => {
  it("a_table_shows_its_columns_with_type_and_primary_key", () => {
    const words = text(render({ initialOpen: ["public.orders"] }));
    expect(words).toContain("orders");
    expect(words).toContain("id bigint · PK");
    expect(words).toContain("status text");
    expect(words).not.toContain("text · PK");
  });

  it("tables_and_views_are_grouped_under_their_schema", () => {
    const words = text(render());
    expect(words).toMatch(/public Tables 1 orders Views 1/);
    expect(words).toContain("audit");
  });

  it("a_closed_table_keeps_its_columns_out_of_the_page", () => {
    expect(text(render())).not.toContain("bigint");
  });

  it("offers independent actions for browsing a table and expanding its columns", () => {
    const html = render({ canBrowse: true });
    expect(html).toMatch(/<button[^>]*aria-label="Expand columns for orders"[^>]*aria-expanded="false"/);
    expect(html).toMatch(/<button[^>]*aria-label="Browse data in public.orders"[^>]*>/);
  });

  it("keeps the column toggle available while browsing is disabled", () => {
    const html = render({ canBrowse: false });
    const browse = html.match(/<button[^>]*aria-label="Browse data in public.orders"[^>]*>/)?.[0];
    const expand = html.match(/<button[^>]*aria-label="Expand columns for orders"[^>]*>/)?.[0];
    expect(browse).toContain(DISABLED);
    expect(expand).toBeDefined();
    expect(expand).not.toContain(DISABLED);
  });

  it("a_capped_tree_says_how_far_it_goes", () => {
    expect(text(render({ tree: tree(true) }))).toContain("Lunport shows the first 5,000 tables and views.");
    expect(text(render())).not.toContain("Lunport shows the first");
  });

  it("a_failed_read_shows_its_sentence", () => {
    expect(text(render({ tree: null, error: "The connection ended. Reconnect to go on." }))).toContain("The connection ended. Reconnect to go on.");
  });

  it("refresh_waits_for_an_open_session", () => {
    const html = render({ canRefresh: false });
    expect(html).toMatch(new RegExp(`<button[^>]*aria-label="Refresh schema"[^>]*${DISABLED}|<button[^>]*${DISABLED}[^>]*aria-label="Refresh schema"`));
    expect(html).toContain('aria-label="Filter tables"');
  });
});
