import { describe, expect, it } from "vitest";
import type { SchemaTree } from "@/bindings/SchemaTree";
import { completionNamespace } from "./schema-completion";

const tree = (truncated: boolean): SchemaTree => ({
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

describe("completionNamespace", () => {
  it("namespace_maps_schema_relation_columns", () => {
    const namespace = completionNamespace(tree(false)) as Record<string, Record<string, { label: string; detail?: string }[]>>;
    expect(namespace.public.orders.map((column) => column.label)).toEqual(["id", "status"]);
    expect(namespace.public.orders.map((column) => column.detail)).toEqual(["bigint", "text"]);
  });
  it("namespace_of_a_capped_tree_has_its_tables_only", () => {
    const namespace = completionNamespace(tree(true)) as Record<string, Record<string, unknown>>;
    expect(Object.keys(namespace.public).sort()).toEqual(["open_orders", "orders"]);
    expect(namespace.audit).toBeUndefined();
  });
});
