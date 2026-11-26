import type { SQLNamespace } from "@codemirror/lang-sql";
import type { SchemaTree } from "@/bindings/SchemaTree";

/** Schema -> relation -> its columns, each with its type as the detail. Functions are left out. */
type Column = { label: string; detail: string; type: string };

export function completionNamespace(tree: SchemaTree): SQLNamespace {
  const namespace: { [schema: string]: { [relation: string]: Column[] } } = {};
  for (const schema of tree.schemas) {
    if (schema.relations.length === 0) continue;
    const relations: { [relation: string]: Column[] } = {};
    for (const relation of schema.relations) {
      relations[relation.name] = relation.columns.map((column) => ({
        label: column.name,
        detail: column.type_name,
        type: "property",
      }));
    }
    namespace[schema.name] = relations;
  }
  return namespace;
}
