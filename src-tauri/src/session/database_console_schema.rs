//! The console's schema tree, read from the catalog in one pass, and the CSV and JSON forms of a kept result.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::database_console::{ConsoleColumn, ConsoleConnection};

/// Relations and functions the tree keeps; the catalog reads ask for one more of each to know whether more exist.
pub(crate) const MAX_RELATIONS: usize = 5_000;
pub(crate) const MAX_FUNCTIONS: usize = 2_000;

/// One row per column of the first `MAX_RELATIONS + 1` relations: schema, relation, relkind, column, type, primary key.
pub(crate) const RELATIONS_SQL: &str = "\
WITH rel AS (
  SELECT c.oid, n.nspname, c.relname, c.relkind
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
    AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
    AND left(n.nspname, 8) <> 'pg_temp_'
    AND left(n.nspname, 14) <> 'pg_toast_temp_'
  ORDER BY n.nspname, c.relname
  LIMIT 5001
)
SELECT rel.nspname, rel.relname, rel.relkind::text, a.attname, format_type(a.atttypid, a.atttypmod),
  EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = rel.oid AND i.indisprimary AND a.attnum = ANY (i.indkey))::text
FROM rel
JOIN pg_attribute a ON a.attrelid = rel.oid AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY rel.nspname, rel.relname, a.attnum";

/// Schema, function name and identity arguments of the first `MAX_FUNCTIONS + 1` functions.
pub(crate) const FUNCTIONS_SQL: &str = "\
SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND left(n.nspname, 8) <> 'pg_temp_'
  AND left(n.nspname, 14) <> 'pg_toast_temp_'
ORDER BY n.nspname, p.proname, 3
LIMIT 2001";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SchemaTree {
    pub schemas: Vec<SchemaNode>,
    /// More relations or functions exist than the tree holds.
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SchemaNode {
    pub name: String,
    pub relations: Vec<RelationNode>,
    pub functions: Vec<FunctionNode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Table,
    View,
    MaterializedView,
    ForeignTable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct RelationNode {
    pub name: String,
    pub kind: RelationKind,
    pub columns: Vec<ColumnNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ColumnNode {
    pub name: String,
    pub type_name: String,
    pub primary_key: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct FunctionNode {
    pub name: String,
    pub arguments: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Csv,
    Json,
}

fn relation_kind(relkind: &str) -> Option<RelationKind> {
    match relkind {
        "r" | "p" => Some(RelationKind::Table),
        "v" => Some(RelationKind::View),
        "m" => Some(RelationKind::MaterializedView),
        "f" => Some(RelationKind::ForeignTable),
        _ => None,
    }
}

/// Groups the catalog rows by schema and relation, keeping their given order within a schema. Past the caps the extra
/// relations and functions are dropped and `truncated` is set. A row with a missing cell is skipped.
pub(crate) fn tree_from_rows(relations: Vec<Vec<Option<String>>>, functions: Vec<Vec<Option<String>>>) -> SchemaTree {
    let mut schemas: BTreeMap<String, SchemaNode> = BTreeMap::new();
    let mut truncated = false;
    let mut kept_relations = 0usize;
    // The relation the previous row belonged to, and whether it was dropped for the cap.
    let mut current: Option<(String, String)> = None;
    let mut current_dropped = false;
    for row in relations {
        let [Some(schema), Some(relation), Some(relkind), Some(column), Some(type_name), Some(primary_key)] = &row[..] else {
            continue;
        };
        let Some(kind) = relation_kind(relkind) else { continue };
        let same = current.as_ref().is_some_and(|(s, r)| s == schema && r == relation);
        if !same {
            current = Some((schema.clone(), relation.clone()));
            current_dropped = kept_relations >= MAX_RELATIONS;
            if current_dropped {
                truncated = true;
            } else {
                kept_relations += 1;
                schemas
                    .entry(schema.clone())
                    .or_insert_with(|| SchemaNode { name: schema.clone(), relations: Vec::new(), functions: Vec::new() })
                    .relations
                    .push(RelationNode { name: relation.clone(), kind, columns: Vec::new() });
            }
        }
        if current_dropped {
            continue;
        }
        if let Some(node) = schemas.get_mut(schema).and_then(|node| node.relations.last_mut()) {
            node.columns.push(ColumnNode {
                name: column.clone(),
                type_name: type_name.clone(),
                primary_key: primary_key == "t" || primary_key == "true",
            });
        }
    }
    for (index, row) in functions.into_iter().enumerate() {
        if index >= MAX_FUNCTIONS {
            truncated = true;
            break;
        }
        let [Some(schema), Some(name), Some(arguments)] = &row[..] else { continue };
        schemas
            .entry(schema.clone())
            .or_insert_with(|| SchemaNode { name: schema.clone(), relations: Vec::new(), functions: Vec::new() })
            .functions
            .push(FunctionNode { name: name.clone(), arguments: arguments.clone() });
    }
    SchemaTree { schemas: schemas.into_values().collect(), truncated }
}

/// Reads the relations, their columns and the functions with two catalog statements.
pub(crate) async fn read_schema(connection: &ConsoleConnection) -> Result<SchemaTree, String> {
    let relations = connection.read_rows(RELATIONS_SQL).await?;
    let functions = connection.read_rows(FUNCTIONS_SQL).await?;
    Ok(tree_from_rows(relations, functions))
}

fn csv_field(out: &mut String, value: Option<&str>) {
    match value {
        None => {}
        Some(text) if text.is_empty() || text.contains([',', '"', '\r', '\n']) => {
            out.push('"');
            out.push_str(&text.replace('"', "\"\""));
            out.push('"');
        }
        Some(text) => out.push_str(text),
    }
}

/// RFC 4180 with a header row. NULL is an empty unquoted field, and an empty string is `""`.
pub(crate) fn csv(columns: &[ConsoleColumn], rows: &[Vec<Option<String>>]) -> String {
    let mut out = String::new();
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        csv_field(&mut out, Some(&column.name));
    }
    out.push_str("\r\n");
    for row in rows {
        for (index, value) in row.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            csv_field(&mut out, value.as_deref());
        }
        out.push_str("\r\n");
    }
    out
}

fn json_string(text: &str) -> String {
    serde_json::to_string(text).expect("a string always serializes")
}

/// Keys for the columns: a repeated name gets `_2`, `_3` and so on.
fn json_keys(columns: &[ConsoleColumn]) -> Vec<String> {
    let mut used: HashSet<String> = columns.iter().map(|column| column.name.clone()).collect();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut keys = Vec::with_capacity(columns.len());
    for column in columns {
        if seen.insert(column.name.as_str()) {
            keys.push(column.name.clone());
            continue;
        }
        let mut n = 2;
        let key = loop {
            let candidate = format!("{}_{n}", column.name);
            if used.insert(candidate.clone()) {
                break candidate;
            }
            n += 1;
        };
        keys.push(key);
    }
    keys
}

/// An array of objects keyed by column name, in column order. Every value is the text PostgreSQL printed, or null.
pub(crate) fn json(columns: &[ConsoleColumn], rows: &[Vec<Option<String>>]) -> String {
    let keys: Vec<String> = json_keys(columns).iter().map(|key| json_string(key)).collect();
    let mut out = String::from("[");
    for (row_index, row) in rows.iter().enumerate() {
        if row_index > 0 {
            out.push(',');
        }
        out.push('{');
        for (index, key) in keys.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(key);
            out.push(':');
            match row.get(index).and_then(|value| value.as_deref()) {
                Some(text) => out.push_str(&json_string(text)),
                None => out.push_str("null"),
            }
        }
        out.push('}');
    }
    out.push(']');
    out
}

/// Writes `content` to a temporary file beside `path` and renames it over `path`, so the file is old or new, never half
/// written. A failure removes the temporary file. The error never holds the content.
pub(crate) fn write_replacing(path: &Path, content: &str) -> Result<(), String> {
    let name = path.file_name().ok_or_else(|| "Lunport could not write the export: the path has no file name.".to_string())?;
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(name);
    temporary_name.push(".lunport-tmp");
    let temporary = path.with_file_name(temporary_name);
    let result = std::fs::write(&temporary, content).and_then(|()| std::fs::rename(&temporary, path));
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("Lunport could not write the export: {error}"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "database_console_schema_tests.rs"]
mod tests;
