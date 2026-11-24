use super::*;

fn row(cells: &[&str]) -> Vec<Option<String>> {
    cells.iter().map(|cell| Some(cell.to_string())).collect()
}

fn column(name: &str) -> ConsoleColumn {
    ConsoleColumn { name: name.to_string(), type_name: "text".to_string() }
}

#[test]
fn tree_groups_rows_by_schema_and_relation() {
    let relations = vec![
        row(&["public", "open_orders", "v", "id", "bigint", "f"]),
        row(&["public", "orders", "r", "id", "bigint", "t"]),
        row(&["public", "orders", "r", "status", "text", "f"]),
    ];
    let functions = vec![row(&["audit", "touch", "integer"])];
    let tree = tree_from_rows(relations, functions);
    assert!(!tree.truncated);
    assert_eq!(tree.schemas.len(), 2);
    let audit = &tree.schemas[0];
    assert_eq!(audit.name, "audit");
    assert!(audit.relations.is_empty());
    assert_eq!(audit.functions, vec![FunctionNode { name: "touch".into(), arguments: "integer".into() }]);
    let public = &tree.schemas[1];
    assert_eq!(public.name, "public");
    assert_eq!(public.relations.len(), 2);
    assert_eq!(public.relations[0].name, "open_orders");
    assert_eq!(public.relations[0].kind, RelationKind::View);
    let orders = &public.relations[1];
    assert_eq!(orders.kind, RelationKind::Table);
    assert_eq!(
        orders.columns,
        vec![
            ColumnNode { name: "id".into(), type_name: "bigint".into(), primary_key: true },
            ColumnNode { name: "status".into(), type_name: "text".into(), primary_key: false },
        ]
    );
}

#[test]
fn catalog_rows_past_the_cap_set_truncated() {
    let relations: Vec<_> = (0..=MAX_RELATIONS).map(|n| row(&["public", &format!("t{n:05}"), "r", "id", "bigint", "f"])).collect();
    let tree = tree_from_rows(relations, Vec::new());
    assert!(tree.truncated);
    assert_eq!(tree.schemas[0].relations.len(), MAX_RELATIONS);

    let functions: Vec<_> = (0..=MAX_FUNCTIONS).map(|n| row(&["public", &format!("f{n:04}"), ""])).collect();
    let tree = tree_from_rows(Vec::new(), functions);
    assert!(tree.truncated);
    assert_eq!(tree.schemas[0].functions.len(), MAX_FUNCTIONS);

    let exact: Vec<_> = (0..MAX_RELATIONS).map(|n| row(&["public", &format!("t{n:05}"), "r", "id", "bigint", "f"])).collect();
    assert!(!tree_from_rows(exact, Vec::new()).truncated);
}

#[test]
fn relations_sql_leaves_out_system_schemas() {
    for name in ["pg_catalog", "information_schema", "pg_toast", "pg_temp_", "pg_toast_temp_"] {
        assert!(RELATIONS_SQL.contains(name), "{name}");
        assert!(FUNCTIONS_SQL.contains(name), "{name}");
    }
    assert!(RELATIONS_SQL.contains("LIMIT 5001"));
    assert!(FUNCTIONS_SQL.contains("LIMIT 2001"));
}

#[test]
fn csv_keeps_null_apart_from_empty() {
    let columns = [column("a"), column("b")];
    let rows = vec![
        vec![None, Some(String::new())],
        vec![Some("x,y".to_string()), Some("say \"hi\"\nok".to_string())],
    ];
    assert_eq!(csv(&columns, &rows), "a,b\r\n,\"\"\r\n\"x,y\",\"say \"\"hi\"\"\nok\"\r\n");
}

#[test]
fn json_names_repeated_columns_and_keeps_text() {
    let columns = [column("?column?"), column("?column?"), column("n")];
    let rows = vec![vec![Some("1".to_string()), None, Some("007".to_string())]];
    assert_eq!(json(&columns, &rows), r#"[{"?column?":"1","?column?_2":null,"n":"007"}]"#);
}

#[test]
fn export_replaces_the_file_whole() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("orders.csv");
    std::fs::write(&path, "old content that is longer than the new one").unwrap();
    write_replacing(&path, "a\r\n").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\r\n");
    let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    assert_eq!(names, vec![std::ffi::OsString::from("orders.csv")]);
}

#[test]
fn a_failed_export_leaves_no_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    // The target is a directory, so the rename fails after the temporary file was written.
    let path = dir.path().join("orders.csv");
    std::fs::create_dir(&path).unwrap();
    let error = write_replacing(&path, "a\r\n").unwrap_err();
    assert!(error.starts_with("Lunport could not write the export: "), "{error}");
    let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    assert_eq!(names, vec![std::ffi::OsString::from("orders.csv")]);
}
