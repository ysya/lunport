use super::*;
pub(crate) fn with_path(path: PathBuf) -> McpRuntime {
    let runtime = McpRuntime::default();
    runtime.audit.lock().unwrap().path = Some(path);
    runtime
}
pub(crate) fn entries(runtime: &McpRuntime) -> Vec<McpAuditEntry> {
    runtime.recent.lock().unwrap().iter().cloned().collect()
}
#[test]
fn deployment_audit_returns_this_write_result_not_a_previous_global_error() {
    let runtime = McpRuntime::default();
    runtime.audit.lock().unwrap().error = Some("old error".into());
    let entry: McpAuditEntry=serde_json::from_value(serde_json::json!({"id":"deployment-test","alias":"web","command":"Deploy public key SHA256:public","outcome":"added","exit_code":0,"detail":null,"completed_at_ms":1})).unwrap();
    assert_eq!(
        runtime.record_deployment(entry),
        None,
        "in-memory write succeeded; old global error is not this write's result"
    );
}

#[test]
fn audit_reader_stops_after_limit_plus_one_bytes() {
    use std::io::Read;
    let mut reader = std::io::repeat(b'x').take(34 * 1024 * 1024);
    let bytes = read_audit_bytes(&mut reader).unwrap();
    assert_eq!(bytes.len(), 32 * 1024 * 1024 + 1);
    assert_eq!(reader.limit(), 2 * 1024 * 1024 - 1);
}

#[test]
fn audit_reader_rejects_oversized_open_file_without_loading_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oversized.jsonl");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(34 * 1024 * 1024).unwrap();
    let runtime = McpRuntime::default();
    runtime.load_audit(path);
    assert_eq!(runtime.status().audit_error.as_deref(), Some("Session log exceeds the 32 MiB read limit."));
    assert!(runtime.status().recent.is_empty());
}
