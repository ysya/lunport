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
