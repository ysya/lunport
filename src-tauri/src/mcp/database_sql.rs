//! AI SQL sessions use a short-lived Cloud SQL TLS stream. No local database port or port password is exposed.

use super::*;
use crate::session::connect::CancelToken;
use crate::session::database_query::{self, SqlError, SqlMode};
use crate::session::protocol::{AiAsker, Unreviewed};
use crate::sync::{databases, record_runtime, records_v3::SyncStateV3};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SqlInput {
    database: String,
    sql: String,
}

fn chosen(state: &SyncStateV3, key: &str) -> Result<databases::SavedDatabase, String> {
    let saved = databases::view(state);
    if let Some(row) = saved.iter().find(|row| row.database.id == key) {
        return Ok(row.database.clone());
    }
    let mut named = saved.into_iter().filter(|row| row.database.name == key);
    let first = named
        .next()
        .ok_or("No database with this ID or name is saved.")?;
    if named.next().is_some() {
        return Err("Several databases have this name; use its ID.".into());
    }
    Ok(first.database)
}

fn permitted(
    policy: &McpPolicy,
    state: &SyncStateV3,
    db: &databases::SavedDatabase,
) -> Result<(), String> {
    if !policy.enabled
        || !policy
            .allowed_databases
            .contains(&permissions::database_key(state, &db.id))
    {
        return Err("This database is not allowed for AI SQL access.".into());
    }
    if let Some(host) = db.route_host() {
        permissions::ensure_record(policy, state, host)?;
    }
    Ok(())
}

fn current_database(app: &AppHandle, original: &databases::SavedDatabase) -> Result<(), String> {
    let state = app.state::<AppState>();
    let policy = state.mcp.policy.lock().unwrap().clone();
    let core = state.sync.core.lock().unwrap();
    let records = record_runtime::active_state(&core).map_err(|e| e.to_string())?;
    let saved = chosen(records, &original.id)?;
    if &saved != original {
        return Err("The database changed while this request was open. Try again.".into());
    }
    permitted(&policy, records, &saved)
}

struct ActiveSql<'a> {
    runtime: &'a McpRuntime,
    id: String,
}
impl Drop for ActiveSql<'_> {
    fn drop(&mut self) {
        self.runtime.sql_active.lock().unwrap().remove(&self.id);
    }
}

pub(super) fn run(
    app: &AppHandle,
    records: &SyncStateV3,
    policy: &McpPolicy,
    params: &Value,
    context: RequestContext,
    cancel: &CancelToken,
    mode: SqlMode,
) -> Result<Value, String> {
    let input: SqlInput = serde_json::from_value(params.clone())
        .map_err(|_| "Provide database and one SQL statement only.".to_string())?;
    let db = chosen(records, &input.database)?;
    permitted(policy, records, &db)?;
    database_query::validate_sql(&input.sql).map_err(|e| e.to_string())?;
    let runtime = &app.state::<AppState>().mcp;
    let at_ms = unix_ms();
    let needs_approval = mode == SqlMode::Write || policy.approval_mode == ApprovalMode::Ask;
    let mut review = if needs_approval {
        None
    } else {
        Some(McpReview::AutoLog)
    };
    let mut decision = None;
    let request = McpPendingRequest {
        id: context.id.clone(),
        alias: db.name.clone(),
        database_id: Some(db.id.clone()),
        host_id: db.route_host().map(str::to_owned),
        command: input.sql.clone(),
        client_info: context.client_info.clone(),
        requested_by: context.requested_by.clone(),
        requester_id: context.requester_id.clone(),
        requested_at_ms: at_ms,
        host_proposal: Some(McpHostProposal {
            kind: if mode == SqlMode::Write {
                "execute_database"
            } else {
                "query_database"
            }
            .into(),
            settings: vec![
                ("Saved database ID".into(), db.id.clone()),
                ("Instance".into(), db.connection_name()),
                ("PostgreSQL database".into(), db.default_database.clone()),
                ("Environment".into(), format!("{:?}", db.environment)),
                (
                    "Route".into(),
                    db.route_host()
                        .map(|id| format!("Host {id}"))
                        .unwrap_or_else(|| "Public IP".into()),
                ),
            ],
        }),
        ..Default::default()
    };
    let run_result = (|| {
        if needs_approval {
            let answer = runtime.wait_approval(&request, cancel, APPROVAL_TIMEOUT, || {
                crate::show_main_window(app);
                let _ = app.emit("mcp://approval-requested", &request);
            });
            review = activity::review_of(answer);
            decision = Some(answer);
            match answer {
                ApprovalDecision::Allow => {}
                ApprovalDecision::Deny => {
                    return Err(SqlError::Rejected("The request was denied.".into()))
                }
                ApprovalDecision::TimedOut => {
                    return Err(SqlError::Rejected("The approval request timed out.".into()))
                }
                ApprovalDecision::Cancel => {
                    return Err(SqlError::Rejected("The request was canceled.".into()))
                }
            }
        }
        current_database(app, &db).map_err(SqlError::Rejected)?;
        if cancel.is_cancelled() {
            return Err(SqlError::Rejected("The request was canceled.".into()));
        }
        if mode == SqlMode::Write
            && db.environment == databases::DatabaseEnvironment::Prod
            && crate::os_auth::unlock_method() == crate::os_auth::UnlockMethod::System
        {
            if !crate::os_auth::confirm(&format!(
                "execute SQL on the production database {}",
                db.name
            ))
            .map_err(SqlError::Failed)?
            {
                return Err(SqlError::Rejected(
                    "System authorization was denied.".into(),
                ));
            }
            current_database(app, &db).map_err(SqlError::Rejected)?;
        }
        runtime.sql_active.lock().unwrap().insert(
            context.id.clone(),
            (
                db.id.clone(),
                db.route_host().map(str::to_owned),
                cancel.clone(),
            ),
        );
        let _active = ActiveSql {
            runtime,
            id: context.id.clone(),
        };
        current_database(app, &db).map_err(SqlError::Rejected)?;
        let ai = AiAsker {
            client: records::client_label(&context),
            unreviewed: (policy.approval_mode == ApprovalMode::AutoLog && mode == SqlMode::Read)
                .then_some(Unreviewed::DatabaseQuery),
        };
        let check_app = app.clone();
        let check_db = db.clone();
        tauri::async_runtime::block_on(database_query::run_direct(
            app.clone(),
            db.clone(),
            input.sql.clone(),
            mode,
            ai,
            cancel.clone(),
            move || current_database(&check_app, &check_db),
        ))
    })();
    let mut audit = McpAuditEntry {
        id: context.id,
        client: "mcp".into(),
        database: Some(db.name.clone()),
        host_id: db.route_host().map(str::to_owned),
        alias: db
            .route_host()
            .and_then(|id| {
                crate::sync::record_repository::get_host(records, id)
                    .ok()
                    .map(|host| host.host.payload.alias)
            })
            .unwrap_or_default(),
        command: input.sql,
        mode: policy.approval_mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        at_ms,
        completed_at_ms: unix_ms(),
        review,
        ..Default::default()
    };
    match &run_result {
        Ok(result) => {
            audit.outcome = if mode == SqlMode::Write {
                "database_executed"
            } else {
                "database_queried"
            }
            .into();
            audit.rows_affected = result.affected_rows;
            if mode == SqlMode::Read {
                audit.rows_returned = Some(result.rows.len() as u64);
            }
        }
        Err(error) => {
            audit.outcome = match error {
                SqlError::Uncertain(_) => "database_write_uncertain",
                _ if mode == SqlMode::Write => "database_not_executed",
                _ => "database_not_queried",
            }
            .into();
            audit.stop = Some(activity::stop_for(
                &error.to_string(),
                decision,
                None,
                cancel.is_cancelled(),
            ));
        }
    }
    let audit_error = runtime.record_deployment(audit);
    run_result
        .map(|result| {
            let mut value = serde_json::to_value(result).expect("SQL result serializes");
            if let Some(error) = audit_error {
                value["audit_error"] = json!(error);
            }
            value
        })
        .map_err(|error| error.to_string())
}

pub(super) fn tool_definitions() -> Vec<Value> {
    let input = json!({"type":"object","properties":{"database":{"type":"string","description":"Saved database ID or exact unambiguous name."},"sql":{"type":"string","maxLength":16384,"description":"One PostgreSQL statement; SQL text appears in local review and audit."}},"required":["database","sql"],"additionalProperties":false});
    vec![
        json!({"name":"query_database","title":"Query Cloud SQL","description":"Run one SQL statement on a short-lived IAM-authenticated Cloud SQL connection. The server locks this session read-only in every environment. Ask mode requires local approval; Auto-log records it without per-query approval. Results are limited to 100 rows and 256 KiB. Never opens or uses the local database port.","inputSchema":input.clone(),"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":false,"openWorldHint":true}}),
        json!({"name":"execute_database","title":"Write to Cloud SQL","description":"Run one SQL statement on a short-lived IAM-authenticated Cloud SQL connection. Always requires local approval, including Auto-log; production additionally requests system authorization where available. If the reply is lost, the outcome is uncertain and the write is never retried automatically.","inputSchema":input,"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}}),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::databases::{DatabaseEngine, DatabaseEnvironment, DatabaseNetwork};

    fn state() -> SyncStateV3 {
        serde_json::from_value(json!({"version":4,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture","relay_url":"http://127.0.0.1","local":{}})).unwrap()
    }
    fn database() -> databases::SavedDatabase {
        databases::SavedDatabase {
            id: "00000000000000b1".into(),
            name: "orders".into(),
            engine: DatabaseEngine::Postgres,
            project: "acme-dev-654321".into(),
            region: "asia-east1".into(),
            instance: "orders-pg".into(),
            environment: DatabaseEnvironment::Dev,
            network: DatabaseNetwork::Public,
            via_host: None,
            account: Some("frank@example.com".into()),
            default_database: "postgres".into(),
            pam: None,
            local_port: None,
        }
    }

    #[test]
    fn sql_requires_explicit_database_grant_and_route_host_grant() {
        let state = state();
        let db = database();
        let mut policy = McpPolicy {
            enabled: true,
            ..Default::default()
        };
        assert!(permitted(&policy, &state, &db).is_err());
        policy
            .allowed_databases
            .insert(permissions::database_key(&state, &db.id));
        assert!(permitted(&policy, &state, &db).is_ok());
        assert_eq!(
            permissions::active_databases(&policy, &state),
            vec![db.id.clone()]
        );
        let mut another_library = state.clone();
        another_library.device_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into();
        assert!(permitted(&policy, &another_library, &db).is_err());
        assert!(permissions::active_databases(&policy, &another_library).is_empty());
        let routed = databases::SavedDatabase {
            network: DatabaseNetwork::Private,
            via_host: Some("00000000000000c1".into()),
            ..db
        };
        assert!(permitted(&policy, &state, &routed).is_err());
        policy.enabled = false;
        assert!(permitted(&policy, &state, &database()).is_err());
    }
}
