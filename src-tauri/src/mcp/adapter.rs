//! Thin, credential-free MCP adapter. Transport selection comes only from the authenticated broker.
use super::*;
use crate::ipc::server::Stream;
use crate::session::{connect::CancelToken, protocol::*};
#[derive(Default)]
pub(super) struct Call {
    pub cancel: CancelToken,
    stream: Mutex<Option<Stream>>,
    legacy: AtomicBool,
}
impl Call {
    pub fn cancel(&self, id: &str) {
        self.cancel.cancel();
        if let Some(stream) = self.stream.lock().unwrap().as_ref() {
            close(stream);
        }
        if self.legacy.load(Ordering::SeqCst) {
            let _ = bridge_call("cancel", json!({"request_id":id}));
        }
    }
}
#[cfg(unix)]
fn close(stream: &Stream) {
    let _ = stream.shutdown(std::net::Shutdown::Both);
}
#[cfg(windows)]
fn close(stream: &Stream) {
    stream.hang_up();
}

pub(super) fn ipc_call(
    method: &str,
    params: Value,
    info: &McpClientInfo,
    call: &Call,
) -> Result<Value, String> {
    if call.cancel.is_cancelled() {
        return Err("MCP request was canceled".into());
    }
    let stream = crate::cli::reach_broker()?;
    ipc_on(stream, method, params, info, call)
}
pub(super) fn ipc_on(
    mut stream: Stream,
    method: &str,
    params: Value,
    info: &McpClientInfo,
    call: &Call,
) -> Result<Value, String> {
    {
        let mut slot = call.stream.lock().unwrap();
        if call.cancel.is_cancelled() {
            close(&stream);
            return Err("MCP request was canceled".into());
        }
        *slot = Some(
            stream
                .try_clone()
                .map_err(|_| "Cannot monitor IPC cancellation")?,
        );
    }
    let result = (|| {
        write_control(
            &mut stream,
            &ClientMessage::Hello {
                client: ClientKind::Mcp,
                version: crate::session::protocol::MCP_PROTOCOL_VERSION,
                client_info: Some(serde_json::to_value(info).unwrap()),
            },
        )
        .map_err(|_| "Session IPC hello failed")?;
        write_control(
            &mut stream,
            &McpClientMessage::McpCall {
                method: method.into(),
                params,
            },
        )
        .map_err(|_| "Session IPC request failed")?;
        let Some(Frame::Control(payload)) =
            read_frame(&mut stream).map_err(|_| "Session IPC disconnected")?
        else {
            return Err("Session IPC disconnected".into());
        };
        match decode::<McpServerMessage>(&payload) {
            Ok(McpServerMessage::McpResult {
                result: Some(v),
                error: None,
            }) => Ok(v),
            Ok(McpServerMessage::McpResult { error: Some(e), .. }) => Err(e),
            _ => Err("Session IPC protocol mismatch; restart Lunport.".into()),
        }
    })();
    call.stream.lock().unwrap().take();
    close(&stream);
    result
}

pub(super) fn tool(params: &Value, id: &str, info: &McpClientInfo, call: &Call) -> Value {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(
        name,
        "list_hosts" | "get_host" | "get_effective_config" | "ssh_exec" | "run" | "create_host" | "verify_host_key"
    ) {
        return tool_error(format!("Unknown tool: {name}"));
    }
    let mut arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut result = ipc_call(name, arguments.clone(), info, call);
    if result
        .as_ref()
        .err()
        .is_some_and(|e| e == "legacy_transport_required")
    {
        if matches!(name, "create_host" | "verify_host_key") {
            return tool_error("This tool requires a Records workspace in the current Lunport version.".into());
        }
        call.legacy.store(true, Ordering::SeqCst);
        if call.cancel.is_cancelled() {
            return tool_error("MCP request was canceled".into());
        }
        if let Some(args) = arguments.as_object_mut() {
            args.insert("_request_id".into(), json!(id));
        }
        result = bridge_call(
            match name {
                "get_host" => "get_effective_config",
                "ssh_exec" => "run",
                other => other,
            },
            arguments,
        );
    }
    match result {
        Ok(result) => {
            json!({"content":[{"type":"text","text":serde_json::to_string_pretty(&result).unwrap()}],"structuredContent":result,"isError":false})
        }
        Err(e) => tool_error(e),
    }
}

/// Insert exactly once; a duplicate JSON-RPC ID must never replace the cancellation handle.
pub(super) fn insert(
    calls: &Mutex<HashMap<String, (String, Arc<Call>)>>,
    key: String,
    id: String,
) -> Result<Arc<Call>, String> {
    let mut calls = calls.lock().unwrap();
    if calls.contains_key(&key) {
        return Err("duplicate active JSON-RPC id".into());
    }
    if calls.len() >= 16 {
        return Err("Too many concurrent MCP requests (maximum 16)".into());
    }
    let call = Arc::new(Call::default());
    calls.insert(key, (id, call.clone()));
    Ok(call)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_rpc_ids_preserve_original_handle_and_cancel_before_ipc_registration() {
        let calls = Mutex::new(HashMap::new());
        let first = insert(&calls, "1".into(), "original".into()).unwrap();
        assert!(insert(&calls, "1".into(), "replacement".into()).is_err());
        assert_eq!(calls.lock().unwrap()["1"].0, "original");
        calls.lock().unwrap()["1"].1.cancel("original");
        assert!(first.cancel.is_cancelled());
        #[cfg(unix)]
        {
            let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
            assert!(
                ipc_on(a, "ssh_exec", json!({}), &McpClientInfo::default(), &first)
                    .unwrap_err()
                    .contains("canceled")
            );
        }
    }
    #[test]
    fn concurrency_is_bounded_and_client_info_cannot_supply_a_requester_identity() {
        let calls = Mutex::new(HashMap::new());
        for n in 0..16 {
            insert(&calls, n.to_string(), n.to_string()).unwrap();
        }
        assert!(insert(&calls, "17".into(), "17".into()).is_err());
        let context = RequestContext::from_peer(
            None,
            Some(
                &json!({"name":"\u{1b}fake\u{202e}","title":"x".repeat(120),"pid":123,"requester_id":"trusted","version":"1\n2"}),
            ),
        );
        assert_eq!(context.requested_by, ["Unknown"]);
        assert_eq!(context.requester_id, None);
        assert_eq!(context.client_info.name.as_deref(), Some("fake"));
        assert_eq!(context.client_info.title.unwrap().chars().count(), 100);
        assert_eq!(context.client_info.version.as_deref(), Some("12"));
    }
}

#[cfg(all(test, unix))]
mod ipc_tests {
    use super::*;
    use crate::session::{
        broker::Broker,
        testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner},
    };
    use crate::ssh::{
        fake::{default_server_key, FakeEngine, FakeEvent},
        AuthMethod,
    };
    use crate::sync::testkit::MemKeychain;
    use std::os::unix::net::UnixStream;
    fn broker() -> (Arc<Broker>, Arc<FakeEngine>) {
        let engine = Arc::new(FakeEngine::new());
        let broker = Broker::new(
            engine.clone(),
            Arc::new(
                FakeDirectory::new()
                    .with_host(
                        "web",
                        AuthMethod::Key {
                            key_id: "k-plain".into(),
                        },
                    )
                    .with_pin("web", default_server_key()),
            ),
            Arc::new(FakeKeys::new()),
            Arc::new(MemKeychain::default()),
            Arc::new(FakeConfirmer::default()),
        );
        (broker, engine)
    }
    fn wait(predicate: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(3);
        while !predicate() {
            assert!(Instant::now() < end);
            thread::sleep(Duration::from_millis(2));
        }
    }
    #[test]
    fn protocol_two_reaches_exec_with_os_context_and_protocol_one_mcp_is_refused() {
        let (broker, engine) = broker();
        let runtime = Arc::new(McpRuntime::default());
        {
            let mut p = runtime.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("id-web".into());
        }
        broker.set_mcp_handler(Arc::new(move |connector, _, _, context, cancel| {
            assert_eq!(context.requested_by, ["Unknown"]);
            assert_eq!(context.requester_id, None);
            assert_eq!(context.client_info.name.as_deref(), Some("self reported"));
            records::execute_context(
                &runtime,
                connector,
                "id-web",
                "uptime",
                60,
                cancel,
                &FakeOwner::default(),
                &|_| ApprovalDecision::Allow,
                context,
            )
        }));
        let (a, b) = UnixStream::pair().unwrap();
        let serving = broker.clone();
        let worker = thread::spawn(move || serving.serve(b, None));
        let value = ipc_on(
            a,
            "ssh_exec",
            json!({"pid":42}),
            &McpClientInfo {
                name: Some("self reported".into()),
                ..Default::default()
            },
            &Call::default(),
        )
        .unwrap();
        assert_eq!(value["ended"], "exited");
        worker.join().unwrap();
        assert!(engine
            .events()
            .iter()
            .any(|e| matches!(e, FakeEvent::Exec { .. })));
        for version in [1, 3, 99] {
            let (mut a, b) = UnixStream::pair().unwrap();
            let serving = broker.clone();
            let worker = thread::spawn(move || serving.serve(b, None));
            write_control(
                &mut a,
                &ClientMessage::Hello {
                    client: ClientKind::Mcp,
                    version,
                    client_info: None,
                },
            )
            .unwrap();
            let Some(Frame::Control(payload)) = read_frame(&mut a).unwrap() else {
                panic!()
            };
            assert!(matches!(
                decode::<ServerMessage>(&payload).unwrap(),
                ServerMessage::Event(Event::Error { .. })
            ));
            worker.join().unwrap();
        }
    }
    #[test]
    fn eof_and_quit_cancel_waiting_requests_and_drain_broker_table() {
        for quit in [false, true] {
            let (broker, _) = broker();
            let entered = Arc::new(AtomicBool::new(false));
            let observed = entered.clone();
            broker.set_mcp_handler(Arc::new(move |_, _, _, _, cancel| {
                observed.store(true, Ordering::SeqCst);
                while !cancel.is_cancelled() {
                    thread::sleep(Duration::from_millis(2));
                }
                Err("canceled".into())
            }));
            let (mut a, b) = UnixStream::pair().unwrap();
            let serving = broker.clone();
            let worker = thread::spawn(move || serving.serve(b, None));
            write_control(
                &mut a,
                &ClientMessage::Hello {
                    client: ClientKind::Mcp,
                    version: crate::session::protocol::MCP_PROTOCOL_VERSION,
                    client_info: None,
                },
            )
            .unwrap();
            write_control(
                &mut a,
                &McpClientMessage::McpCall {
                    method: "ssh_exec".into(),
                    params: json!({}),
                },
            )
            .unwrap();
            wait(|| entered.load(Ordering::SeqCst));
            assert!(broker.has_sessions());
            if quit {
                broker.end_all(Duration::from_secs(2));
            } else {
                close(&a);
            }
            worker.join().unwrap();
            assert!(!broker.has_sessions());
        }
    }
}
