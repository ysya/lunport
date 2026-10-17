#[cfg(test)]
mod fixtures {
    use crate::sync::{record::LocalRecord, records_v3::*};
    use serde_json::json;
    pub(super) fn state() -> SyncStateV3 {
        serde_json::from_value(json!({"version":4,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture","relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null,"local":{"groups":{
            "group:0000000000000001": row("0000000000000001", json!({"schema":1,"name":"Parent","parent_id":null,"defaults":{"user":"ops","port":22,"keepalive_secs":60}})),
            "group:0000000000000002": row("0000000000000002", json!({"schema":1,"name":"Child","parent_id":"0000000000000001","defaults":{"port":2222}}))
        }}})).unwrap()
    }
    fn row(id: &str, payload: serde_json::Value) -> serde_json::Value {
        json!({"record":{"kind":"group","id":id,"version":1,"updated_at_ms":1,"device_id":"dddddddddddddddddddddddddddddddd","deleted":false,"payload":payload},"seq":0,"dirty":false})
    }
    pub(super) fn host() -> HostRecord {
        serde_json::from_value(json!({"id":"0000000000000010","scope":{"kind":"local"},"payload":{"schema":3,"alias":"web","hostname":"example.test","port":2200,"user":"raw","auth":"password","keepalive_secs":10,"group_id":"0000000000000002","inherit":["user","port"]}})).unwrap()
    }
    #[test]
    fn group_nested_effective_values_and_provenance_preserve_raw() {
        let state = state();
        let host = host();
        let resolved = crate::sync::record_groups::resolve_effective(&state, &host).unwrap();
        assert_eq!(resolved.payload.user, "ops");
        assert_eq!(resolved.payload.port, 2222);
        assert_eq!(resolved.payload.keepalive_secs, 10);
        assert_eq!(resolved.inherited_from["user"], "0000000000000001");
        assert_eq!(resolved.inherited_from["port"], "0000000000000002");
        assert_eq!(host.payload.user, "raw");
        assert_eq!(host.payload.port, 2200);
    }
    #[test]
    fn group_missing_parent_cycle_and_cross_scope_fail_closed() {
        let mut state = state();
        let host = host();
        state.local.groups.remove("group:0000000000000001");
        assert!(crate::sync::record_groups::resolve_effective(&state, &host).is_err());
        let cycle: LocalRecord = serde_json::from_value(row(
            "0000000000000001",
            json!({"schema":1,"name":"Cycle","parent_id":"0000000000000002","defaults":{}}),
        ))
        .unwrap();
        state
            .local
            .groups
            .insert("group:0000000000000001".into(), cycle);
        assert!(crate::sync::record_groups::resolve_effective(&state, &host).is_err());
        let mut other = host;
        other.scope = HostScope::Space {
            space_id: "a".repeat(64),
        };
        assert!(crate::sync::record_groups::resolve_effective(&state, &other).is_err());
    }
}

#[cfg(test)]
mod behavior_tests {
    use super::fixtures as tests;
    use crate::sync::record_groups::*;
    use serde_json::json;
    fn host_state() -> SyncStateV3 {
        let mut s = tests::state();
        let host = tests::host();
        let record = repo::ordered_record(
            &s,
            &host.id,
            serde_json::to_value(host.payload).unwrap(),
            false,
            2,
            &[],
        )
        .unwrap();
        s.local.hosts.insert(
            record_key(RecordKind::Host, &host.id),
            repo::cached(record, 0, &HostScope::Local),
        );
        s
    }
    fn pin() -> StoredHostKey {
        let p = ssh_key::PublicKey::from_openssh(crate::sync::slot_rules::test_keys::PLAIN_PUBLIC)
            .unwrap();
        StoredHostKey {
            algorithm: p.algorithm().as_str().into(),
            public_key: crate::sync::slot_rules::test_keys::PLAIN_PUBLIC
                .split_whitespace()
                .nth(1)
                .unwrap()
                .into(),
            fingerprint: p.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            pinned_at_ms: 1,
            pinned_by_device_id: "d".repeat(32),
        }
    }
    #[test]
    fn group_crud_confirmation_stale_revision_duplicates_and_route_validation() {
        let mut s = tests::state();
        s.version = 3;
        s.local.groups.clear();
        let payload: GroupPayload =
            serde_json::from_value(json!({"schema":1,"name":"Team","defaults":{}})).unwrap();
        assert_eq!(
            create_group(
                &s,
                "0000000000000001",
                HostScope::Local,
                payload.clone(),
                false,
                1
            )
            .unwrap_err(),
            RepositoryError::UpgradeConfirmationRequired
        );
        let s = create_group(
            &s,
            "0000000000000001",
            HostScope::Local,
            payload.clone(),
            true,
            1,
        )
        .unwrap();
        assert_eq!(s.version, 4);
        assert!(create_group(&s, "0000000000000002", HostScope::Local, payload, false, 2).is_err());
        let g = list_groups(&s).unwrap().remove(0);
        let mut p = g.group.payload.clone();
        p.name = "Changed".into();
        let next = update_group(&s, &g.group.id, &g.revision, p.clone(), 2).unwrap();
        assert!(update_group(&next, &g.group.id, &g.revision, p, 3).is_err());
        let mut s = host_state();
        s.local
            .hosts
            .get_mut("host:0000000000000010")
            .unwrap()
            .record
            .payload["inherit"] = json!(["jump"]);
        let g = list_groups(&s)
            .unwrap()
            .into_iter()
            .find(|g| g.group.id == "0000000000000002")
            .unwrap();
        let mut p = g.group.payload;
        p.defaults.jump = Some(vec!["0000000000000099".into()]);
        assert!(update_group(&s, &g.group.id, &g.revision, p, 3).is_err());
    }
    #[test]
    fn group_port_change_clears_only_descendant_pin_and_old_endpoint_cas_fails() {
        let mut s = host_state();
        s.local
            .groups
            .get_mut("group:0000000000000002")
            .unwrap()
            .record
            .payload["defaults"] = json!({});
        let host = repo::get_host(&s, "0000000000000010").unwrap();
        let endpoint = repo::HostEndpoint {
            hostname: "example.test".into(),
            port: 22,
        };
        let s = repo::pin_host_key(&s, &host.host.id, &endpoint, None, pin(), 5).unwrap();
        let other = materialize(&host.host.payload);
        let mut other = other;
        other.alias = "other".into();
        let s = repo::create_host(&s, "0000000000000020", HostScope::Local, other, 6).unwrap();
        let s = repo::pin_host_key(
            &s,
            "0000000000000020",
            &repo::HostEndpoint {
                hostname: "example.test".into(),
                port: 2200,
            },
            None,
            pin(),
            7,
        )
        .unwrap();
        let g = list_groups(&s)
            .unwrap()
            .into_iter()
            .find(|g| g.group.id == "0000000000000001")
            .unwrap();
        let mut p = g.group.payload;
        p.defaults.port = Some(2222);
        let next = update_group(&s, &g.group.id, &g.revision, p, 8).unwrap();
        assert!(repo::get_host(&next, &host.host.id)
            .unwrap()
            .host
            .payload
            .host_key
            .is_none());
        assert!(repo::get_host(&next, "0000000000000020")
            .unwrap()
            .host
            .payload
            .host_key
            .is_some());
        assert_eq!(
            repo::pin_host_key(&next, &host.host.id, &endpoint, None, pin(), 9).unwrap_err(),
            RepositoryError::EndpointChanged(host.host.id)
        );
    }
    #[test]
    fn group_delete_rejects_changed_descendants_after_review() {
        let reviewed = host_state();
        let root = list_groups(&reviewed).unwrap().remove(0);
        let mut changed = reviewed.clone();
        let child = changed
            .local
            .groups
            .get_mut("group:0000000000000002")
            .unwrap();
        child.record.version += 1;
        child.record.payload["defaults"]["port"] = json!(2223);
        let before = changed.clone();
        let token = deletion_snapshot_token(&repo::snapshot(&reviewed).unwrap()).unwrap();
        let result = delete_group(&changed, &root.group.id, &root.revision, Some(&token), 9);
        assert!(
            result.is_err(),
            "an unchanged root revision must not approve changed descendants"
        );
        assert_eq!(changed, before, "rejection must not partially edit state");
    }
    #[test]
    fn group_delete_review_binds_every_materialization_dependency_and_rejects_atomically() {
        for change in [
            "root_revision",
            "new_descendant",
            "moved_in_descendant",
            "updated_descendant",
            "moved_out_descendant",
            "host_join",
            "host_leave",
            "host_settings",
            "outside_ancestor",
        ] {
            let mut reviewed = host_state();
            let mut outsider = reviewed.local.groups["group:0000000000000002"].clone();
            outsider.record.id = "0000000000000003".into();
            outsider.record.payload["name"] = json!("Outside");
            outsider.record.payload["parent_id"] = json!(null);
            reviewed
                .local
                .groups
                .insert("group:0000000000000003".into(), outsider);
            let mut outsider_host = reviewed.local.hosts["host:0000000000000010"].clone();
            outsider_host.record.id = "0000000000000011".into();
            outsider_host.record.payload["alias"] = json!("outside-host");
            outsider_host.record.payload["group_id"] = json!(null);
            outsider_host.record.payload["inherit"] = json!([]);
            reviewed
                .local
                .hosts
                .insert("host:0000000000000011".into(), outsider_host);
            let root_id = if change == "outside_ancestor" {
                "0000000000000002"
            } else {
                "0000000000000001"
            };
            let root = list_groups(&reviewed)
                .unwrap()
                .into_iter()
                .find(|g| g.group.id == root_id)
                .unwrap();
            // Exercise the actual overview producer used by the UI, not a test-only token.
            let overview = serde_json::to_value(
                crate::sync::record_commands::overview_from(&reviewed, 7, None).unwrap(),
            )
            .unwrap();
            let token = overview["group_deletion_token"].as_str().unwrap();
            let mut changed = reviewed.clone();
            match change {
                "root_revision" => {
                    changed
                        .local
                        .groups
                        .get_mut("group:0000000000000001")
                        .unwrap()
                        .record
                        .version += 1
                }
                "new_descendant" => {
                    let mut row = changed.local.groups["group:0000000000000002"].clone();
                    row.record.id = "0000000000000004".into();
                    row.record.payload["name"] = json!("New child");
                    changed
                        .local
                        .groups
                        .insert("group:0000000000000004".into(), row);
                }
                "moved_in_descendant" => {
                    changed
                        .local
                        .groups
                        .get_mut("group:0000000000000003")
                        .unwrap()
                        .record
                        .payload["parent_id"] = json!(root_id)
                }
                "updated_descendant" => {
                    changed
                        .local
                        .groups
                        .get_mut("group:0000000000000002")
                        .unwrap()
                        .record
                        .payload["defaults"]["user"] = json!("new-user")
                }
                "moved_out_descendant" => {
                    changed
                        .local
                        .groups
                        .get_mut("group:0000000000000002")
                        .unwrap()
                        .record
                        .payload["parent_id"] = json!(null)
                }
                "host_join" => {
                    changed
                        .local
                        .hosts
                        .get_mut("host:0000000000000011")
                        .unwrap()
                        .record
                        .payload["group_id"] = json!("0000000000000002")
                }
                "host_leave" => {
                    changed
                        .local
                        .hosts
                        .get_mut("host:0000000000000010")
                        .unwrap()
                        .record
                        .payload["group_id"] = json!(null)
                }
                "host_settings" => {
                    changed
                        .local
                        .hosts
                        .get_mut("host:0000000000000010")
                        .unwrap()
                        .record
                        .payload["keepalive_secs"] = json!(99)
                }
                "outside_ancestor" => {
                    changed
                        .local
                        .groups
                        .get_mut("group:0000000000000001")
                        .unwrap()
                        .record
                        .payload["defaults"]["user"] = json!("ancestor-updated")
                }
                _ => unreachable!(),
            }
            let before = changed.clone();
            let result = delete_group(&changed, root_id, &root.revision, Some(token), 9);
            assert!(result.is_err(), "stale review accepted: {change}");
            assert_eq!(changed, before, "partial edit on rejection: {change}");
            assert!(changed.local.groups.values().all(|g| !g.record.deleted));
            if change != "root_revision" {
                assert_eq!(
                    list_groups(&changed)
                        .unwrap()
                        .into_iter()
                        .find(|g| g.group.id == root_id)
                        .unwrap()
                        .revision,
                    root.revision
                );
            }
            let snapshot = repo::snapshot(&changed).unwrap();
            let fresh_token = deletion_snapshot_token(&snapshot).unwrap();
            let current_root = snapshot
                .groups
                .iter()
                .find(|g| g.group.id == root_id)
                .unwrap();
            let next = delete_group(
                &changed,
                root_id,
                &current_root.revision,
                Some(&fresh_token),
                10,
            )
            .unwrap();
            assert!(
                next.local.groups[&format!("group:{root_id}")]
                    .record
                    .deleted
            );
            for before in snapshot.hosts {
                let after = repo::get_host(&next, &before.host.id).unwrap();
                assert_eq!(
                    materialize(&after.effective_payload),
                    materialize(&before.effective_payload),
                    "effective host values changed after fresh review: {change}"
                );
                let affected = ancestor_path(
                    &changed,
                    &before.host.scope,
                    before.host.payload.group_id.as_deref(),
                )
                .unwrap()
                .iter()
                .any(|group| group.id == root_id);
                if affected {
                    assert!(
                        after.host.payload.group_id.is_none(),
                        "membership retained: {change}"
                    );
                    assert!(
                        after.host.payload.inherit.is_empty(),
                        "inheritance retained: {change}"
                    );
                } else {
                    assert_eq!(
                        after.host.payload, before.host.payload,
                        "unaffected host changed: {change}"
                    );
                }
            }
        }
    }

    #[test]
    fn group_delete_missing_review_fails_closed_and_sync_bookkeeping_does_not_expire_review() {
        let s = host_state();
        let root = list_groups(&s).unwrap().remove(0);
        assert!(delete_group(&s, &root.group.id, &root.revision, None, 9)
            .unwrap_err()
            .to_string()
            .contains("review"));
        assert!(delete_group(&s, &root.group.id, &root.revision, Some(""), 9).is_err());
        let token = deletion_snapshot_token(&repo::snapshot(&s).unwrap()).unwrap();
        let mut refreshed = s.clone();
        refreshed.last_sync_ms = Some(99);
        assert!(delete_group(&refreshed, &root.group.id, &root.revision, Some(&token), 10).is_ok());
    }
    #[test]
    fn group_delete_materializes_subtree_without_changing_host_or_credentials() {
        let mut s = host_state();
        s.local
            .groups
            .get_mut("group:0000000000000001")
            .unwrap()
            .record
            .payload["defaults"]["authentication"] =
            json!({"auth":"key","key_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});
        s.local
            .hosts
            .get_mut("host:0000000000000010")
            .unwrap()
            .record
            .payload["inherit"] = json!(["user", "port", "authentication"]);
        let g = list_groups(&s).unwrap().remove(0);
        let token = deletion_snapshot_token(&repo::snapshot(&s).unwrap()).unwrap();
        let next = delete_group(&s, &g.group.id, &g.revision, Some(&token), 9).unwrap();
        let h = repo::get_host(&next, "0000000000000010").unwrap();
        assert_eq!(h.host.payload.user, "ops");
        assert_eq!(h.host.payload.port, 2222);
        assert_eq!(h.host.payload.keepalive_secs, 10);
        assert_eq!(h.host.payload.key_id, Some("a".repeat(32)));
        assert_eq!(h.host.payload.auth, AuthKind::Key);
        assert!(h.host.payload.group_id.is_none());
        assert!(h.host.payload.inherit.is_empty());
        assert_eq!(
            next.local
                .groups
                .values()
                .filter(|g| g.record.deleted)
                .count(),
            2
        );
    }
    #[test]
    fn group_authentication_is_atomic_and_app_fallback_has_no_raw_key() {
        let mut s = host_state();
        let row = s.local.hosts.get_mut("host:0000000000000010").unwrap();
        row.record.payload["auth"] = json!("key");
        row.record.payload["key_id"] = json!("a".repeat(32));
        row.record.payload["inherit"] = json!(["authentication"]);
        let h = repo::get_host(&s, "0000000000000010").unwrap();
        assert_eq!(h.effective_payload.auth, AuthKind::Password);
        assert_eq!(h.effective_payload.key_id, None);
        assert_eq!(h.inherited_from["authentication"], "default");
        let invalid:GroupPayload=serde_json::from_value(json!({"schema":1,"name":"invalid","defaults":{"authentication":{"auth":"password","key_id":"a".repeat(32)}}})).unwrap();
        assert!(create_group(&s, "0000000000000009", HostScope::Local, invalid, true, 5).is_err());
    }
    #[test]
    fn group_format_backup_preserves_source_and_future_state_is_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.json");
        let mut s = tests::state();
        s.version = 3;
        s.local.groups.clear();
        crate::sync::record_runtime::save_active(&path, &s).unwrap();
        let original = std::fs::read(&path).unwrap();
        let g = tests::state();
        crate::sync::record_runtime::save_active(&path, &g).unwrap();
        let files = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|f| f.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().contains("backup"))
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 1);
        assert_eq!(std::fs::read(&files[0]).unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(decode_state(&String::from_utf8(original).unwrap()).is_ok());
        let mut future = serde_json::to_value(g).unwrap();
        future["version"] = json!(NAVIGATION_STATE_VERSION + 1);
        assert!(decode_state(&future.to_string()).is_err());
        let raw = serde_json::to_value(materialize(&tests::host().payload)).unwrap();
        assert!(raw.get("group_id").is_none());
        assert!(raw.get("inherit").is_none());
    }
    #[test]
    fn group_move_to_schema_three_account_materializes_schema_two() {
        let mut s = host_state();
        let sid = "a".repeat(64);
        s.account = Some(crate::sync::state_v2::AccountState::new(&"b".repeat(64)));
        s.spaces.insert(
            sid.clone(),
            SpaceStateV3 {
                selected: true,
                ..Default::default()
            },
        );
        let h = repo::get_host(&s, "0000000000000010").unwrap();
        let next = repo::move_host(
            &s,
            &h.host.id,
            &h.revision,
            HostScope::Space { space_id: sid },
            8,
        )
        .unwrap();
        let moved = repo::get_host(&next, &h.host.id).unwrap();
        assert_eq!(moved.host.payload.schema, 2);
        assert_eq!(moved.host.payload.user, "ops");
        assert_eq!(moved.host.payload.port, 2222);
        assert!(moved.host.payload.group_id.is_none());
        assert!(moved.host.payload.inherit.is_empty());
    }
    #[test]
    fn ungrouped_host_app_defaults_require_confirmed_promotion_and_source_backup() {
        let mut original = tests::state();
        original.local.groups.clear();
        original.version = 3;
        let mut payload = tests::host().payload;
        payload.group_id = None;
        payload.inherit = vec![
            InheritedField::Port,
            InheritedField::User,
            InheritedField::Authentication,
            InheritedField::Jump,
            InheritedField::KeepaliveSecs,
            InheritedField::KeepaliveMaxMissed,
            InheritedField::ConnectTimeoutSecs,
        ];
        let before = original.clone();
        assert_eq!(
            promote_for_host(&original, &HostScope::Local, &payload, false, 10).unwrap_err(),
            RepositoryError::UpgradeConfirmationRequired
        );
        assert_eq!(original, before);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.json");
        crate::sync::record_runtime::save_active(&path, &original).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let promoted = promote_for_host(&original, &HostScope::Local, &payload, true, 10).unwrap();
        let next = repo::create_host(&promoted, "0000000000000010", HostScope::Local, payload, 11)
            .unwrap();
        crate::sync::record_runtime::save_active(&path, &next).unwrap();
        assert_eq!(next.version, 4);
        let host = repo::get_host(&next, "0000000000000010").unwrap();
        assert_eq!(host.effective_payload.port, 22);
        assert_eq!(host.effective_payload.user, "");
        assert_eq!(host.effective_payload.auth, AuthKind::Password);
        assert_eq!(host.effective_payload.key_id, None);
        assert!(host.effective_payload.jump.is_empty());
        assert_eq!(host.effective_payload.keepalive_secs, 30);
        assert_eq!(host.effective_payload.keepalive_max_missed, 3);
        assert_eq!(host.effective_payload.connect_timeout_secs, 15);
        assert!(host
            .inherited_from
            .values()
            .all(|source| source == "default"));
        assert_eq!(host.inherited_from.len(), 7);
        let backup = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.file_name().unwrap().to_string_lossy().contains("backup"))
            .unwrap();
        assert_eq!(std::fs::read(backup).unwrap(), bytes);
    }
}
