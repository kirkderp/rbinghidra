use rbm_ghidra::delete::{DeleteError, DeleteReport, delete_cached_binary};
use rbm_ghidra::inspect::InspectError;

mod common;
use common::{make_manager, make_runtime, write_envelope};

const SHA_LS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA_CAT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SHA_DUP: &str = "3333333333333333333333333333333333333333333333333333333333333333";

#[test]
fn delete_cached_binary_happy_path_removes_dir_and_evicts_lock() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 7);
        let project_dir = mgr.project_dir(SHA_LS);
        assert!(project_dir.exists());
        assert_eq!(mgr.lock_count(), 0);

        let report = delete_cached_binary(&mgr, "ls").await.unwrap();
        assert_eq!(report.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(report.sha256, SHA_LS);
        assert_eq!(report.program_name, "ls");
        assert!(report.deleted, "happy path should report deleted = true");
        assert!(!project_dir.exists(), "project_dir should be gone");
        assert_eq!(
            mgr.lock_count(),
            0,
            "lock map entry should be evicted after a successful delete"
        );
    });
}

#[test]
fn delete_cached_binary_is_idempotent_second_call_returns_not_found() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);

        let first = delete_cached_binary(&mgr, "ls").await.unwrap();
        assert!(first.deleted);
        assert!(!mgr.project_dir(SHA_LS).exists());

        let err = delete_cached_binary(&mgr, "ls").await.unwrap_err();
        assert!(
            matches!(err, DeleteError::Inspect(InspectError::NotFound(_))),
            "second delete should NotFound, got {err:?}"
        );
        assert_eq!(
            mgr.lock_count(),
            0,
            "no zombie lock entries should remain after the no-op second call"
        );
    });
}

#[test]
fn delete_cached_binary_lookup_by_cache_key_works() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 7);
        let report = delete_cached_binary(&mgr, &format!("sha256:{SHA_LS}"))
            .await
            .unwrap();
        assert_eq!(report.sha256, SHA_LS);
        assert!(!mgr.project_dir(SHA_LS).exists());
    });
}

#[test]
fn delete_cached_binary_lookup_by_raw_sha256_works() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 7);
        let report = delete_cached_binary(&mgr, SHA_LS).await.unwrap();
        assert_eq!(report.cache_key, format!("sha256:{SHA_LS}"));
        assert!(!mgr.project_dir(SHA_LS).exists());
    });
}

#[test]
fn delete_cached_binary_lookup_by_sha256_removes_incomplete_project() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        let project_dir = mgr.project_dir(SHA_LS);
        tokio::fs::create_dir_all(&project_dir).await.unwrap();

        let report = delete_cached_binary(&mgr, &format!("sha256:{SHA_LS}"))
            .await
            .unwrap();
        assert_eq!(report.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(report.sha256, SHA_LS);
        assert_eq!(report.program_name, "");
        assert!(report.deleted);
        assert!(!project_dir.exists());
        assert_eq!(mgr.lock_count(), 0);
    });
}

#[test]
fn delete_cached_binary_lookup_by_sha256_is_idempotent_for_missing_project() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();

        let report = delete_cached_binary(&mgr, SHA_LS).await.unwrap();
        assert_eq!(report.cache_key, format!("sha256:{SHA_LS}"));
        assert_eq!(report.sha256, SHA_LS);
        assert_eq!(report.program_name, "");
        assert!(!report.deleted);
        assert_eq!(mgr.lock_count(), 0);
    });
}

#[test]
fn delete_cached_binary_lookup_by_program_name_works() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_CAT, "cat", 1);
        let report = delete_cached_binary(&mgr, "cat").await.unwrap();
        assert_eq!(report.sha256, SHA_CAT);
        assert!(!mgr.project_dir(SHA_CAT).exists());
        assert!(
            mgr.project_dir(SHA_LS).exists(),
            "unrelated cache entry must be untouched"
        );
    });
}

#[test]
fn delete_cached_binary_returns_inspect_not_found_for_unknown_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        let err = delete_cached_binary(&mgr, "nope").await.unwrap_err();
        assert!(
            matches!(err, DeleteError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn delete_cached_binary_returns_inspect_not_found_for_empty_query() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        let err = delete_cached_binary(&mgr, "").await.unwrap_err();
        assert!(
            matches!(err, DeleteError::Inspect(InspectError::NotFound(_))),
            "{err:?}"
        );
    });
}

#[test]
fn delete_cached_binary_propagates_ambiguous_program_name() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 1);
        write_envelope(&mgr, SHA_DUP, "ls", 1);
        let err = delete_cached_binary(&mgr, "ls").await.unwrap_err();
        match err {
            DeleteError::Inspect(InspectError::Ambiguous { matches, .. }) => {
                assert_eq!(matches, 2);
            }
            other => panic!("expected Inspect(Ambiguous), got {other:?}"),
        }
        assert!(
            mgr.project_dir(SHA_LS).exists() && mgr.project_dir(SHA_DUP).exists(),
            "ambiguous lookup must not delete anything"
        );
    });
}

#[test]
fn delete_cached_binary_refuses_when_lock_is_held() {
    let rt = make_runtime();
    rt.block_on(async {
        let (_tmp, mgr) = make_manager();
        write_envelope(&mgr, SHA_LS, "ls", 7);
        let lock = mgr.lock_for(SHA_LS);
        let _held = lock
            .clone()
            .try_lock_owned()
            .expect("test must hold the lock first");

        let err = delete_cached_binary(&mgr, "ls").await.unwrap_err();
        match err {
            DeleteError::LockHeld { sha256 } => assert_eq!(sha256, SHA_LS),
            other => panic!("expected LockHeld, got {other:?}"),
        }
        assert!(
            mgr.project_dir(SHA_LS).exists(),
            "lock-held refusal must not delete the dir"
        );
        assert_eq!(
            mgr.lock_count(),
            1,
            "the test-held lock entry must remain in the map"
        );
    });
}

#[test]
fn delete_cached_binary_lookup_form_parity_evicts_same_sha() {
    let rt = make_runtime();
    rt.block_on(async {
        for query_template in [
            "by-name".to_string(),
            format!("sha256:{SHA_LS}"),
            SHA_LS.to_string(),
            SHA_LS.to_ascii_uppercase(),
        ] {
            let (_tmp, mgr) = make_manager();
            write_envelope(&mgr, SHA_LS, "by-name", 1);
            let report = delete_cached_binary(&mgr, &query_template).await.unwrap();
            assert_eq!(report.sha256, SHA_LS, "query={query_template}");
            assert!(
                !mgr.project_dir(SHA_LS).exists(),
                "query={query_template} must remove the project_dir"
            );
            assert_eq!(
                mgr.lock_count(),
                0,
                "query={query_template} must evict the lock entry"
            );
        }
    });
}

#[test]
fn delete_report_serializes_to_stable_shape() {
    let report = DeleteReport {
        schema: "rbm.ghidra.delete.v0",
        cache_key: "sha256:abc".to_string(),
        sha256: "abc".to_string(),
        program_name: "ls".to_string(),
        project_dir: "/tmp/abc".to_string(),
        deleted: true,
    };
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema"], "rbm.ghidra.delete.v0");
    assert_eq!(json["cache_key"], "sha256:abc");
    assert_eq!(json["sha256"], "abc");
    assert_eq!(json["program_name"], "ls");
    assert_eq!(json["project_dir"], "/tmp/abc");
    assert_eq!(json["deleted"], true);
}

#[test]
fn release_lock_returns_false_when_entry_missing() {
    let (_tmp, mgr) = make_manager();
    assert!(!mgr.release_lock(SHA_LS));
}

#[test]
fn release_lock_evicts_existing_entry() {
    let (_tmp, mgr) = make_manager();
    let _ = mgr.lock_for(SHA_LS);
    assert_eq!(mgr.lock_count(), 1);
    assert!(mgr.release_lock(SHA_LS));
    assert_eq!(mgr.lock_count(), 0);
}
