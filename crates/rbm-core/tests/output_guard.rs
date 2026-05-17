use std::fs;
use std::thread;
use std::time::{Duration, SystemTime};

use rbm_core::output_guard::{GuardedOutput, OVERFLOW_PREFIX, OutputGuard};

use tempfile::tempdir;

fn filetime(path: &std::path::Path) -> SystemTime {
    fs::metadata(path).unwrap().modified().unwrap()
}

#[test]
fn inline_passthrough_under_limit() {
    let dir = tempdir().unwrap();
    let guard = OutputGuard::new(dir.path()).with_max_inline_chars(100);

    let result = guard.guard_str("unit", "a short reply").unwrap();
    match result {
        GuardedOutput::Inline(s) => assert_eq!(s, "a short reply"),
        GuardedOutput::Overflow(_) => panic!("expected inline"),
    }
    assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[test]
fn overflow_writes_file_with_preview_and_summary() {
    let dir = tempdir().unwrap();
    let guard = OutputGuard::new(dir.path()).with_max_inline_chars(10);
    let payload = "x".repeat(1_000);

    let result = guard.guard_str("ghidra_decompile", &payload).unwrap();
    let summary = match result {
        GuardedOutput::Overflow(s) => s,
        GuardedOutput::Inline(_) => panic!("expected overflow"),
    };

    assert!(summary.overflow);
    assert_eq!(summary.total_chars, 1_000);
    assert!(summary.preview.len() <= 2_000);
    assert!(summary.preview.chars().all(|c| c == 'x'));
    assert!(summary.file_path.exists());

    let stem = summary
        .file_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap();
    assert!(stem.starts_with(OVERFLOW_PREFIX));
    assert!(stem.contains("ghidra_decompile"));

    let disk = fs::read_to_string(&summary.file_path).unwrap();
    assert_eq!(disk.len(), 1_000);
}

#[test]
fn overflow_message_uses_thousands_separator() {
    let dir = tempdir().unwrap();
    let guard = OutputGuard::new(dir.path()).with_max_inline_chars(10);
    let payload = "y".repeat(1_234_567);

    let result = guard.guard_str("big", &payload).unwrap();
    let summary = match result {
        GuardedOutput::Overflow(s) => s,
        GuardedOutput::Inline(_) => panic!("expected overflow"),
    };

    assert_eq!(summary.total_chars, 1_234_567);
    assert!(
        summary.message.contains("1,234,567 chars"),
        "message should include grouped number, got: {}",
        summary.message
    );
}

#[test]
fn threshold_exactly_at_limit_stays_inline() {
    let dir = tempdir().unwrap();
    let guard = OutputGuard::new(dir.path()).with_max_inline_chars(200_000);
    let payload = "a".repeat(200_000);
    let result = guard.guard_str("boundary", &payload).unwrap();
    assert!(matches!(result, GuardedOutput::Inline(_)));
}

#[test]
fn threshold_one_over_limit_overflows() {
    let dir = tempdir().unwrap();
    let guard = OutputGuard::new(dir.path()).with_max_inline_chars(200_000);
    let payload = "a".repeat(200_001);
    let result = guard.guard_str("boundary", &payload).unwrap();
    assert!(matches!(result, GuardedOutput::Overflow(_)));
}

#[test]
fn ttl_sweep_removes_stale_mcp_prefixed_files_only() {
    let dir = tempdir().unwrap();
    let guard = OutputGuard::new(dir.path())
        .with_max_inline_chars(4)
        .with_ttl(Duration::from_millis(50));

    let overflow = guard.guard_str("first", "aaaaaaaaaa").unwrap();
    let stale_path = match overflow {
        GuardedOutput::Overflow(s) => s.file_path,
        GuardedOutput::Inline(_) => panic!("expected overflow"),
    };

    let bystander = dir.path().join("keep_me.txt");
    fs::write(&bystander, "not managed by us").unwrap();

    let filetime_stale = filetime(&stale_path);
    let filetime_bystander = filetime(&bystander);

    thread::sleep(Duration::from_millis(120));

    let fresh = guard.guard_str("second", "bbbbbbbbbb").unwrap();
    let fresh_path = match fresh {
        GuardedOutput::Overflow(s) => s.file_path,
        GuardedOutput::Inline(_) => panic!("expected overflow"),
    };

    assert!(!stale_path.exists(), "stale mcp_ file should be swept");
    assert!(fresh_path.exists(), "fresh overflow file should survive");
    assert!(bystander.exists(), "non-mcp_ file must be left alone");

    let _ = (filetime_stale, filetime_bystander);
}

#[test]
fn guard_json_serializes_and_overflows_large_values() {
    let dir = tempdir().unwrap();
    let guard = OutputGuard::new(dir.path()).with_max_inline_chars(50);

    let value: Vec<String> = (0..100).map(|i| format!("entry-{i:05}")).collect();
    let result = guard.guard_json("list", &value).unwrap();
    match result {
        GuardedOutput::Overflow(summary) => {
            let disk = fs::read_to_string(&summary.file_path).unwrap();
            let parsed: Vec<String> = serde_json::from_str(&disk).unwrap();
            assert_eq!(parsed.len(), 100);
        }
        GuardedOutput::Inline(_) => panic!("expected overflow for 100 entries"),
    }
}

#[test]
fn inline_serializes_as_bare_json_string() {
    let dir = tempdir().unwrap();
    let guard = OutputGuard::new(dir.path()).with_max_inline_chars(100);
    let result = guard.guard_str("ghidra_read_bytes", "0x401000").unwrap();
    let json = serde_json::to_string(&result).unwrap();
    assert_eq!(
        json, "\"0x401000\"",
        "Inline variant must serialize as a bare JSON string for the tool boundary"
    );
}

#[test]
fn overflow_serializes_as_object_with_overflow_flag() {
    let dir = tempdir().unwrap();
    let guard = OutputGuard::new(dir.path()).with_max_inline_chars(4);
    let result = guard.guard_str("ghidra_read_bytes", "abcdefghij").unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = value
        .as_object()
        .expect("Overflow variant must serialize as a JSON object");
    assert_eq!(obj.get("overflow"), Some(&serde_json::Value::Bool(true)));
    assert!(obj.contains_key("message"));
    assert!(obj.contains_key("file_path"));
    assert!(obj.contains_key("preview"));
    assert!(obj.contains_key("total_chars"));
}
