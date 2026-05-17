use std::path::PathBuf;

use rbm_core::CachePaths;

#[test]
fn derives_overflow_and_ghidra_subpaths() {
    let root = PathBuf::from("/tmp/rogue-cache-test");
    let paths = CachePaths::new(&root);

    assert_eq!(paths.root(), root.as_path());
    assert_eq!(paths.overflow_dir(), root.join("overflow"));
    assert_eq!(paths.ghidra_dir(), root.join("ghidra"));
    assert_eq!(
        paths.ghidra_project_dir("abc123"),
        root.join("ghidra").join("abc123")
    );
    assert_eq!(paths.r2_sessions_dir(), root.join("r2_sessions"));
    assert_eq!(paths.tmp_dir(), root.join("tmp"));
}

#[test]
fn ensure_all_creates_every_subdirectory() {
    let dir = tempfile::tempdir().unwrap();
    let paths = CachePaths::new(dir.path().join("cache"));
    paths.ensure_all().unwrap();

    assert!(paths.overflow_dir().is_dir());
    assert!(paths.ghidra_dir().is_dir());
    assert!(paths.r2_sessions_dir().is_dir());
    assert!(paths.tmp_dir().is_dir());
}
