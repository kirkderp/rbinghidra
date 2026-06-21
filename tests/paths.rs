#[path = "support/tempfile.rs"]
mod tempfile;

use std::path::PathBuf;

use rbinghidra::CachePaths;

#[test]
fn derives_ghidra_cache_path() {
    let root = PathBuf::from("/tmp/rogue-cache-test");
    let paths = CachePaths::new(&root);

    assert_eq!(paths.root(), root.as_path());
    assert_eq!(paths.ghidra_dir(), root.join("ghidra"));
}

#[test]
fn ensure_all_creates_ghidra_directory() {
    let dir = tempfile::TempDir::new().unwrap();
    let paths = CachePaths::new(dir.path().join("cache"));
    paths.ensure_all().unwrap();

    assert!(paths.ghidra_dir().is_dir());
}
