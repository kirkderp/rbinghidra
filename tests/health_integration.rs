#![cfg(feature = "integration-ghidra")]

use rbinghidra::health::probe;

#[test]
#[ignore = "requires real Ghidra/analyzeHeadless; run explicitly with --ignored"]
fn probe_returns_available_against_real_ghidra_install() {
    let health = probe();
    assert!(
        health.available,
        "GHIDRA_INSTALL_DIR must point at a real Ghidra install for the integration test. \
         got: {health:?}"
    );
    assert!(health.version.is_some(), "version should be populated");
    assert!(
        health.analyze_headless_path.is_some(),
        "analyze_headless_path should be populated",
    );
    assert_eq!(health.error, None);
}
