#![cfg(feature = "integration-ghidra")]

use std::path::Path;
use std::time::Duration;

use rbm_ghidra::decompile_meta::{DECOMPILE_META_SCHEMA, DecompileMetaContext, get_decompile_meta};

mod common;

#[tokio::test]
#[ignore = "requires real Ghidra/analyzeHeadless; run explicitly with --ignored"]
async fn ghidra_decompile_meta_runs_against_real_binary() {
    let fixture = common::import_real_binary(Path::new("/bin/ls")).await;
    let target_name = common::first_real_function_name(&fixture.functions);

    let ctx = DecompileMetaContext {
        manager: fixture.manager.clone(),
        analyze_headless: fixture.analyze_headless.clone(),
        scripts_dir: fixture.scripts_dir.clone(),
        timeout: Duration::from_secs(180),
    };

    let result = get_decompile_meta(&ctx, &fixture.program_name, &target_name, None, 120)
        .await
        .unwrap_or_else(|e| panic!("decompile_meta {target_name}: {e:?}"));

    assert_eq!(result.schema, DECOMPILE_META_SCHEMA);
    assert_eq!(result.cache_key, format!("sha256:{}", fixture.sha));
    assert_eq!(result.sha256, fixture.sha);
    assert_eq!(result.program_name, fixture.program_name);
    assert_eq!(result.query, target_name);
    assert!(
        !result.function_name.is_empty(),
        "resolved function name should be populated"
    );
    assert!(
        !result.address.is_empty(),
        "resolved address should be populated"
    );
    assert_eq!(result.parameter_count as usize, result.parameters.len());
    assert_eq!(result.local_var_count as usize, result.local_vars.len());
    assert_eq!(result.token_limit, 120);
    assert!(
        result.token_count as usize >= result.tokens_preview.len(),
        "token count should cover preview len"
    );
    assert!(
        !result.tokens_preview.is_empty(),
        "token preview should contain at least one token"
    );
    assert!(
        result
            .tokens_preview
            .iter()
            .any(|token| !token.text.is_empty()),
        "token preview should include non-empty text"
    );
}
