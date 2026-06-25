use rbinghidra::search_decompilation::{
    DEFAULT_CONTEXT_LINES, DEFAULT_LIMIT, DEFAULT_MAX_FUNCTIONS, MAX_CONTEXT_LINES, MAX_LIMIT,
    MAX_MAX_FUNCTIONS, resolve_context_lines, resolve_limit, resolve_max_functions,
};

#[test]
fn resolve_limit_clamps_at_max() {
    assert_eq!(resolve_limit(None), DEFAULT_LIMIT);
    assert_eq!(resolve_limit(Some(50)), 50);
    assert_eq!(resolve_limit(Some(MAX_LIMIT)), MAX_LIMIT);
    assert_eq!(resolve_limit(Some(MAX_LIMIT + 1)), MAX_LIMIT);
    assert_eq!(resolve_limit(Some(u64::MAX)), MAX_LIMIT);
}

#[test]
fn resolve_context_lines_clamps_at_max() {
    assert_eq!(resolve_context_lines(None), DEFAULT_CONTEXT_LINES);
    assert_eq!(resolve_context_lines(Some(5)), 5);
    assert_eq!(
        resolve_context_lines(Some(MAX_CONTEXT_LINES)),
        MAX_CONTEXT_LINES
    );
    assert_eq!(
        resolve_context_lines(Some(MAX_CONTEXT_LINES + 1)),
        MAX_CONTEXT_LINES
    );
    assert_eq!(resolve_context_lines(Some(u64::MAX)), MAX_CONTEXT_LINES);
}

#[test]
fn resolve_max_functions_clamps_at_max() {
    assert_eq!(resolve_max_functions(None), DEFAULT_MAX_FUNCTIONS);
    assert_eq!(resolve_max_functions(Some(50)), 50);
    assert_eq!(
        resolve_max_functions(Some(MAX_MAX_FUNCTIONS)),
        MAX_MAX_FUNCTIONS
    );
    assert_eq!(
        resolve_max_functions(Some(MAX_MAX_FUNCTIONS + 1)),
        MAX_MAX_FUNCTIONS
    );
    assert_eq!(resolve_max_functions(Some(u64::MAX)), MAX_MAX_FUNCTIONS);
}
