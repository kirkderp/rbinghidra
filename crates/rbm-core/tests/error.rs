use rbm_core::ToolError;

#[test]
fn not_implemented_formats_with_tool_name() {
    let err = ToolError::NotImplemented { tool: "r2_open" };
    assert_eq!(err.to_string(), "tool not implemented yet: r2_open");
}

#[test]
fn backend_helper_includes_backend_label() {
    let err = ToolError::backend("rbm-r2", "session already open");
    match err {
        ToolError::Backend { backend, message } => {
            assert_eq!(backend, "rbm-r2");
            assert_eq!(message, "session already open");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn io_helper_captures_path_and_source() {
    let path = std::path::PathBuf::from("/no/such/file");
    let err = ToolError::io(&path, std::io::Error::from(std::io::ErrorKind::NotFound));
    let rendered = err.to_string();
    assert!(rendered.contains("/no/such/file"));
}
