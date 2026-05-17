use rbm_core::ToolError;

#[test]
fn not_implemented_formats_with_tool_name() {
    let err = ToolError::NotImplemented {
        tool: "ghidra_probe",
    };
    assert_eq!(err.to_string(), "tool not implemented yet: ghidra_probe");
}

#[test]
fn backend_helper_includes_backend_label() {
    let err = ToolError::backend("rbinghidra", "project already open");
    match err {
        ToolError::Backend { backend, message } => {
            assert_eq!(backend, "rbinghidra");
            assert_eq!(message, "project already open");
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
