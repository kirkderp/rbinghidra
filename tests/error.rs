use rbinghidra::ToolError;

#[test]
fn io_helper_captures_path_and_source() {
    let path = std::path::PathBuf::from("/no/such/file");
    let err = ToolError::io(&path, std::io::Error::from(std::io::ErrorKind::NotFound));
    let rendered = err.to_string();
    assert!(rendered.contains("/no/such/file"));
}
