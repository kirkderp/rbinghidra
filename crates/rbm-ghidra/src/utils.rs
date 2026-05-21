pub const DEFAULT_SIMPLIFICATION_STYLE: &str = "decompile";

#[must_use]
pub fn resolve_simplification_style(style: Option<&str>) -> Option<&'static str> {
    match style.unwrap_or(DEFAULT_SIMPLIFICATION_STYLE).trim() {
        "" | DEFAULT_SIMPLIFICATION_STYLE => Some(DEFAULT_SIMPLIFICATION_STYLE),
        "normalize" => Some("normalize"),
        "register" => Some("register"),
        "firstpass" => Some("firstpass"),
        "paramid" => Some("paramid"),
        _ => None,
    }
}
