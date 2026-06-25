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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_simplification_style_none() {
        assert_eq!(
            resolve_simplification_style(None),
            Some(DEFAULT_SIMPLIFICATION_STYLE)
        );
    }

    #[test]
    fn test_resolve_simplification_style_empty() {
        assert_eq!(
            resolve_simplification_style(Some("")),
            Some(DEFAULT_SIMPLIFICATION_STYLE)
        );
        assert_eq!(
            resolve_simplification_style(Some("   ")),
            Some(DEFAULT_SIMPLIFICATION_STYLE)
        );
    }

    #[test]
    fn test_resolve_simplification_style_default() {
        assert_eq!(
            resolve_simplification_style(Some(DEFAULT_SIMPLIFICATION_STYLE)),
            Some(DEFAULT_SIMPLIFICATION_STYLE)
        );
        assert_eq!(
            resolve_simplification_style(Some(" decompile ")),
            Some(DEFAULT_SIMPLIFICATION_STYLE)
        );
    }

    #[test]
    fn test_resolve_simplification_style_valid() {
        assert_eq!(resolve_simplification_style(Some("normalize")), Some("normalize"));
        assert_eq!(resolve_simplification_style(Some("register")), Some("register"));
        assert_eq!(resolve_simplification_style(Some("firstpass")), Some("firstpass"));
        assert_eq!(resolve_simplification_style(Some("paramid")), Some("paramid"));

        // With whitespace
        assert_eq!(resolve_simplification_style(Some(" normalize ")), Some("normalize"));
        assert_eq!(resolve_simplification_style(Some("\tregister\n")), Some("register"));
    }

    #[test]
    fn test_resolve_simplification_style_invalid() {
        assert_eq!(resolve_simplification_style(Some("invalid_style")), None);
        assert_eq!(resolve_simplification_style(Some("unknown")), None);
        assert_eq!(resolve_simplification_style(Some("123")), None);
    }
}
