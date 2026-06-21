use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GhidraHealth {
    pub available: bool,
    pub ghidra_install_dir: Option<String>,
    pub analyze_headless_path: Option<String>,
    pub version: Option<String>,
    pub release_name: Option<String>,
    pub capabilities: GhidraCapabilities,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct GhidraCapabilities {
    pub decompiler_bitfield_names: bool,
    pub debuginfod: bool,
    pub hexagon_processor: bool,
    pub modern_objc_analyzers: bool,
    pub jython_enabled_by_default: bool,
    pub notes: Vec<String>,
}

/// Discover the Ghidra install directory by checking env var, PATH,
/// and known install roots. Returns None if nothing valid is found.
pub fn discover_install_dir() -> Option<PathBuf> {
    // 1. Explicit env var override
    if let Some(dir) = std::env::var_os("GHIDRA_INSTALL_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|dir| is_valid_ghidra_dir(dir))
    {
        return Some(dir);
    }

    // 2. PATH search for analyzeHeadless
    if let Some(dir) = find_via_path() {
        return Some(dir);
    }

    // 3. Known install roots
    for candidate in known_install_roots() {
        let candidate = Path::new(candidate);
        if is_valid_ghidra_dir(candidate) {
            return Some(candidate.to_path_buf());
        }
    }

    None
}

/// Search PATH for `analyzeHeadless`, derive install root from its parent.
fn find_via_path() -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join("analyzeHeadless");
        if is_executable_file(&candidate)
            // analyzeHeadless lives in support/; install root is parent of support/
            && let Some(parent) = candidate.parent()
            && parent.file_name().is_some_and(|n| n == "support")
            && let Some(root) = parent.parent()
            && is_valid_ghidra_dir(root)
        {
            return Some(root.to_path_buf());
        }
    }
    None
}

/// Known Ghidra install roots to probe.
const fn known_install_roots() -> &'static [&'static str] {
    &[
        // macOS Homebrew
        "/opt/homebrew/opt/ghidra/libexec",
        // macOS MacPorts
        "/opt/local/share/ghidra",
        // Common Linux tarball locations
        "/opt/ghidra",
        "/usr/local/share/ghidra",
        "/usr/share/ghidra",
    ]
}

#[must_use]
pub fn is_valid_ghidra_dir(dir: &Path) -> bool {
    analyze_headless_path(dir).is_file() && application_properties_path(dir).is_file()
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|meta| meta.is_file())
        .unwrap_or(false)
}

#[must_use]
pub fn probe() -> GhidraHealth {
    let install_dir = discover_install_dir();
    probe_at(install_dir.as_deref())
}

#[must_use]
pub fn probe_at(install_dir: Option<&Path>) -> GhidraHealth {
    let Some(dir) = install_dir.filter(|p| !p.as_os_str().is_empty()) else {
        return failure(
            None,
            None,
            None,
            None,
            "Ghidra not found. Set GHIDRA_INSTALL_DIR, add analyzeHeadless to PATH, or install via Homebrew (/opt/homebrew/opt/ghidra/libexec)",
        );
    };
    if !dir.is_dir() {
        return failure(
            Some(dir),
            None,
            None,
            None,
            &format!(
                "GHIDRA_INSTALL_DIR points to a path that is not a directory: {}",
                dir.display()
            ),
        );
    }

    let analyze_headless = analyze_headless_path(dir);
    if !analyze_headless.exists() {
        return failure(
            Some(dir),
            Some(analyze_headless.as_path()),
            None,
            None,
            &format!(
                "analyzeHeadless not found at {}; install Ghidra 11.2+ and ensure the support/ launcher is present",
                analyze_headless.display()
            ),
        );
    }

    let props_path = application_properties_path(dir);
    let props_text = match std::fs::read_to_string(&props_path) {
        Ok(text) => text,
        Err(err) => {
            return failure(
                Some(dir),
                Some(analyze_headless.as_path()),
                None,
                None,
                &format!("could not read {}: {}", props_path.display(), err),
            );
        }
    };

    assemble_health(dir, &analyze_headless, &props_text)
}

#[must_use]
pub fn assemble_health(
    install_dir: &Path,
    analyze_headless: &Path,
    props_text: &str,
) -> GhidraHealth {
    let parsed = parse_application_properties(props_text);
    let name = parsed.get("application.name").cloned();
    let version = parsed.get("application.version").cloned();
    let release_name = parsed.get("application.release.name").cloned();

    if name.as_deref() != Some("Ghidra") {
        return failure(
            Some(install_dir),
            Some(analyze_headless),
            version,
            release_name,
            &format!(
                "application.properties at {} does not identify as Ghidra (application.name={:?})",
                application_properties_path(install_dir).display(),
                name.as_deref().unwrap_or(""),
            ),
        );
    }
    if version.is_none() {
        return failure(
            Some(install_dir),
            Some(analyze_headless),
            None,
            release_name,
            &format!(
                "application.properties at {} is missing application.version",
                application_properties_path(install_dir).display(),
            ),
        );
    }

    GhidraHealth {
        available: true,
        ghidra_install_dir: Some(install_dir.display().to_string()),
        analyze_headless_path: Some(analyze_headless.display().to_string()),
        capabilities: capabilities_for(install_dir, version.as_deref()),
        version,
        release_name,
        error: None,
    }
}

#[must_use]
pub fn analyze_headless_path(install_dir: &Path) -> PathBuf {
    install_dir.join("support").join("analyzeHeadless")
}

#[must_use]
pub fn application_properties_path(install_dir: &Path) -> PathBuf {
    install_dir.join("Ghidra").join("application.properties")
}

#[must_use]
pub fn parse_application_properties(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            out.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    out
}

fn failure(
    install_dir: Option<&Path>,
    analyze_headless: Option<&Path>,
    version: Option<String>,
    release_name: Option<String>,
    message: &str,
) -> GhidraHealth {
    GhidraHealth {
        available: false,
        ghidra_install_dir: install_dir.map(|p| p.display().to_string()),
        analyze_headless_path: analyze_headless.map(|p| p.display().to_string()),
        capabilities: capabilities_for(
            install_dir.unwrap_or_else(|| Path::new("")),
            version.as_deref(),
        ),
        version,
        release_name,
        error: Some(message.to_string()),
    }
}

fn capabilities_for(install_dir: &Path, version: Option<&str>) -> GhidraCapabilities {
    let is_12_1_or_newer = version.is_some_and(version_at_least_12_1);
    let hexagon_processor = install_dir.join("Ghidra/Processors/Hexagon").is_dir();
    let debuginfod_cache = std::env::var_os("DEBUGINFOD_CACHE_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".cache/debuginfod_client"))
        });

    let mut notes = Vec::new();
    if is_12_1_or_newer {
        notes.push("Ghidra 12.1+ decompiler can recover and display struct bitfield names in more expressions; existing ghidra_decompile and ghidra_decompile_meta calls surface this in pseudocode/token views.".to_string());
        notes.push("Ghidra 12.1+ supports debuginfod lookups for DWARF debug files over HTTP/S and the local debuginfod client cache.".to_string());
        notes.push("Jython is shipped as an extension in Ghidra 12.1 and is not enabled by default; rbinghidra Ghidra scripts are Java and do not depend on Jython.".to_string());
    }
    if let Some(cache) = debuginfod_cache {
        notes.push(format!(
            "debuginfod cache path candidate: {}",
            cache.display()
        ));
    }
    if hexagon_processor {
        notes.push("Hexagon processor module is present; ghidra_import can target Hexagon language IDs through the existing processor/cspec import parameters.".to_string());
    }

    GhidraCapabilities {
        decompiler_bitfield_names: is_12_1_or_newer,
        debuginfod: is_12_1_or_newer,
        hexagon_processor,
        modern_objc_analyzers: is_12_1_or_newer,
        jython_enabled_by_default: !is_12_1_or_newer,
        notes,
    }
}

fn version_at_least_12_1(version: &str) -> bool {
    let mut parts = version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u32>().ok());
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    major > 12 || (major == 12 && minor >= 1)
}
