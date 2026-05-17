#![allow(unsafe_code)]
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use rbm_core::{CachePaths, ServerConfig};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    name: &'static str,
    original: Option<OsString>,
}

impl EnvGuard {
    fn set(name: &'static str, value: impl Into<OsString>) -> Self {
        let original = std::env::var_os(name);
        let value: OsString = value.into();
        // SAFETY: tests using environment mutation hold the process-wide env_lock.
        unsafe {
            std::env::set_var(name, &value);
        }
        Self { name, original }
    }

    fn remove(name: &'static str) -> Self {
        let original = std::env::var_os(name);
        // SAFETY: tests using environment mutation hold the process-wide env_lock.
        unsafe {
            std::env::remove_var(name);
        }
        Self { name, original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => {
                // SAFETY: EnvGuard is only used while the process-wide env_lock is held.
                unsafe {
                    std::env::set_var(self.name, value);
                }
            }
            None => {
                // SAFETY: EnvGuard is only used while the process-wide env_lock is held.
                unsafe {
                    std::env::remove_var(self.name);
                }
            }
        }
    }
}

#[test]
fn cache_paths_from_env_rejects_empty_override() {
    let _guard = env_lock().lock().unwrap();
    let _cache = EnvGuard::set("RBM_CACHE_DIR", "");

    assert!(CachePaths::from_env().is_err());
}

#[test]
fn cache_paths_from_env_uses_explicit_override() {
    let _guard = env_lock().lock().unwrap();
    let _cache = EnvGuard::set("RBM_CACHE_DIR", "/tmp/rbinghidra-cache-test");

    let paths = CachePaths::from_env().unwrap();
    assert_eq!(
        paths.root(),
        PathBuf::from("/tmp/rbinghidra-cache-test").as_path()
    );
}

#[test]
fn cache_paths_from_env_absolutizes_relative_root() {
    let _guard = env_lock().lock().unwrap();
    let _cache = EnvGuard::set("RBM_CACHE_DIR", "relative-rbinghidra-cache");

    let paths = CachePaths::from_env().unwrap();
    assert_eq!(
        paths.root(),
        std::env::current_dir()
            .unwrap()
            .join("relative-rbinghidra-cache")
            .as_path()
    );
}

#[test]
fn cache_paths_from_env_removes_current_dir_components() {
    let _guard = env_lock().lock().unwrap();
    let _cache = EnvGuard::set("RBM_CACHE_DIR", "./relative-rbinghidra-cache");

    let paths = CachePaths::from_env().unwrap();
    assert!(!paths.root().display().to_string().contains("/./"));
    assert_eq!(
        paths.root(),
        std::env::current_dir()
            .unwrap()
            .join("relative-rbinghidra-cache")
            .as_path()
    );
}

#[test]
fn cache_paths_from_env_default_is_absolute() {
    let _guard = env_lock().lock().unwrap();
    let _cache = EnvGuard::remove("RBM_CACHE_DIR");

    let paths = CachePaths::from_env().unwrap();
    assert!(paths.root().is_absolute());
    assert!(paths.root().ends_with("rbinghidra-cache"));
}

#[test]
fn server_config_uses_defaults_when_env_is_missing_or_invalid() {
    let _guard = env_lock().lock().unwrap();
    let _cache = EnvGuard::set("RBM_CACHE_DIR", "/tmp/rbinghidra-config-defaults");
    let _install = EnvGuard::remove("GHIDRA_INSTALL_DIR");
    let _ghidra_timeout = EnvGuard::set("RBM_GHIDRA_TIMEOUT", "invalid");
    let _import_timeout = EnvGuard::remove("RBM_GHIDRA_IMPORT_TIMEOUT");
    let _native_timeout = EnvGuard::remove("RBM_NATIVE_TIMEOUT");
    let cfg = ServerConfig::from_env().unwrap();

    assert_eq!(
        cfg.cache.root(),
        PathBuf::from("/tmp/rbinghidra-config-defaults").as_path()
    );
    assert!(cfg.ghidra_install_dir.is_none());
    assert!(cfg.ghidra_scripts_dir.ends_with("ghidra_scripts"));
    assert_eq!(cfg.ghidra_call_timeout, Duration::from_secs(60));
    assert_eq!(cfg.ghidra_import_timeout, Duration::from_secs(900));
}

#[test]
fn server_config_respects_explicit_env_overrides() {
    let _guard = env_lock().lock().unwrap();
    let _cache = EnvGuard::set("RBM_CACHE_DIR", "/tmp/rbinghidra-config-overrides");
    let _install = EnvGuard::set("GHIDRA_INSTALL_DIR", "/opt/ghidra");
    let _ghidra_timeout = EnvGuard::set("RBM_GHIDRA_TIMEOUT", "12");
    let _import_timeout = EnvGuard::set("RBM_GHIDRA_IMPORT_TIMEOUT", "34");
    let _native_timeout = EnvGuard::set("RBM_NATIVE_TIMEOUT", "78");
    let cfg = ServerConfig::from_env().unwrap();

    assert_eq!(
        cfg.cache.root(),
        PathBuf::from("/tmp/rbinghidra-config-overrides").as_path()
    );
    assert_eq!(cfg.ghidra_install_dir, Some(PathBuf::from("/opt/ghidra")));
    assert!(cfg.ghidra_scripts_dir.ends_with("ghidra_scripts"));
    assert_eq!(cfg.ghidra_call_timeout, Duration::from_secs(12));
    assert_eq!(cfg.ghidra_import_timeout, Duration::from_secs(34));
}
