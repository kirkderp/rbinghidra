#![doc = "Ghidra backend for rbinghidra: headless subprocess driver and ghidra_* tool implementations."]

#[macro_export]
macro_rules! from_warm_path {
    ($err:ty) => {
        impl $err {
            #[inline]
            #[allow(clippy::missing_panics_doc)]
            fn convert_from_warm_path(err: $crate::warm_path::WarmPathError) -> Self {
                match err {
                    $crate::warm_path::WarmPathError::Inspect(e) => Self::Inspect(e),
                    $crate::warm_path::WarmPathError::LockHeld { sha256 } => {
                        Self::LockHeld { sha256 }
                    }
                    $crate::warm_path::WarmPathError::PathValidation(e) => Self::PathValidation(e),
                    $crate::warm_path::WarmPathError::ProjectFileMissing(p) => {
                        Self::ProjectFileMissing(p)
                    }
                    $crate::warm_path::WarmPathError::HeadlessFailed { exit_code, stderr } => {
                        Self::HeadlessFailed { exit_code, stderr }
                    }
                    $crate::warm_path::WarmPathError::OutputMissing { stdout, stderr } => {
                        Self::OutputMissing { stdout, stderr }
                    }
                    $crate::warm_path::WarmPathError::Headless(e) => Self::Headless(e),
                    $crate::warm_path::WarmPathError::Io { path, source } => {
                        Self::Io { path, source }
                    }
                }
            }
        }

        impl From<$crate::warm_path::WarmPathError> for $err {
            fn from(err: $crate::warm_path::WarmPathError) -> Self {
                Self::convert_from_warm_path(err)
            }
        }
    };
}

pub mod config;
pub(crate) mod env;
pub mod error;
pub mod paths;

pub mod anti_analysis;
pub mod behaviors;
pub mod bytes;
pub mod callgraph;
pub mod cfg;
pub mod constants;
pub mod context_api_slots;
pub mod data_types;
pub mod decompile;
pub mod decompile_meta;
pub mod decompiler_block_behavior;
pub mod decompiler_calls;
pub mod decompiler_cfg;
pub mod decompiler_memory;
pub mod decompiler_slice;
pub mod defined_data;
pub mod delete;
pub mod disassemble;
pub mod dynamic_dispatch_table;
pub mod equates;
pub mod function_checkpoints;
pub mod function_slices;
pub mod function_stats;
pub mod go_metadata;
pub mod health;
pub mod import;
pub mod imports_exports;
pub mod inspect;
pub mod list_functions;
pub mod memory_map;
pub mod namespaces;
pub mod path_digest;
pub mod pcode;
pub mod project;
pub mod search_bytes;
pub mod search_decompilation;
pub mod server;
pub mod string_context;
pub mod strings;
pub mod symbols;
pub mod thunk_target;
pub mod utils;
pub mod variables;
pub mod warm_path;
pub mod xrefs;

pub use config::ServerConfig;
pub use error::{ToolError, ToolResult};
pub use health::{discover_install_dir, probe};
pub use paths::CachePaths;
pub use project::ProjectManager;
pub use server::RbmServer;
