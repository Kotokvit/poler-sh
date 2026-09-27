//! POLER-SH — Суверенная командная оболочка, терминальный шлюз (Terminal Gateway)
//! и Native Retrieval (grep/scan по файлам и архивам без распаковки).

pub mod archive;
pub mod calc;
pub mod pqc;
pub mod retrieval;
pub mod shell {
    pub mod agentenv;
    pub mod wincompat;
}

pub use calc::{CalcState, Value};
pub use retrieval::grep::{
    grep_run, GrepConfig, GrepMode, GrepOutput, GrepReport,
};

/// Директории, исключаемые из обхода.
pub const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".svn", ".hg", "__pycache__"];
