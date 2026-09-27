//! Native Retrieval для poler-sh: замена grep/ripgrep со сканированием
//! файлов и архивов без распаковки.

pub mod filecache;
pub mod grep;
pub mod teddy;

pub use filecache::FileCache;
pub use grep::{
    collect_archives, grep_buffer, grep_run, grep_run_cached, render_text, stdout_is_tty,
    GrepConfig, GrepGroup, GrepLineOut, GrepMode, GrepOutput, GrepReport, GrepStats,
};
pub use teddy::{Teddy, TeddyError, TeddyMatch, MAX_PATTERNS};
