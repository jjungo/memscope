//! GNU LD linker script parser
//!
//! This module provides optional parsing of GNU LD linker scripts to extract
//! memory region definitions. When provided, these regions enable more accurate
//! memory usage calculations that exactly match the GCC toolchain output.
//!
//! # Usage
//!
//! ```no_run
//! use memscope::linker::parse_linker_script;
//!
//! let regions = parse_linker_script("path/to/linker.ld")?;
//! // Use regions for accurate memory classification
//! ```
//!
//! # Optional Feature
//!
//! Linker script parsing is completely optional. MemScope works perfectly well
//! without a linker script by using ELF section flags and ARM Cortex-M standard
//! memory maps.

pub mod parser;

pub use parser::parse_linker_script;
