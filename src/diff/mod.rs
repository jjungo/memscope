//! Memory layout diffing for tracking changes between ELF binaries
//!
//! This module provides functionality to compare two ELF binaries and analyze
//! differences in memory usage, sections, and symbols.

mod analyzer;
#[cfg(test)]
mod analyzer_tests;
mod display;

pub use analyzer::DiffAnalyzer;
pub use display::display_diff;
