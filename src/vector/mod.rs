//! Vector table parsing and analysis for ARM Cortex-M binaries
//!
//! This module provides functionality to extract, analyze, and visualize
//! the interrupt vector table from ARM embedded ELF binaries.

pub mod analyzer;
pub mod database;
pub mod parser;

pub use analyzer::VectorAnalyzer;
pub use parser::VectorTableParser;
