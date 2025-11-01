//! ELF binary parsing and memory analysis for ARM embedded systems

pub mod analyzer;
pub mod parser;

#[cfg(test)]
mod analyzer_tests;

pub use analyzer::MemoryAnalyzer;
pub use parser::ElfParser;
