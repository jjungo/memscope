//! Export functionality for memory layout data
//!
//! Supports multiple output formats:
//! - JSON: Machine-readable format for CI/CD integration
//! - CSV: Spreadsheet-compatible symbol tables
//! - Markdown: Human-readable reports for documentation

pub mod csv;
pub mod json;
pub mod markdown;

use anyhow::Result;
use std::path::Path;

use crate::models::{AnalysisResult, MemoryLayout};

/// Export format options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExportFormat {
    /// JSON format (machine-readable)
    Json,
    /// CSV format with symbols table
    CsvSymbols,
    /// CSV format with sections summary
    CsvSections,
    /// CSV format with analysis data
    CsvAnalysis,
    /// Markdown report
    Markdown,
}

impl ExportFormat {
    /// Parse export format from string
    ///
    /// Supported formats:
    /// - "json"
    /// - "csv" or "csv:symbols" (default CSV mode)
    /// - "csv:sections"
    /// - "csv:analysis"
    /// - "markdown" or "md"
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "csv" | "csv:symbols" => Some(Self::CsvSymbols),
            "csv:sections" => Some(Self::CsvSections),
            "csv:analysis" => Some(Self::CsvAnalysis),
            "markdown" | "md" => Some(Self::Markdown),
            _ => None,
        }
    }
}

/// Export memory layout data to a string in the specified format
pub fn export_to_string(
    layout: &MemoryLayout,
    analysis: &AnalysisResult,
    symbols: &[crate::models::Symbol],
    format: ExportFormat,
    elf_path: &Path,
) -> Result<String> {
    match format {
        ExportFormat::Json => json::export_json(layout, analysis, symbols, elf_path, true),
        ExportFormat::CsvSymbols => csv::export_symbols_csv(symbols),
        ExportFormat::CsvSections => csv::export_sections_csv(layout),
        ExportFormat::CsvAnalysis => csv::export_analysis_csv(analysis),
        ExportFormat::Markdown => markdown::export_markdown(layout, analysis, symbols, elf_path),
    }
}

/// Export memory layout data to a file
pub fn export_to_file(
    layout: &MemoryLayout,
    analysis: &AnalysisResult,
    symbols: &[crate::models::Symbol],
    format: ExportFormat,
    elf_path: &Path,
    output_path: &Path,
) -> Result<()> {
    let content = export_to_string(layout, analysis, symbols, format, elf_path)?;
    std::fs::write(output_path, content)?;
    Ok(())
}
