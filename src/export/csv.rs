//! CSV export format for spreadsheet-compatible data

use anyhow::Result;

use crate::models::{AnalysisResult, MemoryLayout, Symbol};
use crate::utils::format_size_human;

/// Export symbols as CSV with all metadata
pub fn export_symbols_csv(symbols: &[Symbol]) -> Result<String> {
    let mut output = String::new();

    // Header
    output
        .push_str("Name,Address,Size,SizeHuman,Type,Binding,Visibility,SectionIndex,SourceFile\n");

    // Rows
    for symbol in symbols {
        let source_file = symbol.source_file.as_deref().unwrap_or("");
        output.push_str(&format!(
            "\"{}\",0x{:08x},{},{},{:?},{:?},{:?},{},\"{}\"\n",
            escape_csv(&symbol.name),
            symbol.address,
            symbol.size,
            format_size_human(symbol.size),
            symbol.symbol_type,
            symbol.binding,
            symbol.visibility,
            symbol.section_index,
            escape_csv(source_file)
        ));
    }

    Ok(output)
}

/// Export sections summary as CSV (Flash/RAM classification)
pub fn export_sections_csv(layout: &MemoryLayout) -> Result<String> {
    let mut output = String::new();

    // Header
    output.push_str("Section,Address,Size,SizeHuman,Type,Region\n");

    // Rows
    for section in &layout.sections {
        let region = if crate::utils::is_flash_section(section) {
            "Flash"
        } else if crate::utils::is_ram_section(section) {
            "RAM"
        } else {
            "Unknown"
        };

        output.push_str(&format!(
            "\"{}\",0x{:08x},{},{},{:?},{}\n",
            escape_csv(&section.name),
            section.address,
            section.size,
            format_size_human(section.size),
            section.section_type,
            region
        ));
    }

    Ok(output)
}

/// Export memory analysis (gaps, overlaps, padding) as CSV
pub fn export_analysis_csv(analysis: &AnalysisResult) -> Result<String> {
    let mut output = String::new();

    // Header
    output.push_str("Type,Region,Start,End,Size,SizeHuman,Details\n");

    // Gaps
    for gap in &analysis.gaps {
        output.push_str(&format!(
            "Gap,{:?},0x{:08x},0x{:08x},{},{},\"\"\n",
            gap.region_type,
            gap.start,
            gap.end,
            gap.size,
            format_size_human(gap.size)
        ));
    }

    // Overlaps
    for overlap in &analysis.overlaps {
        output.push_str(&format!(
            "Overlap,Both,0x{:08x},0x{:08x},{},{},\"{} ↔ {}\"\n",
            overlap.overlap_start,
            overlap.overlap_end,
            overlap.overlap_size,
            format_size_human(overlap.overlap_size),
            escape_csv(&overlap.section1),
            escape_csv(&overlap.section2)
        ));
    }

    // Padding (single row)
    if analysis.total_padding > 0 {
        output.push_str(&format!(
            "Padding,Both,,,{},{},\"Alignment waste\"\n",
            analysis.total_padding,
            format_size_human(analysis.total_padding)
        ));
    }

    // Stack/Heap gap
    if let Some(gap) = analysis.stack_heap_gap {
        output.push_str(&format!(
            "StackHeapGap,RAM,,,{},{},\"Gap between stack and heap\"\n",
            gap,
            format_size_human(gap)
        ));
    }

    Ok(output)
}

/// Escape CSV values (handle quotes and commas)
fn escape_csv(s: &str) -> String {
    if s.contains('"') {
        s.replace('"', "\"\"")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_csv() {
        assert_eq!(escape_csv("simple"), "simple");
        assert_eq!(escape_csv("with\"quote"), "with\"\"quote");
        assert_eq!(escape_csv("normal,comma"), "normal,comma");
    }

    #[test]
    fn test_symbols_csv_header() {
        let symbols = vec![];
        let csv = export_symbols_csv(&symbols).unwrap();
        assert!(csv.starts_with(
            "Name,Address,Size,SizeHuman,Type,Binding,Visibility,SectionIndex,SourceFile\n"
        ));
    }

    #[test]
    fn test_sections_csv_header() {
        let layout = MemoryLayout::new();
        let csv = export_sections_csv(&layout).unwrap();
        assert!(csv.starts_with("Section,Address,Size,SizeHuman,Type,Region\n"));
    }

    #[test]
    fn test_analysis_csv_header() {
        let analysis = AnalysisResult {
            gaps: vec![],
            overlaps: vec![],
            total_padding: 0,
            stack_heap_gap: None,
            warnings: vec![],
        };
        let csv = export_analysis_csv(&analysis).unwrap();
        assert!(csv.starts_with("Type,Region,Start,End,Size,SizeHuman,Details\n"));
    }
}
