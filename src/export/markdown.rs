//! Markdown export format for human-readable reports

use anyhow::Result;
use std::path::Path;

use crate::models::{AnalysisResult, MemoryLayout, Symbol};
use crate::utils::format_size_human;

/// Export memory layout as Markdown report
pub fn export_markdown(
    layout: &MemoryLayout,
    analysis: &AnalysisResult,
    symbols: &[Symbol],
    elf_path: &Path,
) -> Result<String> {
    let mut output = String::new();

    // Title
    output.push_str(&format!(
        "# Memory Report: {}\n\n",
        elf_path.file_name().unwrap_or_default().to_string_lossy()
    ));

    // Metadata
    output.push_str(&format!(
        "Generated: {}\n\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    ));

    // Memory Summary
    write_memory_summary(&mut output, layout);

    // Memory Sections
    write_sections(&mut output, layout);

    // Analysis
    write_analysis(&mut output, analysis);

    // Top Symbols
    write_top_symbols(&mut output, symbols);

    Ok(output)
}

fn write_memory_summary(output: &mut String, layout: &MemoryLayout) {
    output.push_str("## Memory Summary\n\n");
    output.push_str("| Region | Used | Total | Percentage |\n");
    output.push_str("|--------|------|-------|------------|\n");

    // Flash
    let flash_total = layout
        .flash_size
        .map(format_size_human)
        .unwrap_or_else(|| "Unknown".to_string());
    let flash_pct = layout
        .flash_percentage()
        .map(|p| format!("{:.1}%", p))
        .unwrap_or_else(|| "N/A".to_string());
    output.push_str(&format!(
        "| Flash  | {} | {} | {} |\n",
        format_size_human(layout.total_flash_used),
        flash_total,
        flash_pct
    ));

    // RAM
    let ram_total = layout
        .ram_size
        .map(format_size_human)
        .unwrap_or_else(|| "Unknown".to_string());
    let ram_pct = layout
        .ram_percentage()
        .map(|p| format!("{:.1}%", p))
        .unwrap_or_else(|| "N/A".to_string());
    output.push_str(&format!(
        "| RAM    | {} | {} | {} |\n\n",
        format_size_human(layout.total_ram_used),
        ram_total,
        ram_pct
    ));
}

fn write_sections(output: &mut String, layout: &MemoryLayout) {
    output.push_str("## Memory Sections\n\n");

    // Flash sections
    let flash_sections: Vec<_> = layout
        .sections
        .iter()
        .filter(|s| crate::utils::is_flash_section(s))
        .collect();

    if !flash_sections.is_empty() {
        output.push_str("### Flash Sections\n\n");
        output.push_str("| Section | Address | Size | Type |\n");
        output.push_str("|---------|---------|------|------|\n");

        for section in flash_sections {
            output.push_str(&format!(
                "| {} | 0x{:08x} | {} | {:?} |\n",
                section.name,
                section.address,
                format_size_human(section.size),
                section.section_type
            ));
        }
        output.push('\n');
    }

    // RAM sections
    let ram_sections: Vec<_> = layout
        .sections
        .iter()
        .filter(|s| crate::utils::is_ram_section(s))
        .collect();

    if !ram_sections.is_empty() {
        output.push_str("### RAM Sections\n\n");
        output.push_str("| Section | Address | Size | Type |\n");
        output.push_str("|---------|---------|------|------|\n");

        for section in ram_sections {
            output.push_str(&format!(
                "| {} | 0x{:08x} | {} | {:?} |\n",
                section.name,
                section.address,
                format_size_human(section.size),
                section.section_type
            ));
        }
        output.push('\n');
    }
}

fn write_analysis(output: &mut String, analysis: &AnalysisResult) {
    output.push_str("## Analysis\n\n");

    // Warnings
    if !analysis.warnings.is_empty() {
        output.push_str("### ⚠️ Warnings\n\n");
        for warning in &analysis.warnings {
            output.push_str(&format!("- {}\n", warning));
        }
        output.push('\n');
    }

    // Gaps
    if !analysis.gaps.is_empty() {
        output.push_str("### Memory Gaps\n\n");
        output.push_str("| Region | Start | End | Size |\n");
        output.push_str("|--------|-------|-----|------|\n");

        for gap in &analysis.gaps {
            output.push_str(&format!(
                "| {:?} | 0x{:08x} | 0x{:08x} | {} |\n",
                gap.region_type,
                gap.start,
                gap.end,
                format_size_human(gap.size)
            ));
        }
        output.push('\n');
    }

    // Overlaps
    if !analysis.overlaps.is_empty() {
        output.push_str("### ❌ Memory Overlaps (Critical Issues)\n\n");
        output.push_str("| Section 1 | Section 2 | Start | End | Size |\n");
        output.push_str("|-----------|-----------|-------|-----|------|\n");

        for overlap in &analysis.overlaps {
            output.push_str(&format!(
                "| {} | {} | 0x{:08x} | 0x{:08x} | {} |\n",
                overlap.section1,
                overlap.section2,
                overlap.overlap_start,
                overlap.overlap_end,
                format_size_human(overlap.overlap_size)
            ));
        }
        output.push('\n');
    }

    // Padding
    if analysis.total_padding > 0 {
        output.push_str(&format!(
            "**Alignment Padding**: {} (wasted due to alignment)\n\n",
            format_size_human(analysis.total_padding)
        ));
    }

    // Stack/Heap gap
    if let Some(gap) = analysis.stack_heap_gap {
        let status = if gap == 0 {
            "❌ CRITICAL"
        } else if gap < 1024 {
            "⚠️ WARNING"
        } else if gap < 4096 {
            "⚠️ CAUTION"
        } else {
            "✅ OK"
        };

        output.push_str(&format!(
            "**Stack/Heap Gap**: {} - {}\n\n",
            format_size_human(gap),
            status
        ));
    }
}

fn write_top_symbols(output: &mut String, symbols: &[Symbol]) {
    output.push_str("## Top 10 Largest Symbols\n\n");

    if symbols.is_empty() {
        output.push_str("*No symbols found*\n\n");
        return;
    }

    output.push_str("| Rank | Symbol | Size | Type | File |\n");
    output.push_str("|------|--------|------|------|------|\n");

    // Sort by size (largest first) and take top 10
    let mut sorted_symbols: Vec<_> = symbols.iter().collect();
    sorted_symbols.sort_by(|a, b| b.size.cmp(&a.size));
    let top_symbols: Vec<_> = sorted_symbols.iter().take(10).collect();

    for (i, symbol) in top_symbols.iter().enumerate() {
        let source_file = symbol.source_file.as_deref().unwrap_or("Unknown");
        output.push_str(&format!(
            "| {} | {} | {} | {:?} | {} |\n",
            i + 1,
            truncate_for_table(&symbol.name, 40),
            format_size_human(symbol.size),
            symbol.symbol_type,
            truncate_for_table(source_file, 20)
        ));
    }
    output.push('\n');

    // Summary
    let total_top10: u64 = top_symbols.iter().map(|s| s.size).sum();
    output.push_str(&format!(
        "**Total (Top 10)**: {}\n\n",
        format_size_human(total_top10)
    ));
}

/// Truncate string for table display
fn truncate_for_table(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_for_table() {
        assert_eq!(truncate_for_table("short", 10), "short");
        assert_eq!(
            truncate_for_table("this_is_a_very_long_symbol_name", 15),
            "this_is_a_ve..."
        );
    }

    #[test]
    fn test_markdown_generation() {
        let layout = MemoryLayout::new();
        let analysis = AnalysisResult {
            gaps: vec![],
            overlaps: vec![],
            total_padding: 0,
            stack_heap_gap: None,
            warnings: vec![],
        };
        let symbols = vec![];
        let path = Path::new("test.elf");

        let md = export_markdown(&layout, &analysis, &symbols, path).unwrap();
        assert!(md.contains("# Memory Report: test.elf"));
        assert!(md.contains("## Memory Summary"));
        assert!(md.contains("## Analysis"));
    }
}
