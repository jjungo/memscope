//! JSON export format for machine-readable memory layout data

use anyhow::Result;
use serde::Serialize;
use std::path::Path;

use crate::models::{AnalysisResult, MemoryLayout, MemorySection, Symbol};

/// Complete memory report for JSON export
#[derive(Debug, Serialize)]
pub struct MemoryReport {
    pub metadata: Metadata,
    pub memory: MemoryInfo,
    pub analysis: AnalysisInfo,
    pub symbols: Vec<SymbolInfo>,
}

/// Report metadata
#[derive(Debug, Serialize)]
pub struct Metadata {
    pub elf_file: String,
    pub timestamp: String,
    pub memscope_version: String,
}

/// Memory usage information
#[derive(Debug, Serialize)]
pub struct MemoryInfo {
    pub flash: RegionInfo,
    pub ram: RegionInfo,
}

/// Memory region information
#[derive(Debug, Serialize)]
pub struct RegionInfo {
    pub used: u64,
    pub total: Option<u64>,
    pub percentage: Option<f64>,
    pub sections: Vec<SectionInfo>,
}

/// Section information for JSON
#[derive(Debug, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub address: String,
    pub size: u64,
    pub size_human: String,
    #[serde(rename = "type")]
    pub section_type: String,
}

/// Analysis results for JSON
#[derive(Debug, Serialize)]
pub struct AnalysisInfo {
    pub gaps: Vec<GapInfo>,
    pub overlaps: Vec<OverlapInfo>,
    pub padding: u64,
    pub stack_heap_gap: Option<u64>,
    pub warnings: Vec<String>,
}

/// Gap information
#[derive(Debug, Serialize)]
pub struct GapInfo {
    pub region: String,
    pub start: String,
    pub end: String,
    pub size: u64,
}

/// Overlap information
#[derive(Debug, Serialize)]
pub struct OverlapInfo {
    pub section1: String,
    pub section2: String,
    pub start: String,
    pub end: String,
    pub size: u64,
}

/// Symbol information for JSON
#[derive(Debug, Serialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: String,
    pub size: u64,
    pub size_human: String,
    #[serde(rename = "type")]
    pub symbol_type: String,
    pub binding: String,
    pub visibility: String,
    pub section_index: usize,
    pub source_file: Option<String>,
}

/// Export memory layout as JSON
pub fn export_json(
    layout: &MemoryLayout,
    analysis: &AnalysisResult,
    symbols: &[Symbol],
    elf_path: &Path,
    pretty: bool,
) -> Result<String> {
    let report = build_report(layout, analysis, symbols, elf_path);

    if pretty {
        Ok(serde_json::to_string_pretty(&report)?)
    } else {
        Ok(serde_json::to_string(&report)?)
    }
}

fn build_report(
    layout: &MemoryLayout,
    analysis: &AnalysisResult,
    symbols: &[Symbol],
    elf_path: &Path,
) -> MemoryReport {
    let metadata = Metadata {
        elf_file: elf_path.display().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        memscope_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let flash_sections = layout
        .sections
        .iter()
        .filter(|s| crate::utils::is_flash_section(s))
        .map(section_to_info)
        .collect();

    let ram_sections = layout
        .sections
        .iter()
        .filter(|s| crate::utils::is_ram_section(s))
        .map(section_to_info)
        .collect();

    let memory = MemoryInfo {
        flash: RegionInfo {
            used: layout.total_flash_used,
            total: layout.flash_size,
            percentage: layout.flash_percentage(),
            sections: flash_sections,
        },
        ram: RegionInfo {
            used: layout.total_ram_used,
            total: layout.ram_size,
            percentage: layout.ram_percentage(),
            sections: ram_sections,
        },
    };

    let analysis_info = AnalysisInfo {
        gaps: analysis
            .gaps
            .iter()
            .map(|g| GapInfo {
                region: format!("{:?}", g.region_type),
                start: format!("0x{:08x}", g.start),
                end: format!("0x{:08x}", g.end),
                size: g.size,
            })
            .collect(),
        overlaps: analysis
            .overlaps
            .iter()
            .map(|o| OverlapInfo {
                section1: o.section1.clone(),
                section2: o.section2.clone(),
                start: format!("0x{:08x}", o.overlap_start),
                end: format!("0x{:08x}", o.overlap_end),
                size: o.overlap_size,
            })
            .collect(),
        padding: analysis.total_padding,
        stack_heap_gap: analysis.stack_heap_gap,
        warnings: analysis.warnings.clone(),
    };

    let symbol_infos = symbols
        .iter()
        .map(|s| SymbolInfo {
            name: s.name.clone(),
            address: format!("0x{:08x}", s.address),
            size: s.size,
            size_human: crate::utils::format_size_human(s.size),
            symbol_type: format!("{:?}", s.symbol_type),
            binding: format!("{:?}", s.binding),
            visibility: format!("{:?}", s.visibility),
            section_index: s.section_index,
            source_file: s.source_file.clone(),
        })
        .collect();

    MemoryReport {
        metadata,
        memory,
        analysis: analysis_info,
        symbols: symbol_infos,
    }
}

fn section_to_info(section: &MemorySection) -> SectionInfo {
    SectionInfo {
        name: section.name.clone(),
        address: format!("0x{:08x}", section.address),
        size: section.size,
        size_human: crate::utils::format_size_human(section.size),
        section_type: format!("{:?}", section.section_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AnalysisResult, GapRegionType, MemoryGap, MemoryLayout, MemorySection, SectionType, Symbol,
        SymbolBinding, SymbolType, SymbolVisibility,
    };
    use std::path::Path;

    fn create_test_layout() -> MemoryLayout {
        let mut layout = MemoryLayout::new();
        layout.flash_size = Some(512 * 1024);
        layout.ram_size = Some(256 * 1024);
        layout.total_flash_used = 100 * 1024;
        layout.total_ram_used = 50 * 1024;

        layout.sections.push(MemorySection {
            name: ".text".to_string(),
            address: 0x00000000,
            size: 100 * 1024,
            section_type: SectionType::Text,
            symbols: vec![],
        });

        layout.sections.push(MemorySection {
            name: ".data".to_string(),
            address: 0x20000000,
            size: 50 * 1024,
            section_type: SectionType::Data,
            symbols: vec![],
        });

        layout
    }

    fn create_test_analysis() -> AnalysisResult {
        AnalysisResult {
            gaps: vec![MemoryGap {
                start: 0x20010000,
                end: 0x20020000,
                size: 64 * 1024,
                region_type: GapRegionType::Ram,
            }],
            overlaps: vec![],
            total_padding: 128,
            stack_heap_gap: Some(4096),
            warnings: vec!["Test warning".to_string()],
        }
    }

    fn create_test_symbols() -> Vec<Symbol> {
        vec![
            Symbol {
                name: "main".to_string(),
                address: 0x00001000,
                size: 512,
                symbol_type: SymbolType::Function,
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                section_index: 1,
                source_file: Some("main.c".to_string()),
                section_name: Some(".text".to_string()),
            },
            Symbol {
                name: "buffer".to_string(),
                address: 0x20000000,
                size: 1024,
                symbol_type: SymbolType::Object,
                binding: SymbolBinding::Local,
                visibility: SymbolVisibility::Default,
                section_index: 2,
                source_file: Some("data.c".to_string()),
                section_name: Some(".bss".to_string()),
            },
        ]
    }

    #[test]
    fn test_json_export_structure() {
        let layout = create_test_layout();
        let analysis = create_test_analysis();
        let symbols = create_test_symbols();
        let path = Path::new("test.elf");

        let json = export_json(&layout, &analysis, &symbols, path, true).unwrap();

        // Verify it's valid JSON
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());

        // Verify it contains expected sections
        assert!(json.contains("metadata"));
        assert!(json.contains("memory"));
        assert!(json.contains("analysis"));
        assert!(json.contains("symbols"));
    }

    #[test]
    fn test_json_metadata() {
        let layout = create_test_layout();
        let analysis = create_test_analysis();
        let symbols = vec![];
        let path = Path::new("firmware.elf");

        let json = export_json(&layout, &analysis, &symbols, path, true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["metadata"]["elf_file"], "firmware.elf");
        assert!(value["metadata"]["timestamp"].is_string());
        assert!(value["metadata"]["memscope_version"].is_string());
    }

    #[test]
    fn test_json_memory_info() {
        let layout = create_test_layout();
        let analysis = create_test_analysis();
        let symbols = vec![];
        let path = Path::new("test.elf");

        let json = export_json(&layout, &analysis, &symbols, path, true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Check Flash
        assert_eq!(value["memory"]["flash"]["used"], 102400);
        assert_eq!(value["memory"]["flash"]["total"], 524288);
        assert!(value["memory"]["flash"]["percentage"].is_number());

        // Check RAM
        assert_eq!(value["memory"]["ram"]["used"], 51200);
        assert_eq!(value["memory"]["ram"]["total"], 262144);
        assert!(value["memory"]["ram"]["percentage"].is_number());
    }

    #[test]
    fn test_json_symbols() {
        let layout = create_test_layout();
        let analysis = create_test_analysis();
        let symbols = create_test_symbols();
        let path = Path::new("test.elf");

        let json = export_json(&layout, &analysis, &symbols, path, true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        let symbol_array = value["symbols"].as_array().unwrap();
        assert_eq!(symbol_array.len(), 2);

        // Check first symbol
        assert_eq!(symbol_array[0]["name"], "main");
        assert_eq!(symbol_array[0]["address"], "0x00001000");
        assert_eq!(symbol_array[0]["size"], 512);
        assert_eq!(symbol_array[0]["type"], "Function");
        assert_eq!(symbol_array[0]["source_file"], "main.c");

        // Check second symbol
        assert_eq!(symbol_array[1]["name"], "buffer");
        assert_eq!(symbol_array[1]["size"], 1024);
        assert_eq!(symbol_array[1]["type"], "Object");
    }

    #[test]
    fn test_json_analysis() {
        let layout = create_test_layout();
        let analysis = create_test_analysis();
        let symbols = vec![];
        let path = Path::new("test.elf");

        let json = export_json(&layout, &analysis, &symbols, path, true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Check gaps
        let gaps = value["analysis"]["gaps"].as_array().unwrap();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0]["region"], "Ram");
        assert_eq!(gaps[0]["size"], 65536);

        // Check padding
        assert_eq!(value["analysis"]["padding"], 128);

        // Check stack_heap_gap
        assert_eq!(value["analysis"]["stack_heap_gap"], 4096);

        // Check warnings
        let warnings = value["analysis"]["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0], "Test warning");
    }

    #[test]
    fn test_json_pretty_vs_compact() {
        let layout = create_test_layout();
        let analysis = create_test_analysis();
        let symbols = vec![];
        let path = Path::new("test.elf");

        let pretty = export_json(&layout, &analysis, &symbols, path, true).unwrap();
        let compact = export_json(&layout, &analysis, &symbols, path, false).unwrap();

        // Pretty should have newlines and indentation
        assert!(pretty.contains('\n'));
        assert!(pretty.len() > compact.len());

        // Both should be valid JSON
        let pretty_val: serde_json::Value = serde_json::from_str(&pretty).unwrap();
        let compact_val: serde_json::Value = serde_json::from_str(&compact).unwrap();

        // Check that both have the same structure (ignore timestamp which differs)
        assert_eq!(
            pretty_val["memory"]["flash"]["used"],
            compact_val["memory"]["flash"]["used"]
        );
        assert_eq!(
            pretty_val["symbols"].as_array().unwrap().len(),
            compact_val["symbols"].as_array().unwrap().len()
        );
    }

    #[test]
    fn test_json_empty_symbols() {
        let layout = create_test_layout();
        let analysis = create_test_analysis();
        let symbols = vec![];
        let path = Path::new("test.elf");

        let json = export_json(&layout, &analysis, &symbols, path, true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        let symbol_array = value["symbols"].as_array().unwrap();
        assert_eq!(symbol_array.len(), 0);
    }
}
