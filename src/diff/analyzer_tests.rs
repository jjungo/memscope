//! Comprehensive tests for memory diff analyzer

#[cfg(test)]
mod tests {
    use crate::diff::analyzer::*;
    use crate::models::*;

    /// Create a test symbol
    fn make_symbol(name: &str, address: u64, size: u64) -> Symbol {
        Symbol {
            name: name.to_string(),
            address,
            size,
            symbol_type: SymbolType::Object,
            binding: SymbolBinding::Global,
            visibility: SymbolVisibility::Default,
            section_index: 0,
            source_file: None,
            section_name: None,
        }
    }

    /// Create a test section
    fn make_section(name: &str, address: u64, size: u64, symbols: Vec<Symbol>) -> MemorySection {
        MemorySection {
            name: name.to_string(),
            address,
            size,
            section_type: match name {
                ".text" => SectionType::Text,
                ".rodata" => SectionType::RoData,
                ".data" => SectionType::Data,
                ".bss" => SectionType::Bss,
                _ => SectionType::Custom(name.to_string()),
            },
            symbols,
        }
    }

    /// Create a test memory layout
    fn make_layout(sections: Vec<MemorySection>, flash_used: u64, ram_used: u64) -> MemoryLayout {
        MemoryLayout {
            regions: vec![],
            sections,
            total_flash_used: flash_used,
            total_ram_used: ram_used,
            flash_size: Some(512 * 1024),
            ram_size: Some(256 * 1024),
        }
    }

    #[test]
    fn test_identical_binaries() {
        let sections = vec![
            make_section(".text", 0x0000, 1000, vec![]),
            make_section(".data", 0x2000, 100, vec![]),
        ];

        let layout = make_layout(sections.clone(), 1100, 100);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&layout, &layout, "v1.elf", "v2.elf", None, None);

        // All sections should be unchanged
        assert_eq!(diff.section_diffs.len(), 2);
        for section_diff in &diff.section_diffs {
            assert_eq!(section_diff.status, SectionStatus::Unchanged);
            assert_eq!(section_diff.delta, 0);
            assert_eq!(section_diff.percent_change, 0.0);
        }

        // Flash and RAM should be unchanged
        assert_eq!(diff.v1_info.total_flash_used, diff.v2_info.total_flash_used);
        assert_eq!(diff.v1_info.total_ram_used, diff.v2_info.total_ram_used);
    }

    #[test]
    fn test_section_size_change() {
        let v1_sections = vec![
            make_section(".text", 0x0000, 1000, vec![]),
            make_section(".data", 0x2000, 100, vec![]),
        ];

        let v2_sections = vec![
            make_section(".text", 0x0000, 1500, vec![]), // +500 bytes
            make_section(".data", 0x2000, 80, vec![]),   // -20 bytes
        ];

        let v1_layout = make_layout(v1_sections, 1100, 100);
        let v2_layout = make_layout(v2_sections, 1580, 80);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&v1_layout, &v2_layout, "v1.elf", "v2.elf", None, None);

        // Check .text section
        let text_diff = diff
            .section_diffs
            .iter()
            .find(|s| s.name == ".text")
            .unwrap();
        assert_eq!(text_diff.status, SectionStatus::Modified);
        assert_eq!(text_diff.delta, 500);
        assert_eq!(text_diff.percent_change, 50.0);

        // Check .data section
        let data_diff = diff
            .section_diffs
            .iter()
            .find(|s| s.name == ".data")
            .unwrap();
        assert_eq!(data_diff.status, SectionStatus::Modified);
        assert_eq!(data_diff.delta, -20);
        assert_eq!(data_diff.percent_change, -20.0);
    }

    #[test]
    fn test_new_section() {
        let v1_sections = vec![make_section(".text", 0x0000, 1000, vec![])];

        let v2_sections = vec![
            make_section(".text", 0x0000, 1000, vec![]),
            make_section(".custom", 0x3000, 256, vec![]), // New section
        ];

        let v1_layout = make_layout(v1_sections, 1000, 0);
        let v2_layout = make_layout(v2_sections, 1256, 0);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&v1_layout, &v2_layout, "v1.elf", "v2.elf", None, None);

        // Check new section
        let custom_diff = diff
            .section_diffs
            .iter()
            .find(|s| s.name == ".custom")
            .unwrap();
        assert_eq!(custom_diff.status, SectionStatus::New);
        assert_eq!(custom_diff.v1_size, None);
        assert_eq!(custom_diff.v2_size, Some(256));
        assert_eq!(custom_diff.delta, 256);
    }

    #[test]
    fn test_removed_section() {
        let v1_sections = vec![
            make_section(".text", 0x0000, 1000, vec![]),
            make_section(".old_section", 0x3000, 512, vec![]),
        ];

        let v2_sections = vec![make_section(".text", 0x0000, 1000, vec![])];

        let v1_layout = make_layout(v1_sections, 1512, 0);
        let v2_layout = make_layout(v2_sections, 1000, 0);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&v1_layout, &v2_layout, "v1.elf", "v2.elf", None, None);

        // Check removed section
        let old_diff = diff
            .section_diffs
            .iter()
            .find(|s| s.name == ".old_section")
            .unwrap();
        assert_eq!(old_diff.status, SectionStatus::Removed);
        assert_eq!(old_diff.v1_size, Some(512));
        assert_eq!(old_diff.v2_size, None);
        assert_eq!(old_diff.delta, -512);
    }

    #[test]
    fn test_symbol_changes_new_symbols() {
        let v1_symbols = vec![make_symbol("var_a", 0x2000, 64)];

        let v2_symbols = vec![
            make_symbol("var_a", 0x2000, 64),
            make_symbol("var_b", 0x2040, 128), // New symbol
            make_symbol("var_c", 0x20C0, 32),  // New symbol
        ];

        let v1_sections = vec![make_section(".data", 0x2000, 64, v1_symbols)];
        let v2_sections = vec![make_section(".data", 0x2000, 224, v2_symbols)];

        let v1_layout = make_layout(v1_sections, 0, 64);
        let v2_layout = make_layout(v2_sections, 0, 224);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&v1_layout, &v2_layout, "v1.elf", "v2.elf", None, None);

        // Check .data symbol changes
        let data_changes = &diff.symbol_changes.data_changes;
        assert_eq!(data_changes.new_symbols.len(), 2);
        assert_eq!(data_changes.removed_symbols.len(), 0);
        assert_eq!(data_changes.modified_symbols.len(), 0);

        // Total delta should be +160 (128 + 32)
        assert_eq!(data_changes.total_delta, 160);

        // Verify new symbols are sorted by size (largest first)
        assert_eq!(data_changes.new_symbols[0].name, "var_b");
        assert_eq!(data_changes.new_symbols[0].size, 128);
        assert_eq!(data_changes.new_symbols[1].name, "var_c");
        assert_eq!(data_changes.new_symbols[1].size, 32);
    }

    #[test]
    fn test_symbol_changes_removed_symbols() {
        let v1_symbols = vec![
            make_symbol("var_a", 0x2000, 64),
            make_symbol("var_b", 0x2040, 128),
            make_symbol("var_c", 0x20C0, 32),
        ];

        let v2_symbols = vec![make_symbol("var_a", 0x2000, 64)];

        let v1_sections = vec![make_section(".data", 0x2000, 224, v1_symbols)];
        let v2_sections = vec![make_section(".data", 0x2000, 64, v2_symbols)];

        let v1_layout = make_layout(v1_sections, 0, 224);
        let v2_layout = make_layout(v2_sections, 0, 64);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&v1_layout, &v2_layout, "v1.elf", "v2.elf", None, None);

        // Check .data symbol changes
        let data_changes = &diff.symbol_changes.data_changes;
        assert_eq!(data_changes.new_symbols.len(), 0);
        assert_eq!(data_changes.removed_symbols.len(), 2);
        assert_eq!(data_changes.modified_symbols.len(), 0);

        // Total delta should be -160 (removed 128 + 32)
        assert_eq!(data_changes.total_delta, -160);

        // Verify removed symbols are sorted by size (largest first)
        assert_eq!(data_changes.removed_symbols[0].name, "var_b");
        assert_eq!(data_changes.removed_symbols[0].size, 128);
        assert_eq!(data_changes.removed_symbols[1].name, "var_c");
        assert_eq!(data_changes.removed_symbols[1].size, 32);
    }

    #[test]
    fn test_symbol_changes_modified_symbols() {
        let v1_symbols = vec![
            make_symbol("var_a", 0x2000, 64),
            make_symbol("var_b", 0x2040, 128),
        ];

        let v2_symbols = vec![
            make_symbol("var_a", 0x2000, 128), // Size doubled
            make_symbol("var_b", 0x2080, 64),  // Size halved
        ];

        let v1_sections = vec![make_section(".data", 0x2000, 192, v1_symbols)];
        let v2_sections = vec![make_section(".data", 0x2000, 192, v2_symbols)];

        let v1_layout = make_layout(v1_sections, 0, 192);
        let v2_layout = make_layout(v2_sections, 0, 192);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&v1_layout, &v2_layout, "v1.elf", "v2.elf", None, None);

        // Check .data symbol changes
        let data_changes = &diff.symbol_changes.data_changes;
        assert_eq!(data_changes.new_symbols.len(), 0);
        assert_eq!(data_changes.removed_symbols.len(), 0);
        assert_eq!(data_changes.modified_symbols.len(), 2);

        // Total delta should be 0 (+64 -64)
        assert_eq!(data_changes.total_delta, 0);

        // Verify both symbols are modified with equal absolute deltas (order doesn't matter)
        let var_a = data_changes
            .modified_symbols
            .iter()
            .find(|s| s.name == "var_a")
            .unwrap();
        assert_eq!(var_a.v1_size, 64);
        assert_eq!(var_a.v2_size, 128);
        assert_eq!(var_a.delta, 64);

        let var_b = data_changes
            .modified_symbols
            .iter()
            .find(|s| s.name == "var_b")
            .unwrap();
        assert_eq!(var_b.v1_size, 128);
        assert_eq!(var_b.v2_size, 64);
        assert_eq!(var_b.delta, -64);
    }

    #[test]
    fn test_symbol_changes_mixed() {
        let v1_symbols = vec![
            make_symbol("var_a", 0x2000, 64),
            make_symbol("var_b", 0x2040, 128),
            make_symbol("var_old", 0x20C0, 256),
        ];

        let v2_symbols = vec![
            make_symbol("var_a", 0x2000, 128),   // Modified
            make_symbol("var_b", 0x2080, 128),   // Unchanged size
            make_symbol("var_new", 0x2100, 512), // New
        ];

        let v1_sections = vec![make_section(".rodata", 0x2000, 448, v1_symbols)];
        let v2_sections = vec![make_section(".rodata", 0x2000, 768, v2_symbols)];

        let v1_layout = make_layout(v1_sections, 448, 0);
        let v2_layout = make_layout(v2_sections, 768, 0);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&v1_layout, &v2_layout, "v1.elf", "v2.elf", None, None);

        // Check .rodata symbol changes
        let rodata_changes = &diff.symbol_changes.rodata_changes;
        assert_eq!(rodata_changes.new_symbols.len(), 1);
        assert_eq!(rodata_changes.removed_symbols.len(), 1);
        assert_eq!(rodata_changes.modified_symbols.len(), 1);

        // Total delta: +512 (new) -256 (removed) +64 (modified) = +320
        assert_eq!(rodata_changes.total_delta, 320);

        // Verify new symbol
        assert_eq!(rodata_changes.new_symbols[0].name, "var_new");
        assert_eq!(rodata_changes.new_symbols[0].size, 512);

        // Verify removed symbol
        assert_eq!(rodata_changes.removed_symbols[0].name, "var_old");
        assert_eq!(rodata_changes.removed_symbols[0].size, 256);

        // Verify modified symbol
        assert_eq!(rodata_changes.modified_symbols[0].name, "var_a");
        assert_eq!(rodata_changes.modified_symbols[0].delta, 64);
    }

    #[test]
    fn test_multiple_data_sections() {
        let v1_data_symbols = vec![make_symbol("data_var", 0x2000, 100)];
        let v1_rodata_symbols = vec![make_symbol("const_str", 0x1000, 50)];
        let v1_bss_symbols = vec![make_symbol("uninit_var", 0x3000, 200)];

        let v2_data_symbols = vec![
            make_symbol("data_var", 0x2000, 150), // Modified
        ];
        let v2_rodata_symbols = vec![
            make_symbol("const_str", 0x1000, 50),  // Unchanged
            make_symbol("new_const", 0x1050, 100), // New
        ];
        let v2_bss_symbols = vec![]; // All removed

        let v1_sections = vec![
            make_section(".data", 0x2000, 100, v1_data_symbols),
            make_section(".rodata", 0x1000, 50, v1_rodata_symbols),
            make_section(".bss", 0x3000, 200, v1_bss_symbols),
        ];

        let v2_sections = vec![
            make_section(".data", 0x2000, 150, v2_data_symbols),
            make_section(".rodata", 0x1000, 150, v2_rodata_symbols),
            make_section(".bss", 0x3000, 0, v2_bss_symbols),
        ];

        let v1_layout = make_layout(v1_sections, 150, 300);
        let v2_layout = make_layout(v2_sections, 300, 150);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&v1_layout, &v2_layout, "v1.elf", "v2.elf", None, None);

        // Check .data changes
        assert_eq!(diff.symbol_changes.data_changes.modified_symbols.len(), 1);
        assert_eq!(diff.symbol_changes.data_changes.total_delta, 50);

        // Check .rodata changes
        assert_eq!(diff.symbol_changes.rodata_changes.new_symbols.len(), 1);
        assert_eq!(diff.symbol_changes.rodata_changes.total_delta, 100);

        // Check .bss changes
        assert_eq!(diff.symbol_changes.bss_changes.removed_symbols.len(), 1);
        assert_eq!(diff.symbol_changes.bss_changes.total_delta, -200);
    }

    #[test]
    fn test_linker_script_comparison_identical() {
        let regions = vec![
            MemoryRegion {
                name: "FLASH".to_string(),
                origin: 0x0000,
                length: 512 * 1024,
                attributes: "rx".to_string(),
            },
            MemoryRegion {
                name: "RAM".to_string(),
                origin: 0x20000000,
                length: 256 * 1024,
                attributes: "rw".to_string(),
            },
        ];

        let v1_layout = make_layout(vec![], 0, 0);
        let v2_layout = make_layout(vec![], 0, 0);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(
            &v1_layout,
            &v2_layout,
            "v1.elf",
            "v2.elf",
            Some(&regions),
            Some(&regions),
        );

        assert!(diff.linker_diff.is_some());
        let linker_diff = diff.linker_diff.unwrap();

        // All regions should be unchanged
        for region_change in &linker_diff.region_changes {
            assert_eq!(region_change.status, RegionStatus::Unchanged);
        }
    }

    #[test]
    fn test_linker_script_comparison_modified() {
        let v1_regions = vec![
            MemoryRegion {
                name: "FLASH".to_string(),
                origin: 0x0000,
                length: 512 * 1024,
                attributes: "rx".to_string(),
            },
            MemoryRegion {
                name: "RAM".to_string(),
                origin: 0x20000000,
                length: 256 * 1024,
                attributes: "rw".to_string(),
            },
        ];

        let v2_regions = vec![
            MemoryRegion {
                name: "FLASH".to_string(),
                origin: 0x0000,
                length: 1024 * 1024, // Doubled
                attributes: "rx".to_string(),
            },
            MemoryRegion {
                name: "RAM".to_string(),
                origin: 0x20000000,
                length: 256 * 1024, // Unchanged
                attributes: "rw".to_string(),
            },
        ];

        let v1_layout = make_layout(vec![], 0, 0);
        let v2_layout = make_layout(vec![], 0, 0);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(
            &v1_layout,
            &v2_layout,
            "v1.elf",
            "v2.elf",
            Some(&v1_regions),
            Some(&v2_regions),
        );

        let linker_diff = diff.linker_diff.unwrap();

        // Check FLASH region
        let flash_change = linker_diff
            .region_changes
            .iter()
            .find(|r| r.name == "FLASH")
            .unwrap();
        assert_eq!(flash_change.status, RegionStatus::Modified);
        assert_eq!(flash_change.v1_size, Some(512 * 1024));
        assert_eq!(flash_change.v2_size, Some(1024 * 1024));

        // Check RAM region
        let ram_change = linker_diff
            .region_changes
            .iter()
            .find(|r| r.name == "RAM")
            .unwrap();
        assert_eq!(ram_change.status, RegionStatus::Unchanged);
    }

    #[test]
    fn test_linker_script_new_and_removed_regions() {
        let v1_regions = vec![
            MemoryRegion {
                name: "FLASH".to_string(),
                origin: 0x0000,
                length: 512 * 1024,
                attributes: "rx".to_string(),
            },
            MemoryRegion {
                name: "CCM".to_string(),
                origin: 0x10000000,
                length: 64 * 1024,
                attributes: "rw".to_string(),
            },
        ];

        let v2_regions = vec![
            MemoryRegion {
                name: "FLASH".to_string(),
                origin: 0x0000,
                length: 512 * 1024,
                attributes: "rx".to_string(),
            },
            MemoryRegion {
                name: "SRAM2".to_string(),
                origin: 0x20040000,
                length: 128 * 1024,
                attributes: "rw".to_string(),
            },
        ];

        let v1_layout = make_layout(vec![], 0, 0);
        let v2_layout = make_layout(vec![], 0, 0);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(
            &v1_layout,
            &v2_layout,
            "v1.elf",
            "v2.elf",
            Some(&v1_regions),
            Some(&v2_regions),
        );

        let linker_diff = diff.linker_diff.unwrap();

        // Check removed region
        let ccm_change = linker_diff
            .region_changes
            .iter()
            .find(|r| r.name == "CCM")
            .unwrap();
        assert_eq!(ccm_change.status, RegionStatus::Removed);
        assert_eq!(ccm_change.v1_size, Some(64 * 1024));
        assert_eq!(ccm_change.v2_size, None);

        // Check new region
        let sram2_change = linker_diff
            .region_changes
            .iter()
            .find(|r| r.name == "SRAM2")
            .unwrap();
        assert_eq!(sram2_change.status, RegionStatus::New);
        assert_eq!(sram2_change.v1_size, None);
        assert_eq!(sram2_change.v2_size, Some(128 * 1024));
    }

    #[test]
    fn test_empty_sections() {
        // Test with sections that have no symbols
        let v1_sections = vec![make_section(".data", 0x2000, 0, vec![])];

        let v2_sections = vec![make_section(
            ".data",
            0x2000,
            100,
            vec![make_symbol("new_var", 0x2000, 100)],
        )];

        let v1_layout = make_layout(v1_sections, 0, 0);
        let v2_layout = make_layout(v2_sections, 0, 100);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&v1_layout, &v2_layout, "v1.elf", "v2.elf", None, None);

        // Section should show as modified
        let data_diff = diff
            .section_diffs
            .iter()
            .find(|s| s.name == ".data")
            .unwrap();
        assert_eq!(data_diff.status, SectionStatus::Modified);
        assert_eq!(data_diff.delta, 100);

        // Should have 1 new symbol
        assert_eq!(diff.symbol_changes.data_changes.new_symbols.len(), 1);
    }

    #[test]
    fn test_zero_size_section_percent_change() {
        let v1_sections = vec![make_section(".custom", 0x4000, 0, vec![])];

        let v2_sections = vec![make_section(".custom", 0x4000, 100, vec![])];

        let v1_layout = make_layout(v1_sections, 0, 0);
        let v2_layout = make_layout(v2_sections, 100, 0);

        let analyzer = DiffAnalyzer::new();
        let diff = analyzer.diff(&v1_layout, &v2_layout, "v1.elf", "v2.elf", None, None);

        let custom_diff = diff
            .section_diffs
            .iter()
            .find(|s| s.name == ".custom")
            .unwrap();
        assert_eq!(custom_diff.delta, 100);
        assert_eq!(custom_diff.percent_change, 0.0); // 0% when dividing by zero
    }
}
