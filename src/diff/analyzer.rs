//! Core diffing logic for comparing two memory layouts

use crate::models::{MemoryLayout, MemoryRegion, MemorySection, Symbol};
use std::collections::HashMap;

/// Result of comparing two ELF binaries
#[derive(Debug, Clone)]
pub struct MemoryDiff {
    /// First binary info
    pub v1_info: BinaryInfo,
    /// Second binary info
    pub v2_info: BinaryInfo,
    /// Section-level differences
    pub section_diffs: Vec<SectionDiff>,
    /// Symbol-level changes for data sections (.data, .rodata, .bss)
    pub symbol_changes: SymbolChanges,
    /// Linker script comparison (if provided)
    pub linker_diff: Option<LinkerDiff>,
}

/// Basic information about a binary
#[derive(Debug, Clone)]
pub struct BinaryInfo {
    pub path: String,
    pub total_flash_used: u64,
    pub total_ram_used: u64,
    /// Total Flash size (reserved for future percentage calculations)
    #[allow(dead_code)]
    pub flash_size: Option<u64>,
    /// Total RAM size (reserved for future percentage calculations)
    #[allow(dead_code)]
    pub ram_size: Option<u64>,
}

/// Difference for a single section
#[derive(Debug, Clone)]
pub struct SectionDiff {
    pub name: String,
    pub v1_size: Option<u64>,
    pub v2_size: Option<u64>,
    pub delta: i64,
    pub percent_change: f64,
    pub status: SectionStatus,
}

/// Section change status
#[derive(Debug, Clone, PartialEq)]
pub enum SectionStatus {
    /// Section exists in both binaries with size change
    Modified,
    /// Section exists in both binaries with same size
    Unchanged,
    /// Section only exists in v2
    New,
    /// Section only exists in v1
    Removed,
}

/// Symbol-level changes for data sections
#[derive(Debug, Clone)]
pub struct SymbolChanges {
    /// Changes in .data section
    pub data_changes: SectionSymbolChanges,
    /// Changes in .rodata section
    pub rodata_changes: SectionSymbolChanges,
    /// Changes in .bss section
    pub bss_changes: SectionSymbolChanges,
}

/// Symbol changes within a specific section
#[derive(Debug, Clone)]
pub struct SectionSymbolChanges {
    /// Section name (.data, .rodata, or .bss)
    #[allow(dead_code)]
    pub section_name: String,
    pub total_delta: i64,
    pub new_symbols: Vec<Symbol>,
    pub removed_symbols: Vec<Symbol>,
    pub modified_symbols: Vec<ModifiedSymbol>,
}

/// A symbol that changed size between versions
#[derive(Debug, Clone)]
pub struct ModifiedSymbol {
    pub name: String,
    pub v1_size: u64,
    pub v2_size: u64,
    pub delta: i64,
}

/// Linker script comparison
#[derive(Debug, Clone)]
pub struct LinkerDiff {
    pub v1_script: Option<String>,
    pub v2_script: Option<String>,
    pub region_changes: Vec<RegionChange>,
}

/// Change in a memory region definition
#[derive(Debug, Clone)]
pub struct RegionChange {
    pub name: String,
    pub v1_size: Option<u64>,
    pub v2_size: Option<u64>,
    pub status: RegionStatus,
}

/// Region change status
#[derive(Debug, Clone, PartialEq)]
pub enum RegionStatus {
    Modified,
    Unchanged,
    New,
    Removed,
}

/// Analyzer for computing diffs between two memory layouts
pub struct DiffAnalyzer;

impl DiffAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Compare two memory layouts and produce a diff
    pub fn diff(
        &self,
        v1_layout: &MemoryLayout,
        v2_layout: &MemoryLayout,
        v1_path: &str,
        v2_path: &str,
        v1_linker: Option<&[MemoryRegion]>,
        v2_linker: Option<&[MemoryRegion]>,
    ) -> MemoryDiff {
        let v1_info = BinaryInfo {
            path: v1_path.to_string(),
            total_flash_used: v1_layout.total_flash_used,
            total_ram_used: v1_layout.total_ram_used,
            flash_size: v1_layout.flash_size,
            ram_size: v1_layout.ram_size,
        };

        let v2_info = BinaryInfo {
            path: v2_path.to_string(),
            total_flash_used: v2_layout.total_flash_used,
            total_ram_used: v2_layout.total_ram_used,
            flash_size: v2_layout.flash_size,
            ram_size: v2_layout.ram_size,
        };

        let section_diffs = self.diff_sections(&v1_layout.sections, &v2_layout.sections);
        let symbol_changes = self.diff_symbols(&v1_layout.sections, &v2_layout.sections);
        let linker_diff = self.diff_linker_scripts(v1_linker, v2_linker);

        MemoryDiff {
            v1_info,
            v2_info,
            section_diffs,
            symbol_changes,
            linker_diff,
        }
    }

    /// Compare sections between two layouts
    fn diff_sections(
        &self,
        v1_sections: &[MemorySection],
        v2_sections: &[MemorySection],
    ) -> Vec<SectionDiff> {
        let mut diffs = Vec::new();

        // Create maps for quick lookup
        let v1_map: HashMap<&str, &MemorySection> =
            v1_sections.iter().map(|s| (s.name.as_str(), s)).collect();
        let v2_map: HashMap<&str, &MemorySection> =
            v2_sections.iter().map(|s| (s.name.as_str(), s)).collect();

        // Collect all unique section names
        let mut all_names: Vec<&str> = v1_map.keys().copied().collect();
        for name in v2_map.keys() {
            if !all_names.contains(name) {
                all_names.push(name);
            }
        }
        all_names.sort();

        for name in all_names {
            let v1_size = v1_map.get(name).map(|s| s.size);
            let v2_size = v2_map.get(name).map(|s| s.size);

            let (delta, percent_change, status) = match (v1_size, v2_size) {
                (Some(v1), Some(v2)) => {
                    let delta = v2 as i64 - v1 as i64;
                    let percent = if v1 > 0 {
                        (delta as f64 / v1 as f64) * 100.0
                    } else {
                        0.0
                    };
                    let status = if delta == 0 {
                        SectionStatus::Unchanged
                    } else {
                        SectionStatus::Modified
                    };
                    (delta, percent, status)
                }
                (None, Some(v2)) => (v2 as i64, 0.0, SectionStatus::New),
                (Some(v1), None) => (-(v1 as i64), 0.0, SectionStatus::Removed),
                (None, None) => unreachable!(),
            };

            diffs.push(SectionDiff {
                name: name.to_string(),
                v1_size,
                v2_size,
                delta,
                percent_change,
                status,
            });
        }

        diffs
    }

    /// Compare symbols in data sections (.data, .rodata, .bss)
    fn diff_symbols(
        &self,
        v1_sections: &[MemorySection],
        v2_sections: &[MemorySection],
    ) -> SymbolChanges {
        let data_changes = self.diff_section_symbols(v1_sections, v2_sections, ".data");
        let rodata_changes = self.diff_section_symbols(v1_sections, v2_sections, ".rodata");
        let bss_changes = self.diff_section_symbols(v1_sections, v2_sections, ".bss");

        SymbolChanges {
            data_changes,
            rodata_changes,
            bss_changes,
        }
    }

    /// Compare symbols within a specific section
    fn diff_section_symbols(
        &self,
        v1_sections: &[MemorySection],
        v2_sections: &[MemorySection],
        section_name: &str,
    ) -> SectionSymbolChanges {
        let v1_section = v1_sections.iter().find(|s| s.name == section_name);
        let v2_section = v2_sections.iter().find(|s| s.name == section_name);

        let v1_symbols: Vec<&Symbol> = v1_section
            .map(|s| s.symbols.iter().collect())
            .unwrap_or_default();
        let v2_symbols: Vec<&Symbol> = v2_section
            .map(|s| s.symbols.iter().collect())
            .unwrap_or_default();

        // Create maps for quick lookup by name
        let v1_map: HashMap<&str, &Symbol> =
            v1_symbols.iter().map(|s| (s.name.as_str(), *s)).collect();
        let v2_map: HashMap<&str, &Symbol> =
            v2_symbols.iter().map(|s| (s.name.as_str(), *s)).collect();

        let mut new_symbols = Vec::new();
        let mut removed_symbols = Vec::new();
        let mut modified_symbols = Vec::new();

        // Find new and modified symbols
        for (name, v2_sym) in &v2_map {
            match v1_map.get(name) {
                None => {
                    // New symbol
                    new_symbols.push((*v2_sym).clone());
                }
                Some(v1_sym) => {
                    // Existing symbol - check if size changed
                    if v1_sym.size != v2_sym.size {
                        modified_symbols.push(ModifiedSymbol {
                            name: name.to_string(),
                            v1_size: v1_sym.size,
                            v2_size: v2_sym.size,
                            delta: v2_sym.size as i64 - v1_sym.size as i64,
                        });
                    }
                }
            }
        }

        // Find removed symbols
        for (name, v1_sym) in &v1_map {
            if !v2_map.contains_key(name) {
                removed_symbols.push((*v1_sym).clone());
            }
        }

        // Sort by size (largest first)
        new_symbols.sort_by(|a, b| b.size.cmp(&a.size));
        removed_symbols.sort_by(|a, b| b.size.cmp(&a.size));
        modified_symbols.sort_by(|a, b| b.delta.abs().cmp(&a.delta.abs()));

        // Calculate total delta
        let new_total: i64 = new_symbols.iter().map(|s| s.size as i64).sum();
        let removed_total: i64 = removed_symbols.iter().map(|s| s.size as i64).sum();
        let modified_total: i64 = modified_symbols.iter().map(|s| s.delta).sum();
        let total_delta = new_total - removed_total + modified_total;

        SectionSymbolChanges {
            section_name: section_name.to_string(),
            total_delta,
            new_symbols,
            removed_symbols,
            modified_symbols,
        }
    }

    /// Compare linker scripts (if provided)
    fn diff_linker_scripts(
        &self,
        v1_regions: Option<&[MemoryRegion]>,
        v2_regions: Option<&[MemoryRegion]>,
    ) -> Option<LinkerDiff> {
        match (v1_regions, v2_regions) {
            (None, None) => None,
            (v1, v2) => {
                let region_changes = self.diff_regions(v1.unwrap_or(&[]), v2.unwrap_or(&[]));

                Some(LinkerDiff {
                    v1_script: v1.map(|_| "v1.ld".to_string()),
                    v2_script: v2.map(|_| "v2.ld".to_string()),
                    region_changes,
                })
            }
        }
    }

    /// Compare memory regions from linker scripts
    fn diff_regions(
        &self,
        v1_regions: &[MemoryRegion],
        v2_regions: &[MemoryRegion],
    ) -> Vec<RegionChange> {
        let mut changes = Vec::new();

        let v1_map: HashMap<&str, &MemoryRegion> =
            v1_regions.iter().map(|r| (r.name.as_str(), r)).collect();
        let v2_map: HashMap<&str, &MemoryRegion> =
            v2_regions.iter().map(|r| (r.name.as_str(), r)).collect();

        // Collect all unique region names
        let mut all_names: Vec<&str> = v1_map.keys().copied().collect();
        for name in v2_map.keys() {
            if !all_names.contains(name) {
                all_names.push(name);
            }
        }
        all_names.sort();

        for name in all_names {
            let v1_size = v1_map.get(name).map(|r| r.length);
            let v2_size = v2_map.get(name).map(|r| r.length);

            let status = match (v1_size, v2_size) {
                (Some(v1), Some(v2)) if v1 == v2 => RegionStatus::Unchanged,
                (Some(_), Some(_)) => RegionStatus::Modified,
                (None, Some(_)) => RegionStatus::New,
                (Some(_), None) => RegionStatus::Removed,
                (None, None) => unreachable!(),
            };

            changes.push(RegionChange {
                name: name.to_string(),
                v1_size,
                v2_size,
                status,
            });
        }

        changes
    }
}

impl Default for DiffAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
