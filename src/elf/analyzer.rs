//! Memory layout analyzer for detecting issues and optimization opportunities

use crate::models::{
    AnalysisResult, GapRegionType, MemoryGap, MemoryLayout, MemoryOverlap, SectionType,
};
use crate::utils::{is_flash_section, is_ram_section};

/// Analyzer for memory layout issues and optimization opportunities
///
/// Detects gaps, overlaps, padding waste, and stack/heap collisions
pub struct MemoryAnalyzer;

impl MemoryAnalyzer {
    /// Create a new memory analyzer
    pub fn new() -> Self {
        Self
    }

    /// Analyze a memory layout for potential issues
    ///
    /// Performs comprehensive analysis including:
    /// - Gap detection (unused memory regions)
    /// - Overlap detection (sections that conflict)
    /// - Padding calculation (alignment waste)
    /// - Stack/heap collision risk assessment
    /// - Warning generation for high memory usage
    ///
    /// Returns `AnalysisResult` with all findings
    pub fn analyze(&self, layout: &MemoryLayout) -> AnalysisResult {
        let mut result = AnalysisResult {
            gaps: Vec::new(),
            overlaps: Vec::new(),
            total_padding: 0,
            stack_heap_gap: None,
            warnings: Vec::new(),
        };

        // Detect gaps
        result.gaps = self.detect_gaps(layout);

        // Detect overlaps
        result.overlaps = self.detect_overlaps(layout);

        // Calculate padding
        result.total_padding = self.calculate_padding(layout);

        // Check stack/heap collision risk
        result.stack_heap_gap = self.check_stack_heap_collision(layout);

        // Generate warnings
        result.warnings = self.generate_warnings(layout, &result);

        result
    }

    fn detect_gaps(&self, layout: &MemoryLayout) -> Vec<MemoryGap> {
        let mut gaps = Vec::new();

        // Separate sections by region (Flash vs RAM)
        let mut flash_sections: Vec<_> = layout
            .sections
            .iter()
            .filter(|s| is_flash_section(s))
            .collect();

        let mut ram_sections: Vec<_> = layout
            .sections
            .iter()
            .filter(|s| is_ram_section(s))
            .collect();

        // Sort by address
        flash_sections.sort_by_key(|s| s.address);
        ram_sections.sort_by_key(|s| s.address);

        // Find gaps in Flash
        for i in 0..flash_sections.len().saturating_sub(1) {
            let current_end = flash_sections[i].address + flash_sections[i].size;
            let next_start = flash_sections[i + 1].address;

            if next_start > current_end {
                let gap_size = next_start - current_end;
                // Only report gaps larger than 16 bytes (filter alignment padding)
                if gap_size > 16 {
                    gaps.push(MemoryGap {
                        start: current_end,
                        end: next_start,
                        size: gap_size,
                        region_type: GapRegionType::Flash,
                    });
                }
            }
        }

        // Find gaps in RAM
        for i in 0..ram_sections.len().saturating_sub(1) {
            let current_end = ram_sections[i].address + ram_sections[i].size;
            let next_start = ram_sections[i + 1].address;

            if next_start > current_end {
                let gap_size = next_start - current_end;
                // Only report gaps larger than 16 bytes
                if gap_size > 16 {
                    gaps.push(MemoryGap {
                        start: current_end,
                        end: next_start,
                        size: gap_size,
                        region_type: GapRegionType::Ram,
                    });
                }
            }
        }

        gaps
    }

    fn detect_overlaps(&self, layout: &MemoryLayout) -> Vec<MemoryOverlap> {
        let mut overlaps = Vec::new();

        for i in 0..layout.sections.len() {
            for j in (i + 1)..layout.sections.len() {
                let s1 = &layout.sections[i];
                let s2 = &layout.sections[j];

                let s1_end = s1.address + s1.size;
                let s2_end = s2.address + s2.size;

                // Check if sections overlap
                let overlap_start = s1.address.max(s2.address);
                let overlap_end = s1_end.min(s2_end);

                if overlap_start < overlap_end {
                    overlaps.push(MemoryOverlap {
                        section1: s1.name.clone(),
                        section2: s2.name.clone(),
                        overlap_start,
                        overlap_end,
                        overlap_size: overlap_end - overlap_start,
                    });
                }
            }
        }

        overlaps
    }

    fn calculate_padding(&self, layout: &MemoryLayout) -> u64 {
        let mut total_padding = 0u64;

        // Group sections by region and sort
        let mut flash_sections: Vec<_> = layout
            .sections
            .iter()
            .filter(|s| is_flash_section(s))
            .collect();
        flash_sections.sort_by_key(|s| s.address);

        let mut ram_sections: Vec<_> = layout
            .sections
            .iter()
            .filter(|s| is_ram_section(s))
            .collect();
        ram_sections.sort_by_key(|s| s.address);

        // Calculate padding in Flash (gaps <= 16 bytes are likely alignment)
        for i in 0..flash_sections.len().saturating_sub(1) {
            let current_end = flash_sections[i].address + flash_sections[i].size;
            let next_start = flash_sections[i + 1].address;

            if next_start > current_end {
                let gap = next_start - current_end;
                if gap <= 16 {
                    total_padding += gap;
                }
            }
        }

        // Calculate padding in RAM
        for i in 0..ram_sections.len().saturating_sub(1) {
            let current_end = ram_sections[i].address + ram_sections[i].size;
            let next_start = ram_sections[i + 1].address;

            if next_start > current_end {
                let gap = next_start - current_end;
                if gap <= 16 {
                    total_padding += gap;
                }
            }
        }

        total_padding
    }

    fn check_stack_heap_collision(&self, layout: &MemoryLayout) -> Option<u64> {
        // Find stack and heap sections
        let stack_section = layout
            .sections
            .iter()
            .find(|s| matches!(s.section_type, SectionType::Stack) || s.name.contains("stack"));

        let heap_section = layout
            .sections
            .iter()
            .find(|s| matches!(s.section_type, SectionType::Heap) || s.name.contains("heap"));

        if let (Some(stack), Some(heap)) = (stack_section, heap_section) {
            let stack_start = stack.address;
            let stack_end = stack.address + stack.size;
            let heap_start = heap.address;
            let heap_end = heap.address + heap.size;

            // Check which is higher in memory
            if stack_start > heap_end {
                // Stack is above heap (typical for descending stacks)
                Some(stack_start - heap_end)
            } else if heap_start > stack_end {
                // Heap is above stack
                Some(heap_start - stack_end)
            } else {
                // They overlap or touch - critical issue
                Some(0)
            }
        } else {
            None
        }
    }

    fn generate_warnings(&self, layout: &MemoryLayout, result: &AnalysisResult) -> Vec<String> {
        let mut warnings = Vec::new();

        // Check for overlaps
        if !result.overlaps.is_empty() {
            warnings.push(format!(
                "⚠ Found {} memory overlaps - this will cause runtime issues!",
                result.overlaps.len()
            ));
        }

        // Check stack/heap collision
        if let Some(gap) = result.stack_heap_gap {
            if gap == 0 {
                warnings.push("⚠ CRITICAL: Stack and heap overlap!".to_string());
            } else if gap < 1024 {
                warnings.push(format!(
                    "⚠ WARNING: Only {} bytes between stack and heap - collision risk!",
                    gap
                ));
            } else if gap < 4096 {
                warnings.push(format!(
                    "⚠ Stack/heap gap is {} bytes - monitor for potential collision",
                    gap
                ));
            }
        }

        // Check memory usage percentage
        if let Some(percentage) = layout.flash_percentage() {
            if percentage > 95.0 {
                warnings.push(format!(
                    "⚠ Flash usage is {:.1}% - very little space remaining!",
                    percentage
                ));
            } else if percentage > 85.0 {
                warnings.push(format!(
                    "⚠ Flash usage is {:.1}% - consider optimization",
                    percentage
                ));
            }
        }

        if let Some(percentage) = layout.ram_percentage() {
            if percentage > 95.0 {
                warnings.push(format!(
                    "⚠ RAM usage is {:.1}% - very little space remaining!",
                    percentage
                ));
            } else if percentage > 85.0 {
                warnings.push(format!(
                    "⚠ RAM usage is {:.1}% - consider optimization",
                    percentage
                ));
            }
        }

        warnings
    }
}

impl Default for MemoryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
