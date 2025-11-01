#[cfg(test)]
mod tests {
    use super::super::analyzer::MemoryAnalyzer;
    use crate::models::{MemoryLayout, MemorySection, SectionType};

    fn create_test_section(
        name: &str,
        address: u64,
        size: u64,
        section_type: SectionType,
    ) -> MemorySection {
        MemorySection {
            name: name.to_string(),
            address,
            size,
            section_type,
            symbols: Vec::new(),
        }
    }

    #[test]
    fn test_gap_detection() {
        let mut layout = MemoryLayout::new();

        // Create sections with a gap
        layout.sections.push(create_test_section(
            ".text",
            0x00000000,
            1024,
            SectionType::Text,
        ));
        layout.sections.push(create_test_section(
            ".rodata",
            0x00001000,
            512,
            SectionType::RoData,
        )); // 3KB gap

        let analyzer = MemoryAnalyzer::new();
        let result = analyzer.analyze(&layout);

        // Should detect the gap between .text and .rodata
        assert!(!result.gaps.is_empty());
        assert_eq!(result.gaps[0].size, 0x1000 - 1024); // 3KB gap
    }

    #[test]
    fn test_overlap_detection() {
        let mut layout = MemoryLayout::new();

        // Create overlapping sections (both in Flash region)
        // .text: 0x0000 - 0x0800 (2048 bytes)
        // .rodata: 0x0400 - 0x0800 (1024 bytes)
        // Overlap: 0x0400 - 0x0800 (1024 bytes)
        layout.sections.push(create_test_section(
            ".text",
            0x00000000,
            2048,
            SectionType::Text,
        ));
        layout.sections.push(create_test_section(
            ".rodata",
            0x00000400,
            1024,
            SectionType::RoData,
        ));

        let analyzer = MemoryAnalyzer::new();
        let result = analyzer.analyze(&layout);

        // Should detect overlap
        assert!(!result.overlaps.is_empty());
        assert_eq!(result.overlaps[0].overlap_size, 1024);
    }

    #[test]
    fn test_stack_heap_collision_safe() {
        let mut layout = MemoryLayout::new();

        // Heap and stack with safe gap
        layout.sections.push(create_test_section(
            ".heap",
            0x20000000,
            4096,
            SectionType::Heap,
        ));
        layout.sections.push(create_test_section(
            ".stack",
            0x20002000,
            4096,
            SectionType::Stack,
        )); // 4KB gap

        let analyzer = MemoryAnalyzer::new();
        let result = analyzer.analyze(&layout);

        assert!(result.stack_heap_gap.is_some());
        assert_eq!(result.stack_heap_gap.unwrap(), 4096);
    }

    #[test]
    fn test_stack_heap_collision_warning() {
        let mut layout = MemoryLayout::new();

        // Heap and stack with small gap (512 bytes)
        layout.sections.push(create_test_section(
            ".heap",
            0x20000000,
            4096,
            SectionType::Heap,
        ));
        layout.sections.push(create_test_section(
            ".stack",
            0x20001200,
            4096,
            SectionType::Stack,
        )); // 512 byte gap

        let analyzer = MemoryAnalyzer::new();
        let result = analyzer.analyze(&layout);

        assert!(result.stack_heap_gap.is_some());
        assert_eq!(result.stack_heap_gap.unwrap(), 512);

        // Should generate warning
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_padding_calculation() {
        let mut layout = MemoryLayout::new();

        // Create sections with small alignment gaps (8 bytes each)
        layout.sections.push(create_test_section(
            ".text",
            0x00000000,
            1000,
            SectionType::Text,
        ));
        layout.sections.push(create_test_section(
            ".rodata",
            0x000003f0,
            500,
            SectionType::RoData,
        )); // 8 byte padding

        let analyzer = MemoryAnalyzer::new();
        let result = analyzer.analyze(&layout);

        // Should detect 8 bytes of padding
        assert_eq!(result.total_padding, 8);
    }

    #[test]
    fn test_high_memory_usage_warning() {
        let mut layout = MemoryLayout::new();
        layout.flash_size = Some(100 * 1024); // 100KB
        layout.total_flash_used = 96 * 1024; // 96KB = 96%

        let analyzer = MemoryAnalyzer::new();
        let result = analyzer.analyze(&layout);

        // Should generate high usage warning
        assert!(!result.warnings.is_empty());
        assert!(result.warnings.iter().any(|w| w.contains("Flash usage")));
    }

    #[test]
    fn test_no_gaps_contiguous_sections() {
        let mut layout = MemoryLayout::new();

        // Create perfectly contiguous sections
        layout.sections.push(create_test_section(
            ".text",
            0x00000000,
            1024,
            SectionType::Text,
        ));
        layout.sections.push(create_test_section(
            ".rodata",
            0x00000400,
            512,
            SectionType::RoData,
        ));

        let analyzer = MemoryAnalyzer::new();
        let result = analyzer.analyze(&layout);

        // Should not detect any gaps
        assert!(result.gaps.is_empty());
    }
}
