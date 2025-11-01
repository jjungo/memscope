/// Utility functions shared across the codebase
use crate::models::{MemorySection, SectionType};

/// Format a size in bytes to human-readable format
///
/// # Examples
/// ```
/// assert_eq!(format_size_human(512), "512 B");
/// assert_eq!(format_size_human(2048), "2.00 KB");
/// assert_eq!(format_size_human(2097152), "2.00 MB");
/// ```
pub fn format_size_human(size: u64) -> String {
    if size < 1024 {
        format!("{} B", size)
    } else if size < 1024 * 1024 {
        format!("{:.2} KB", size as f64 / 1024.0)
    } else {
        format!("{:.2} MB", size as f64 / (1024.0 * 1024.0))
    }
}

/// Truncate a string to a maximum length, adding "..." if truncated
///
/// # Examples
/// ```
/// assert_eq!(truncate("hello", 10), "hello");
/// assert_eq!(truncate("hello world", 8), "hello...");
/// ```
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Check if a memory section is in Flash region
///
/// Flash sections are typically Text or RoData, or have addresses below 0x20000000
pub fn is_flash_section(section: &MemorySection) -> bool {
    matches!(
        section.section_type,
        SectionType::Text | SectionType::RoData
    ) || section.address < 0x20000000
}

/// Check if a memory section is in RAM region
///
/// RAM sections are Data, Bss, Stack, or Heap, or have addresses in the 0x20000000-0x40000000 range
pub fn is_ram_section(section: &MemorySection) -> bool {
    matches!(
        section.section_type,
        SectionType::Data | SectionType::Bss | SectionType::Stack | SectionType::Heap
    ) || (section.address >= 0x20000000 && section.address < 0x40000000)
}

/// Round a size to the nearest common embedded memory size
///
/// Common sizes are: 16KB, 32KB, 64KB, 128KB, 256KB, 384KB, 512KB, 1MB, 2MB
/// Sizes larger than 2MB are rounded to the next MB
pub fn round_to_common_size(size: u64) -> u64 {
    const SIZES: &[u64] = &[
        16 * 1024,   // 16KB
        32 * 1024,   // 32KB
        64 * 1024,   // 64KB
        128 * 1024,  // 128KB
        256 * 1024,  // 256KB
        384 * 1024,  // 384KB
        512 * 1024,  // 512KB
        1024 * 1024, // 1MB
        2048 * 1024, // 2MB
    ];

    for &common_size in SIZES {
        if size <= common_size {
            return common_size;
        }
    }

    // If larger than all common sizes, round to next MB
    size.div_ceil(1024 * 1024) * 1024 * 1024
}
