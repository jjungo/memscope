//! GNU LD linker script parser for extracting memory region definitions
//!
//! Parses the `MEMORY` command from GNU LD linker scripts to extract memory
//! region definitions (FLASH, RAM, etc.) with their addresses and sizes.
//!
//! # Supported Syntax
//!
//! ```ld
//! MEMORY {
//!   FLASH (rx)  : ORIGIN = 0x00027000, LENGTH = 0x90000
//!   RAM (rwx)   : ORIGIN = 0x20006000, LENGTH = 256K
//!   CCMRAM (rw) : org = 0x10000000, len = 64K
//! }
//! ```
//!
//! Supports:
//! - Hex (0x1000) and decimal (4096) addresses
//! - Size suffixes: K (×1024), M (×1024×1024)
//! - Alternative keywords: ORIGIN/org/o, LENGTH/len/l
//! - C-style comments: `/* comment */`
//! - Optional attributes: (rwx), (rx), etc.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::models::MemoryRegion;

/// Parse a GNU LD linker script and extract memory region definitions
///
/// Extracts memory regions from the `MEMORY` command block. If the file cannot
/// be read or parsed, returns an error. The caller can choose to fall back to
/// ELF-only analysis.
///
/// # Example
///
/// ```no_run
/// use memscope::linker::parse_linker_script;
///
/// match parse_linker_script("linker.ld") {
///     Ok(regions) => println!("Found {} memory regions", regions.len()),
///     Err(e) => eprintln!("Warning: Failed to parse linker script: {}", e),
/// }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - File cannot be read
/// - No MEMORY block is found
/// - MEMORY block syntax is malformed
pub fn parse_linker_script<P: AsRef<Path>>(path: P) -> Result<Vec<MemoryRegion>> {
    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read linker script: {}", path.as_ref().display()))?;

    parse_memory_regions(&content)
}

/// Parse memory regions from linker script content
fn parse_memory_regions(content: &str) -> Result<Vec<MemoryRegion>> {
    let mut regions = Vec::new();

    // Remove comments first
    let content = remove_comments(content);

    // Find and extract MEMORY block
    let memory_block = extract_memory_block(&content)?;

    // Parse each region line
    for line in memory_block.lines() {
        if let Some(region) = parse_region_line(line) {
            // Skip zero-length regions (common for unused memory)
            if region.length == 0 {
                continue;
            }
            regions.push(region);
        }
    }

    if regions.is_empty() {
        anyhow::bail!("No valid memory regions found in MEMORY block");
    }

    Ok(regions)
}

/// Extract the MEMORY { ... } block from the content
fn extract_memory_block(content: &str) -> Result<String> {
    // Find MEMORY keyword
    let start = content
        .find("MEMORY")
        .context("No MEMORY block found in linker script")?;

    let content = &content[start..];

    // Find opening brace
    let brace_start = content
        .find('{')
        .context("No opening brace found for MEMORY block")?;

    // Find matching closing brace
    let brace_end = find_matching_brace(&content[brace_start..])
        .context("No closing brace found for MEMORY block")?;

    Ok(content[brace_start + 1..brace_start + brace_end].to_string())
}

/// Find the position of the matching closing brace
fn find_matching_brace(content: &str) -> Option<usize> {
    let mut depth = 0;
    for (i, c) in content.chars().enumerate() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Remove C-style comments /* ... */ from the content
fn remove_comments(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '/' {
            // Check for /* comment */
            if let Some(&'*') = chars.peek() {
                chars.next(); // consume '*'

                // Skip until we find */
                let mut found_end = false;
                while let Some(c) = chars.next() {
                    if c == '*'
                        && let Some(&'/') = chars.peek()
                    {
                        chars.next(); // consume '/'
                        found_end = true;
                        break;
                    }
                }

                // Replace comment with space to avoid joining tokens
                if found_end {
                    result.push(' ');
                }
                continue;
            }
            // Check for // line comment
            else if let Some(&'/') = chars.peek() {
                chars.next(); // consume second '/'

                // Skip until end of line
                for c in chars.by_ref() {
                    if c == '\n' {
                        result.push('\n');
                        break;
                    }
                }
                continue;
            }
        }
        result.push(c);
    }

    result
}

/// Parse a single memory region line
///
/// Supports various formats:
/// - `FLASH (rx) : ORIGIN = 0x8000, LENGTH = 512K`
/// - `RAM (rwx) : org = 0x20000000, len = 128K`
/// - `CCMRAM : o = 0x10000000, l = 64K`
fn parse_region_line(line: &str) -> Option<MemoryRegion> {
    let line = line.trim();

    // Skip empty lines
    if line.is_empty() {
        return None;
    }

    // Extract region name (first token, ends at '(' or ':' or whitespace)
    let name_end = line
        .find(|c: char| c == ':' || c == '(' || c.is_whitespace())
        .unwrap_or(line.len());

    let name = line[..name_end].trim().to_string();

    // Skip if name is empty
    if name.is_empty() {
        return None;
    }

    // Extract attributes if present (between parentheses)
    let attributes = if let Some(attr_start) = line.find('(') {
        if let Some(attr_end) = line.find(')') {
            line[attr_start + 1..attr_end].trim().to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    // Extract ORIGIN (or org, o)
    let origin = extract_address_value(line, &["ORIGIN", "org", "o"])?;

    // Extract LENGTH (or len, l)
    let length = extract_size_value(line, &["LENGTH", "len", "l"])?;

    Some(MemoryRegion {
        name,
        origin,
        length,
        attributes,
    })
}

/// Extract address value for ORIGIN/org/o keywords
fn extract_address_value(line: &str, keywords: &[&str]) -> Option<u64> {
    for keyword in keywords {
        if let Some(value_str) = extract_value(line, keyword)
            && let Some(value) = parse_number(&value_str)
        {
            return Some(value);
        }
    }
    None
}

/// Extract size value for LENGTH/len/l keywords (supports K/M suffixes)
fn extract_size_value(line: &str, keywords: &[&str]) -> Option<u64> {
    for keyword in keywords {
        if let Some(value_str) = extract_value(line, keyword)
            && let Some(value) = parse_size(&value_str)
        {
            return Some(value);
        }
    }
    None
}

/// Extract the value after a keyword and '=' sign
///
/// Example: "ORIGIN = 0x8000, LENGTH = 512K" with keyword "ORIGIN" returns "0x8000"
fn extract_value(line: &str, keyword: &str) -> Option<String> {
    // Find keyword (case-sensitive)
    let key_pos = line.find(keyword)?;

    // Make sure it's a whole word (not part of another word)
    if key_pos > 0 {
        let prev_char = line.chars().nth(key_pos - 1)?;
        if prev_char.is_alphanumeric() || prev_char == '_' {
            return None; // Part of another identifier
        }
    }

    let rest = &line[key_pos + keyword.len()..];

    // Find '=' sign
    let eq_pos = rest.find('=')?;
    let value_start = &rest[eq_pos + 1..].trim_start();

    // Extract value until comma, closing brace, or end of line
    let value_end = value_start
        .find(',')
        .or_else(|| value_start.find('}'))
        .or_else(|| value_start.find(';'))
        .unwrap_or(value_start.len());

    Some(value_start[..value_end].trim().to_string())
}

/// Parse a number (hex or decimal)
///
/// Supports:
/// - Hexadecimal: 0x1000, 0X1000
/// - Decimal: 4096
fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim();

    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Parse a size value with optional K/M suffix
///
/// Supports:
/// - Plain numbers: 4096
/// - Hex: 0x1000
/// - K suffix: 4K = 4096, 256K = 262144
/// - M suffix: 1M = 1048576
/// - Simple expressions: 512K - 32K, 1M + 256K
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();

    // Remove parentheses if present first
    let s = if s.starts_with('(') && s.ends_with(')') {
        s[1..s.len() - 1].trim()
    } else {
        s
    };

    // Check for simple expressions (addition/subtraction)
    // Look for operators outside of hex numbers (not immediately after '0x')
    if let Some(plus_pos) = s.find('+') {
        // Make sure '+' is not part of a number
        if plus_pos > 0 && !s[..plus_pos].ends_with("0x") {
            return parse_expression(s, |a, b| a + b);
        }
    }

    if let Some(minus_pos) = s.find('-') {
        // Make sure '-' is not part of a hex number
        if minus_pos > 0 && !s[..minus_pos].ends_with("0x") {
            return parse_expression(s, |a, b| a.saturating_sub(b));
        }
    }

    // Check for size suffixes
    if s.ends_with('K') || s.ends_with('k') {
        let num_str = &s[..s.len() - 1].trim();
        parse_number(num_str).map(|n| n * 1024)
    } else if s.ends_with('M') || s.ends_with('m') {
        let num_str = &s[..s.len() - 1].trim();
        parse_number(num_str).map(|n| n * 1024 * 1024)
    } else {
        parse_number(s)
    }
}

/// Parse a simple arithmetic expression (a + b or a - b)
fn parse_expression<F>(s: &str, op: F) -> Option<u64>
where
    F: Fn(u64, u64) -> u64,
{
    let (left, right) = if let Some(pos) = s.find('+') {
        (&s[..pos], &s[pos + 1..])
    } else if let Some(pos) = s.rfind('-') {
        // Use rfind to handle negative numbers correctly
        if pos == 0 {
            return None; // Just a negative number
        }
        (&s[..pos], &s[pos + 1..])
    } else {
        return None;
    };

    let left_val = parse_size(left.trim())?;
    let right_val = parse_size(right.trim())?;

    Some(op(left_val, right_val))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_number_hex() {
        assert_eq!(parse_number("0x1000"), Some(4096));
        assert_eq!(parse_number("0X1000"), Some(4096));
        assert_eq!(parse_number("0x27000"), Some(0x27000));
    }

    #[test]
    fn test_parse_number_decimal() {
        assert_eq!(parse_number("4096"), Some(4096));
        assert_eq!(parse_number("262144"), Some(262144));
    }

    #[test]
    fn test_parse_size_with_k_suffix() {
        assert_eq!(parse_size("256K"), Some(262144));
        assert_eq!(parse_size("4k"), Some(4096));
        assert_eq!(parse_size("512K"), Some(524288));
    }

    #[test]
    fn test_parse_size_with_m_suffix() {
        assert_eq!(parse_size("1M"), Some(1048576));
        assert_eq!(parse_size("2m"), Some(2097152));
    }

    #[test]
    fn test_parse_size_expression() {
        assert_eq!(parse_size("512K - 32K"), Some(491520));
        assert_eq!(parse_size("1M + 256K"), Some(1310720));
        assert_eq!(parse_size("(512K - 32K)"), Some(491520));
    }

    #[test]
    fn test_remove_comments() {
        let input = "FLASH /* comment */ (rx)";
        let output = remove_comments(input);
        assert!(output.contains("FLASH"));
        assert!(output.contains("(rx)"));
        assert!(!output.contains("comment"));
    }

    #[test]
    fn test_remove_line_comments() {
        let input = "FLASH (rx) // line comment\nRAM (rwx)";
        let output = remove_comments(input);
        assert!(output.contains("FLASH"));
        assert!(output.contains("RAM"));
        assert!(!output.contains("line comment"));
    }

    #[test]
    fn test_parse_region_standard_syntax() {
        let line = "FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512K";
        let region = parse_region_line(line).expect("Failed to parse");

        assert_eq!(region.name, "FLASH");
        assert_eq!(region.origin, 0x08000000);
        assert_eq!(region.length, 524288);
        assert_eq!(region.attributes, "rx");
    }

    #[test]
    fn test_parse_region_alternative_keywords() {
        let line = "RAM (rwx) : org = 0x20000000, len = 128K";
        let region = parse_region_line(line).expect("Failed to parse");

        assert_eq!(region.name, "RAM");
        assert_eq!(region.origin, 0x20000000);
        assert_eq!(region.length, 131072);
    }

    #[test]
    fn test_parse_region_short_keywords() {
        let line = "CCMRAM : o = 0x10000000, l = 64K";
        let region = parse_region_line(line).expect("Failed to parse");

        assert_eq!(region.name, "CCMRAM");
        assert_eq!(region.origin, 0x10000000);
        assert_eq!(region.length, 65536);
        assert_eq!(region.attributes, "");
    }

    #[test]
    fn test_parse_region_no_attributes() {
        let line = "RAM : ORIGIN = 0x20000000, LENGTH = 256K";
        let region = parse_region_line(line).expect("Failed to parse");

        assert_eq!(region.name, "RAM");
        assert_eq!(region.attributes, "");
    }

    #[test]
    fn test_parse_full_memory_block() {
        let content = r#"
        MEMORY {
            FLASH (rx)  : ORIGIN = 0x00027000, LENGTH = 0x90000
            RAM (rwx)   : ORIGIN = 0x20006000, LENGTH = 0x3A000
            NOINIT (rw) : ORIGIN = 0x20002C00, LENGTH = 0x1400
        }
        "#;

        let regions = parse_memory_regions(content).expect("Failed to parse");

        assert_eq!(regions.len(), 3);
        assert_eq!(regions[0].name, "FLASH");
        assert_eq!(regions[1].name, "RAM");
        assert_eq!(regions[2].name, "NOINIT");
    }

    #[test]
    fn test_parse_with_comments() {
        let content = r#"
        MEMORY {
            /* Application Flash */
            FLASH (rx) : ORIGIN = 0x8000, LENGTH = 512K  /* 512KB total */

            // Main SRAM
            RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 128K
        }
        "#;

        let regions = parse_memory_regions(content).expect("Failed to parse");

        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].name, "FLASH");
        assert_eq!(regions[1].name, "RAM");
    }

    #[test]
    fn test_skip_zero_length_regions() {
        let content = r#"
        MEMORY {
            FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512K
            UNUSED (r) : ORIGIN = 0x60000000, LENGTH = 0
            RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 128K
        }
        "#;

        let regions = parse_memory_regions(content).expect("Failed to parse");

        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].name, "FLASH");
        assert_eq!(regions[1].name, "RAM");
    }

    #[test]
    fn test_extract_value() {
        let line = "RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 256K";

        assert_eq!(
            extract_value(line, "ORIGIN"),
            Some("0x20000000".to_string())
        );
        assert_eq!(extract_value(line, "LENGTH"), Some("256K".to_string()));
    }

    #[test]
    fn test_nrf52840_linker_script() {
        let content = r#"
        MEMORY
        {
          FLASH (rx)     : ORIGIN = 0x00027000, LENGTH = 0x90000
          COREDUMP (rx)  : ORIGIN = 0x000b7000, LENGTH = 0x3e000
          RAM (rwx)      : ORIGIN = 0x20006000, LENGTH = 0x3A000
          NOINIT (rwx)   : ORIGIN = 0x20002C00, LENGTH = 0x1400
        }
        "#;

        let regions = parse_memory_regions(content).expect("Failed to parse");

        assert_eq!(regions.len(), 4);

        // Verify FLASH
        assert_eq!(regions[0].name, "FLASH");
        assert_eq!(regions[0].origin, 0x00027000);
        assert_eq!(regions[0].length, 0x90000);

        // Verify RAM
        let ram = regions.iter().find(|r| r.name == "RAM").unwrap();
        assert_eq!(ram.origin, 0x20006000);
        assert_eq!(ram.length, 0x3A000);
    }
}
