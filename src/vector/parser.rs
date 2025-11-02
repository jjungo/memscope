//! Vector table parsing from ARM ELF binaries

use anyhow::{Context, Result, anyhow};
use goblin::elf::Elf;

use crate::models::{Symbol, VectorEntry, VectorEntryType, VectorStatus, VectorTable};
use crate::vector::database::ArmDatabase;

/// Parser for ARM Cortex-M interrupt vector tables
pub struct VectorTableParser {
    db: ArmDatabase,
}

impl VectorTableParser {
    /// Create a new vector table parser
    pub fn new() -> Self {
        Self {
            db: ArmDatabase::new(),
        }
    }

    /// Parse vector table from ELF binary
    ///
    /// Looks for common vector table section names and parses the entries
    ///
    /// # Arguments
    ///
    /// * `elf_bytes` - Raw ELF binary data
    /// * `all_symbols` - All symbols from the ELF (for resolving handler names)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(VectorTable))` if a vector table is found,
    /// `Ok(None)` if no vector table section exists,
    /// or `Err` if parsing fails
    pub fn parse(&self, elf_bytes: &[u8], all_symbols: &[Symbol]) -> Result<Option<VectorTable>> {
        let elf = Elf::parse(elf_bytes).context("Failed to parse ELF file")?;

        // Try to find vector table section
        let vector_section = self.find_vector_section(&elf)?;

        let Some((section_header, _section_name)) = vector_section else {
            return Ok(None);
        };

        let base_address = section_header.sh_addr;
        let mut section_size = section_header.sh_size;
        let section_offset = section_header.sh_offset as usize;

        // If this is .text section, we need to determine where the vector table ends
        // Vector tables are typically 256-512 bytes for most ARM Cortex-M MCUs
        // We'll limit to a reasonable maximum and detect the actual end
        if _section_name == ".text" {
            // For ARM Cortex-M, vector tables are usually:
            // - 16 core exceptions + N device IRQs
            // - Common sizes: 48 (nRF51), 64 (STM32F0), 98 (STM32F1), 114 (STM32F4), etc.
            // Let's limit to first 1KB (256 vectors max) to avoid parsing entire .text
            section_size = section_size.min(1024);
        }

        // Extract raw bytes of the vector table
        let vector_bytes = &elf_bytes[section_offset..section_offset + section_size as usize];

        // Parse vector entries (each is 4 bytes / 32-bit)
        let mut entries = Vec::new();

        // First entry is initial stack pointer
        if vector_bytes.len() < 4 {
            return Err(anyhow!("Vector table too small (< 4 bytes)"));
        }

        let initial_sp = u32::from_le_bytes([
            vector_bytes[0],
            vector_bytes[1],
            vector_bytes[2],
            vector_bytes[3],
        ]) as u64;

        entries.push(VectorEntry {
            offset: 0,
            irq_number: 0, // Special case for stack pointer
            handler_address: initial_sp,
            handler_name: Some("__stack_top__".to_string()),
            handler_size: 0,
            entry_type: VectorEntryType::StackPointer,
            status: VectorStatus::Unassigned,
            description: "Initial Stack Pointer".to_string(),
        });

        // Parse remaining entries (handlers)
        let num_vectors = (section_size as usize) / 4;
        for i in 1..num_vectors {
            let offset = (i * 4) as u64;
            let handler_addr = u32::from_le_bytes([
                vector_bytes[i * 4],
                vector_bytes[i * 4 + 1],
                vector_bytes[i * 4 + 2],
                vector_bytes[i * 4 + 3],
            ]) as u64;

            // IRQ number: first handler (Reset) is IRQ -15
            // Then NMI is -14, HardFault is -13, etc.
            let irq_number = (i as i16) - 16;

            // Determine entry type
            let entry_type = if self.db.is_core_exception(irq_number) {
                VectorEntryType::CoreException
            } else {
                VectorEntryType::DeviceIRQ
            };

            // Try to resolve handler name and size from symbols
            let (handler_name, handler_size, status) =
                self.resolve_handler(handler_addr, all_symbols);

            let description = self.db.get_description(irq_number);

            entries.push(VectorEntry {
                offset,
                irq_number,
                handler_address: handler_addr,
                handler_name,
                handler_size,
                entry_type,
                status,
                description,
            });
        }

        // Detect MCU family from vector count
        let mcu_family = self.db.detect_mcu_family(num_vectors);

        Ok(Some(VectorTable {
            base_address,
            initial_stack_pointer: initial_sp,
            entries,
            table_size: section_size,
            mcu_family,
        }))
    }

    /// Find the vector table section in the ELF
    fn find_vector_section<'a>(
        &self,
        elf: &'a Elf,
    ) -> Result<Option<(&'a goblin::elf::SectionHeader, String)>> {
        // Common vector table section names
        let vector_section_names = [
            ".isr_vector",
            ".vectors",
            ".vector_table",
            ".isr_vectors",
            ".intvec",
        ];

        for section_header in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section_header.sh_name)
                && vector_section_names.contains(&name)
            {
                return Ok(Some((section_header, name.to_string())));
            }
        }

        // Fallback: Check if .text section starts with a vector table
        // (common in Nordic nRF and other MCUs where vectors are embedded in .text)
        for section_header in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section_header.sh_name)
                && name == ".text"
            {
                // Vector tables typically start at Flash base (0x00000000 or 0x08000000 for STM32)
                // or at a bootloader offset (like 0x00027000 for nRF with softdevice)
                // We'll accept .text sections that look like they contain vectors
                return Ok(Some((section_header, name.to_string())));
            }
        }

        Ok(None)
    }

    /// Resolve handler name and size from symbol table
    ///
    /// Returns (handler_name, handler_size, status)
    fn resolve_handler(
        &self,
        handler_addr: u64,
        all_symbols: &[Symbol],
    ) -> (Option<String>, u64, VectorStatus) {
        // Handle NULL or invalid addresses
        if handler_addr == 0 || handler_addr == 0xFFFFFFFF {
            return (None, 0, VectorStatus::Invalid);
        }

        // ARM Thumb mode uses LSB = 1 for function pointers
        // Both the vector table AND the ELF symbols have this bit set
        // So we can compare directly, OR mask both sides
        // Let's try both with and without the bit for robustness
        let addr_with_thumb = handler_addr;
        let addr_without_thumb = handler_addr & !1;

        // Find symbol at this address (try both with and without Thumb bit)
        if let Some(symbol) = all_symbols
            .iter()
            .find(|s| s.address == addr_with_thumb || s.address == addr_without_thumb)
        {
            let name = symbol.name.clone();
            let size = symbol.size;

            // Determine if it's a default handler
            let status = if self.db.is_default_handler_name(&name) {
                VectorStatus::DefaultHandler
            } else {
                VectorStatus::Implemented
            };

            (Some(name), size, status)
        } else {
            // No symbol found - likely points to code without a named symbol
            (None, 0, VectorStatus::Unassigned)
        }
    }
}

impl Default for VectorTableParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let parser = VectorTableParser::new();
        assert!(parser.db.is_core_exception(-13)); // HardFault
    }

    #[test]
    fn test_irq_numbering() {
        // Reset handler is at offset 0x04 (index 1)
        // IRQ number should be 1 - 16 = -15
        let irq = (1 as i16) - 16;
        assert_eq!(irq, -15);
    }
}
