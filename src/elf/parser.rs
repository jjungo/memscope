//! ELF binary parsing for ARM embedded systems

use anyhow::{Context, Result};
use goblin::elf::{Elf, SectionHeader};
use std::fs;
use std::path::Path;

use crate::models::{
    MemoryLayout, MemoryRegion, MemorySection, SectionType, Symbol, SymbolBinding, SymbolType,
    SymbolVisibility,
};

/// Parser for ARM ELF binary files
///
/// Extracts memory layout information including sections and symbols
/// from ELF files compiled with arm-none-eabi-gcc or similar toolchains.
pub struct ElfParser {
    bytes: Vec<u8>,
}

impl ElfParser {
    /// Create a new ELF parser from a file path
    ///
    /// # Errors
    /// Returns an error if the file cannot be read
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let bytes = fs::read(&path)
            .with_context(|| format!("Failed to read ELF file: {}", path.as_ref().display()))?;

        Ok(Self { bytes })
    }

    /// Parse the ELF file and extract memory layout
    ///
    /// Returns a `MemoryLayout` containing all sections with their addresses,
    /// sizes, and contained symbols.
    ///
    /// # Arguments
    ///
    /// * `linker_regions` - Optional memory regions from linker script for accurate classification
    ///
    /// # Errors
    /// Returns an error if the ELF format is invalid or cannot be parsed
    pub fn parse(&self, linker_regions: Option<&[MemoryRegion]>) -> Result<MemoryLayout> {
        let elf = Elf::parse(&self.bytes).context("Failed to parse ELF file")?;

        let mut layout = MemoryLayout::new();

        // Parse all sections
        for section_header in &elf.section_headers {
            if let Some(section) = self.parse_section(&elf, section_header)? {
                layout.sections.push(section);
            }
        }

        // Calculate totals
        self.calculate_totals(&mut layout, linker_regions);

        Ok(layout)
    }

    /// Extract all symbols from the ELF file
    ///
    /// Returns a vector of all symbols with their metadata (name, address, size, type, etc.).
    /// Symbols are associated with their source files when possible.
    ///
    /// # Errors
    /// Returns an error if the ELF format is invalid
    pub fn parse_all_symbols(&self) -> Result<Vec<Symbol>> {
        let elf = Elf::parse(&self.bytes).context("Failed to parse ELF file")?;

        // First pass: build a map of symbol index -> source file
        // In ELF, FILE symbols declare the source file for symbols that FOLLOW them
        let mut file_map: std::collections::HashMap<usize, String> =
            std::collections::HashMap::new();
        let mut current_source_file: Option<String> = None;

        for (idx, sym) in elf.syms.iter().enumerate() {
            let st_type = goblin::elf::sym::st_type(sym.st_info);

            if st_type == 4 {
                // FILE symbol - this declares the source file for following symbols
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        // Extract just the filename, not the full path
                        let filename = name.rsplit('/').next().unwrap_or(name).to_string();
                        current_source_file = Some(filename);
                    } else {
                        // Empty FILE symbol - clear current source file context
                        current_source_file = None;
                    }
                }
            } else {
                // Non-FILE symbol - associate with current source file
                if let Some(ref file) = current_source_file {
                    file_map.insert(idx, file.clone());
                }
            }
        }

        // Second pass: create Symbol objects
        let mut symbols = Vec::new();

        for (idx, sym) in elf.syms.iter().enumerate() {
            let st_type = goblin::elf::sym::st_type(sym.st_info);

            // Skip FILE symbols
            if st_type == 4 {
                continue;
            }

            // Skip symbols with no size or no name
            if sym.st_size == 0 {
                continue;
            }

            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name.is_empty() {
                    continue;
                }

                let st_bind = goblin::elf::sym::st_bind(sym.st_info);

                symbols.push(Symbol {
                    name: name.to_string(),
                    address: sym.st_value,
                    size: sym.st_size,
                    symbol_type: self.classify_symbol_type(st_type),
                    binding: self.classify_symbol_binding(st_bind),
                    visibility: self.classify_symbol_visibility(sym.st_other),
                    section_index: idx,
                    source_file: file_map.get(&idx).cloned(),
                });
            }
        }

        Ok(symbols)
    }

    fn parse_section(&self, elf: &Elf, header: &SectionHeader) -> Result<Option<MemorySection>> {
        use goblin::elf::section_header::SHF_ALLOC;

        let name = elf
            .shdr_strtab
            .get_at(header.sh_name)
            .unwrap_or("")
            .to_string();

        // Skip empty sections, non-allocatable sections, and sections without SHF_ALLOC flag
        // SHF_ALLOC means the section occupies memory during execution
        // Sections without this flag (like NOLOAD sections) don't consume runtime memory
        if header.sh_size == 0 || header.sh_addr == 0 || (header.sh_flags & (SHF_ALLOC as u64)) == 0
        {
            return Ok(None);
        }

        let section_type = self.classify_section(&name, header);

        let symbols = self.extract_symbols_for_section(elf, header)?;

        Ok(Some(MemorySection {
            name,
            address: header.sh_addr,
            size: header.sh_size,
            section_type,
            symbols,
        }))
    }

    fn classify_section(&self, name: &str, header: &SectionHeader) -> SectionType {
        use goblin::elf::section_header::*;

        match name {
            n if n.starts_with(".text") => SectionType::Text,
            n if n.starts_with(".rodata") => SectionType::RoData,
            n if n.starts_with(".data") => SectionType::Data,
            n if n.starts_with(".bss") => SectionType::Bss,
            ".stack" | "._stack" => SectionType::Stack,
            ".heap" | "._heap" => SectionType::Heap,
            _ => {
                // Try to classify by flags
                if header.sh_flags & (SHF_EXECINSTR as u64) != 0 {
                    SectionType::Text
                } else if header.sh_flags & (SHF_WRITE as u64) != 0 {
                    if header.sh_type == SHT_NOBITS {
                        SectionType::Bss
                    } else {
                        SectionType::Data
                    }
                } else {
                    SectionType::Custom(name.to_string())
                }
            }
        }
    }

    fn extract_symbols_for_section(
        &self,
        elf: &Elf,
        section_header: &SectionHeader,
    ) -> Result<Vec<Symbol>> {
        let mut symbols = Vec::new();

        for (idx, sym) in elf.syms.iter().enumerate() {
            // Check if symbol belongs to this section
            if sym.st_shndx == section_header.sh_name
                && sym.st_size > 0
                && let Some(name) = elf.strtab.get_at(sym.st_name)
            {
                let st_type = goblin::elf::sym::st_type(sym.st_info);
                let st_bind = goblin::elf::sym::st_bind(sym.st_info);

                symbols.push(Symbol {
                    name: name.to_string(),
                    address: sym.st_value,
                    size: sym.st_size,
                    symbol_type: self.classify_symbol_type(st_type),
                    binding: self.classify_symbol_binding(st_bind),
                    visibility: self.classify_symbol_visibility(sym.st_other),
                    section_index: idx,
                    source_file: None, // Not tracking source files for section symbols
                });
            }
        }

        Ok(symbols)
    }

    fn classify_symbol_type(&self, st_type: u8) -> SymbolType {
        match st_type {
            0 => SymbolType::NoType,   // STT_NOTYPE
            1 => SymbolType::Object,   // STT_OBJECT
            2 => SymbolType::Function, // STT_FUNC
            3 => SymbolType::Section,  // STT_SECTION
            4 => SymbolType::File,     // STT_FILE
            5 => SymbolType::Common,   // STT_COMMON
            6 => SymbolType::Tls,      // STT_TLS
            _ => SymbolType::Unknown,
        }
    }

    fn classify_symbol_binding(&self, st_bind: u8) -> SymbolBinding {
        match st_bind {
            0 => SymbolBinding::Local,  // STB_LOCAL
            1 => SymbolBinding::Global, // STB_GLOBAL
            2 => SymbolBinding::Weak,   // STB_WEAK
            _ => SymbolBinding::Unknown,
        }
    }

    fn classify_symbol_visibility(&self, st_vis: u8) -> SymbolVisibility {
        match st_vis & 0x3 {
            // Visibility is in lower 2 bits
            0 => SymbolVisibility::Default,   // STV_DEFAULT
            1 => SymbolVisibility::Internal,  // STV_INTERNAL
            2 => SymbolVisibility::Hidden,    // STV_HIDDEN
            3 => SymbolVisibility::Protected, // STV_PROTECTED
            _ => SymbolVisibility::Default,
        }
    }

    fn calculate_totals(&self, layout: &mut MemoryLayout, linker_regions: Option<&[MemoryRegion]>) {
        let mut flash_used = 0u64;
        let mut ram_used = 0u64;

        // Extract memory region ranges from linker script if provided
        let (ram_regions, flash_regions) = if let Some(regions) = linker_regions {
            let (ram, flash) = extract_memory_regions(regions);
            // If linker script produced no usable regions (need BOTH RAM and Flash), fall back to auto-detect
            if ram.is_empty() || flash.is_empty() {
                detect_memory_regions_from_sections(&layout.sections)
            } else {
                (ram, flash)
            }
        } else {
            // Auto-detect memory regions from section addresses
            detect_memory_regions_from_sections(&layout.sections)
        };

        for section in &layout.sections {
            // Sections are already filtered by SHF_ALLOC flag in parse_section()
            // so we only see sections that actually occupy runtime memory

            match section.section_type {
                SectionType::Text | SectionType::RoData => {
                    // Code and read-only data always go to Flash
                    flash_used += section.size;
                }
                SectionType::Data => {
                    // .data takes space in both flash (initialization data) and RAM (runtime copy)
                    flash_used += section.size;
                    // Only count in RAM if section is within defined RAM regions
                    if is_in_regions(section.address, &ram_regions) {
                        ram_used += section.size;
                    }
                }
                SectionType::Bss | SectionType::Stack | SectionType::Heap => {
                    // Uninitialized data, stack, and heap only consume RAM
                    // Only count if section is within defined RAM regions
                    if is_in_regions(section.address, &ram_regions) {
                        ram_used += section.size;
                    }
                }
                SectionType::Custom(ref name) => {
                    // For custom sections, classify by address and name hints
                    // Skip vendor-specific non-volatile config sections
                    if name.contains("uicr")       // Nordic User Information Configuration Registers
                        || name.contains("ficr")    // Factory Information Configuration Registers
                        || name.contains("bootloader")
                    {
                        continue;
                    }

                    // Classify by memory regions
                    if is_in_regions(section.address, &ram_regions) {
                        ram_used += section.size;
                    } else if is_in_regions(section.address, &flash_regions) {
                        flash_used += section.size;
                    }
                }
            }
        }

        layout.total_flash_used = flash_used;
        layout.total_ram_used = ram_used;
    }

    /// Get ELF header information as a formatted string
    ///
    /// Returns details about the ELF binary including machine type,
    /// entry point, and counts of sections and symbols.
    ///
    /// # Errors
    /// Returns an error if the ELF format is invalid
    pub fn get_elf_info(&self) -> Result<String> {
        let elf = Elf::parse(&self.bytes).context("Failed to parse ELF file")?;

        Ok(format!(
            "ELF Header:\n\
             - Machine: {:?}\n\
             - Entry point: 0x{:08x}\n\
             - Section count: {}\n\
             - Symbol count: {}",
            elf.header.e_machine,
            elf.header.e_entry,
            elf.section_headers.len(),
            elf.syms.len()
        ))
    }

    /// Get raw ELF bytes for vector table parsing
    ///
    /// # Returns
    /// Returns a reference to the raw ELF binary data
    pub fn get_bytes(&self) -> Result<&[u8]> {
        Ok(&self.bytes)
    }
}

/// Memory address range (start, end)
type MemoryRange = (u64, u64);

/// Extract RAM and Flash memory regions from linker script regions
///
/// Returns (ram_regions, flash_regions) as vectors of (start, end) address ranges
fn extract_memory_regions(regions: &[MemoryRegion]) -> (Vec<MemoryRange>, Vec<MemoryRange>) {
    let mut ram_regions = Vec::new();
    let mut flash_regions = Vec::new();

    for region in regions {
        let range = (region.origin, region.origin + region.length);

        // Classify region by name and attributes
        let name_lower = region.name.to_lowercase();

        // RAM regions: contains "ram", "sram", "tcm", or has write attribute
        if name_lower.contains("ram")
            || name_lower.contains("sram")
            || name_lower.contains("tcm")
            || name_lower.contains("ccm")
        {
            // Only include regions that are intended for application use
            // Exclude special-purpose regions by default
            if !name_lower.contains("noinit")
                && !name_lower.contains("spim")
                && !name_lower.contains("dma")
                && !name_lower.contains("shared")
                && !name_lower.contains("bootloader")
            {
                ram_regions.push(range);
            }
        }
        // Flash regions: contains "flash", "rom", or has execute attribute
        else if name_lower.contains("flash")
            || name_lower.contains("rom")
            || name_lower.contains("text")
            || region.attributes.contains('x')
        {
            // Exclude coredump and other special flash regions
            if !name_lower.contains("coredump")
                && !name_lower.contains("bootloader")
                && !name_lower.contains("uicr")
            {
                flash_regions.push(range);
            }
        }
    }

    // If no regions classified by name, fall back to address-based classification
    if ram_regions.is_empty() && flash_regions.is_empty() {
        for region in regions {
            let range = (region.origin, region.origin + region.length);

            // ARM Cortex-M standard: RAM is 0x20000000-0x40000000
            if region.origin >= 0x20000000 && region.origin < 0x40000000 {
                ram_regions.push(range);
            } else if region.origin < 0x20000000 {
                flash_regions.push(range);
            }
        }
    }

    (ram_regions, flash_regions)
}

/// Check if an address is within any of the given memory regions
fn is_in_regions(address: u64, regions: &[MemoryRange]) -> bool {
    regions
        .iter()
        .any(|(start, end)| address >= *start && address < *end)
}

/// Auto-detect memory regions from actual section addresses
///
/// This finds the contiguous main application regions by:
/// 1. Finding the lowest and highest Flash sections
/// 2. Finding the main RAM region (largest contiguous block)
///
/// Returns (ram_regions, flash_regions)
fn detect_memory_regions_from_sections(
    sections: &[MemorySection],
) -> (Vec<MemoryRange>, Vec<MemoryRange>) {
    use crate::models::SectionType;

    let mut flash_sections: Vec<(u64, u64)> = Vec::new();
    let mut ram_sections: Vec<(u64, u64)> = Vec::new();

    // Collect Flash and RAM section address ranges
    // Also find the lowest address of main application sections (.data, .bss)
    let mut app_ram_start = None;

    for section in sections {
        let range = (section.address, section.address + section.size);

        match section.section_type {
            SectionType::Text | SectionType::RoData => {
                flash_sections.push(range);
            }
            SectionType::Data | SectionType::Bss | SectionType::Stack | SectionType::Heap => {
                ram_sections.push(range);

                // .data sections mark the start of application RAM
                // (excludes special regions like NOINIT which are Bss type)
                if matches!(section.section_type, SectionType::Data) {
                    app_ram_start = Some(
                        app_ram_start
                            .map_or(section.address, |addr: u64| addr.min(section.address)),
                    );
                }
            }
            _ => {}
        }
    }

    // Find Flash region: lowest to highest Flash section
    let flash_region = if !flash_sections.is_empty() {
        let min_addr = flash_sections
            .iter()
            .map(|(start, _)| *start)
            .min()
            .unwrap();
        let max_addr = flash_sections.iter().map(|(_, end)| *end).max().unwrap();
        vec![(min_addr, max_addr)]
    } else {
        vec![(0x00000000, 0x20000000)] // Fallback to ARM standard
    };

    // Find main RAM region
    // If we found application RAM start (.data/.bss), use that as the lower bound
    // Otherwise use the lowest RAM section
    ram_sections.sort_by_key(|(start, _)| *start);

    let ram_region = if !ram_sections.is_empty() {
        let min_addr = if let Some(app_start) = app_ram_start {
            // Use application RAM start, filtering out sections before it
            app_start
        } else {
            // Fallback: use lowest RAM section
            ram_sections.iter().map(|(start, _)| *start).min().unwrap()
        };

        let max_addr = ram_sections.iter().map(|(_, end)| *end).max().unwrap();
        vec![(min_addr, max_addr)]
    } else {
        vec![(0x20000000, 0x40000000)] // Fallback to ARM standard
    };

    (ram_region, flash_region)
}
