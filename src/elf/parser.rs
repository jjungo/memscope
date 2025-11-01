//! ELF binary parsing for ARM embedded systems

use anyhow::{Context, Result};
use goblin::elf::{Elf, SectionHeader};
use std::fs;
use std::path::Path;

use crate::models::{
    MemoryLayout, MemorySection, SectionType, Symbol, SymbolBinding, SymbolType, SymbolVisibility,
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
    /// # Errors
    /// Returns an error if the ELF format is invalid or cannot be parsed
    pub fn parse(&self) -> Result<MemoryLayout> {
        let elf = Elf::parse(&self.bytes).context("Failed to parse ELF file")?;

        let mut layout = MemoryLayout::new();

        // Parse all sections
        for section_header in &elf.section_headers {
            if let Some(section) = self.parse_section(&elf, section_header)? {
                layout.sections.push(section);
            }
        }

        // Calculate totals
        self.calculate_totals(&mut layout);

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
        let mut file_map: std::collections::HashMap<usize, String> =
            std::collections::HashMap::new();
        let mut current_source_file: Option<String> = None;
        let mut last_file_index = 0;
        let mut saw_empty_file = false;

        for (idx, sym) in elf.syms.iter().enumerate() {
            let st_type = goblin::elf::sym::st_type(sym.st_info);

            if st_type == 4 {
                // FILE symbol
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        // Extract just the filename, not the full path
                        let filename = name.rsplit('/').next().unwrap_or(name).to_string();

                        // Associate symbols since the last FILE marker with this file
                        // But only if we haven't seen an empty FILE symbol
                        for i in last_file_index..idx {
                            if !file_map.contains_key(&i) && !saw_empty_file {
                                file_map.insert(i, filename.clone());
                            }
                        }

                        current_source_file = Some(filename);
                        last_file_index = idx;
                        saw_empty_file = false;
                    } else {
                        // Empty FILE symbol - marks uncertain boundary
                        saw_empty_file = true;
                    }
                }
            }
        }

        // Associate remaining symbols with the last file only if we didn't see empty FILE
        if !saw_empty_file && let Some(ref file) = current_source_file {
            for i in last_file_index..elf.syms.len() {
                file_map.entry(i).or_insert_with(|| file.clone());
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
        let name = elf
            .shdr_strtab
            .get_at(header.sh_name)
            .unwrap_or("")
            .to_string();

        // Skip empty sections and non-allocatable sections
        if header.sh_size == 0 || header.sh_addr == 0 {
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

    fn calculate_totals(&self, layout: &mut MemoryLayout) {
        let mut flash_used = 0u64;
        let mut ram_used = 0u64;

        for section in &layout.sections {
            match section.section_type {
                SectionType::Text | SectionType::RoData => {
                    flash_used += section.size;
                }
                SectionType::Data => {
                    // .data takes space in both flash (initialization) and RAM
                    flash_used += section.size;
                    ram_used += section.size;
                }
                SectionType::Bss | SectionType::Stack | SectionType::Heap => {
                    ram_used += section.size;
                }
                SectionType::Custom(_) => {
                    // For custom sections, assume RAM unless it looks like flash
                    if section.name.contains("flash") || section.name.contains("rom") {
                        flash_used += section.size;
                    } else {
                        ram_used += section.size;
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
}
