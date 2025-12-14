//! Core data structures for memory layout analysis
//!
//! This module defines the fundamental types used throughout MemScope
//! for representing ELF binary memory layouts, sections, symbols, and analysis results.

use serde::{Deserialize, Serialize};

/// Physical memory region (e.g., FLASH, RAM) with address and size
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Region name (e.g., "FLASH", "RAM")
    pub name: String,
    /// Starting address
    pub origin: u64,
    /// Size in bytes
    pub length: u64,
    /// Memory attributes (e.g., "rx" for read/execute)
    pub attributes: String,
}

/// Detected unused memory gap between sections
#[derive(Debug, Clone)]
pub struct MemoryGap {
    /// Start address of the gap
    pub start: u64,
    /// End address of the gap
    pub end: u64,
    /// Gap size in bytes
    pub size: u64,
    /// Which memory region type (Flash or RAM)
    pub region_type: GapRegionType,
}

/// Memory region classification for gaps
#[derive(Debug, Clone, PartialEq)]
pub enum GapRegionType {
    /// Flash/ROM memory region
    Flash,
    /// RAM memory region
    Ram,
    /// Unknown or unclassified region
    #[allow(dead_code)]
    Unknown,
}

/// Detected memory overlap between two sections (indicates a problem)
#[derive(Debug, Clone)]
pub struct MemoryOverlap {
    /// First overlapping section name
    pub section1: String,
    /// Second overlapping section name
    pub section2: String,
    /// Address where overlap starts
    pub overlap_start: u64,
    /// Address where overlap ends
    pub overlap_end: u64,
    /// Total overlap size in bytes
    pub overlap_size: u64,
}

/// Results from memory layout analysis
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Detected memory gaps (unused regions)
    pub gaps: Vec<MemoryGap>,
    /// Detected section overlaps
    pub overlaps: Vec<MemoryOverlap>,
    /// Total alignment padding in bytes
    pub total_padding: u64,
    /// Gap between stack and heap (if both exist)
    pub stack_heap_gap: Option<u64>,
    /// Generated warnings about potential issues
    pub warnings: Vec<String>,
}

/// ELF section with associated symbols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySection {
    /// Section name (e.g., ".text", ".data", ".bss")
    pub name: String,
    /// Starting address in memory
    pub address: u64,
    /// Section size in bytes
    pub size: u64,
    /// Classified section type
    pub section_type: SectionType,
    /// Symbols contained in this section
    pub symbols: Vec<Symbol>,
}

/// Classification of ELF section types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SectionType {
    /// Executable code (.text)
    Text,
    /// Read-only data (.rodata)
    RoData,
    /// Initialized data (.data)
    Data,
    /// Uninitialized data (.bss)
    Bss,
    /// Stack memory
    Stack,
    /// Heap memory
    Heap,
    /// Custom/unrecognized section
    Custom(String),
}

/// ELF symbol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    /// Symbol address in memory
    pub address: u64,
    /// Symbol size in bytes
    pub size: u64,
    /// Symbol classification
    pub symbol_type: SymbolType,
    /// Symbol binding scope
    pub binding: SymbolBinding,
    /// Symbol visibility
    pub visibility: SymbolVisibility,
    /// Index in ELF symbol table
    pub section_index: usize,
    /// Source file this symbol originated from (if available)
    pub source_file: Option<String>,
    /// Section name this symbol belongs to (e.g., ".text", ".bss", ".data")
    pub section_name: Option<String>,
}

/// ELF symbol type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolType {
    /// No type specified
    NoType,
    /// Data object / variable
    Object,
    /// Function / code
    Function,
    /// Section reference
    Section,
    /// Source file name
    File,
    /// Uninitialized common block
    Common,
    /// Thread-local storage
    Tls,
    /// Unknown symbol type
    Unknown,
}

/// ELF symbol binding scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolBinding {
    /// Local to compilation unit
    Local,
    /// Globally visible
    Global,
    /// Weak symbol (can be overridden)
    Weak,
    /// Unknown binding
    Unknown,
}

/// ELF symbol visibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolVisibility {
    /// Default visibility
    Default,
    /// Hidden from other modules
    Hidden,
    /// Protected visibility
    Protected,
    /// Internal visibility
    Internal,
}

/// Complete memory layout combining regions and sections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLayout {
    /// Memory regions (FLASH, RAM, etc.)
    pub regions: Vec<MemoryRegion>,
    /// ELF sections with symbols
    pub sections: Vec<MemorySection>,
    /// Total Flash memory used in bytes
    pub total_flash_used: u64,
    /// Total RAM used in bytes
    pub total_ram_used: u64,
    /// Total Flash size (if known/configured)
    pub flash_size: Option<u64>,
    /// Total RAM size (if known/configured)
    pub ram_size: Option<u64>,
}

impl MemoryLayout {
    /// Create a new empty memory layout
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            sections: Vec::new(),
            total_flash_used: 0,
            total_ram_used: 0,
            flash_size: None,
            ram_size: None,
        }
    }

    /// Calculate Flash usage percentage (if flash_size is set)
    pub fn flash_percentage(&self) -> Option<f64> {
        self.flash_size
            .map(|size| (self.total_flash_used as f64 / size as f64) * 100.0)
    }

    /// Calculate RAM usage percentage (if ram_size is set)
    pub fn ram_percentage(&self) -> Option<f64> {
        self.ram_size
            .map(|size| (self.total_ram_used as f64 / size as f64) * 100.0)
    }
}

impl Default for MemoryLayout {
    fn default() -> Self {
        Self::new()
    }
}

/// ARM Cortex-M Vector Table representation
#[derive(Debug, Clone)]
pub struct VectorTable {
    /// Base address of vector table (usually 0x00000000)
    pub base_address: u64,
    /// Initial stack pointer value (first entry)
    #[allow(dead_code)]
    pub initial_stack_pointer: u64,
    /// All vector entries
    pub entries: Vec<VectorEntry>,
    /// Total table size in bytes
    pub table_size: u64,
    /// Detected MCU family (if identifiable)
    pub mcu_family: Option<String>,
}

/// Single entry in the vector table
#[derive(Debug, Clone)]
pub struct VectorEntry {
    /// Offset from vector table base
    pub offset: u64,
    /// IRQ number (negative for exceptions, positive for device IRQs)
    pub irq_number: i16,
    /// Handler function address
    pub handler_address: u64,
    /// Handler function name (resolved from symbols)
    pub handler_name: Option<String>,
    /// Handler function size (from symbols)
    pub handler_size: u64,
    /// Entry classification
    pub entry_type: VectorEntryType,
    /// Entry status
    pub status: VectorStatus,
    /// Human-readable description
    pub description: String,
}

/// Vector entry type classification
#[derive(Debug, Clone, PartialEq)]
pub enum VectorEntryType {
    /// Initial stack pointer
    StackPointer,
    /// ARM core exception (NMI, HardFault, etc.)
    CoreException,
    /// Device-specific interrupt
    DeviceIRQ,
    /// Reserved/unused slot
    #[allow(dead_code)]
    Reserved,
}

/// Vector handler implementation status
#[derive(Debug, Clone, PartialEq)]
pub enum VectorStatus {
    /// Custom handler implemented
    Implemented,
    /// Uses default/weak handler stub
    DefaultHandler,
    /// Shared with another vector (alias)
    #[allow(dead_code)]
    Shared(String), // Name of the primary handler
    /// NULL or invalid pointer
    Invalid,
    /// Not assigned
    Unassigned,
}

/// Statistics about vector table usage
#[derive(Debug, Clone)]
pub struct VectorTableStats {
    /// Total number of vectors
    pub total_vectors: usize,
    /// Custom-implemented handlers
    pub custom_handlers: usize,
    /// Default/weak handlers
    pub default_handlers: usize,
    /// Shared handlers (aliases)
    pub shared_handlers: usize,
    /// Invalid/NULL handlers
    pub invalid_handlers: usize,
    /// Unassigned handlers
    pub unassigned_handlers: usize,
    /// ARM core exceptions count
    pub core_exceptions: usize,
    /// Device-specific IRQs count
    pub device_irqs: usize,
    /// Warnings about vector table issues
    pub warnings: Vec<String>,
}
