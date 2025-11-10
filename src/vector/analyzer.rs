//! Vector table analysis and statistics generation

use crate::models::{VectorEntryType, VectorStatus, VectorTable, VectorTableStats};
use crate::vector::database::ArmDatabase;
use std::collections::HashMap;

/// Analyzer for vector table statistics and warnings
pub struct VectorAnalyzer {
    db: ArmDatabase,
}

impl VectorAnalyzer {
    /// Create a new vector analyzer
    pub fn new() -> Self {
        Self {
            db: ArmDatabase::new(),
        }
    }

    /// Analyze a vector table and generate statistics
    pub fn analyze(&self, vector_table: &mut VectorTable) -> VectorTableStats {
        let mut stats = VectorTableStats {
            total_vectors: vector_table.entries.len(),
            custom_handlers: 0,
            default_handlers: 0,
            shared_handlers: 0,
            invalid_handlers: 0,
            unassigned_handlers: 0,
            core_exceptions: 0,
            device_irqs: 0,
            warnings: Vec::new(),
        };

        // Track addresses for shared handler detection
        let mut handler_addresses: HashMap<u64, Vec<usize>> = HashMap::new();

        for (idx, entry) in vector_table.entries.iter().enumerate() {
            // Skip stack pointer entry
            if entry.entry_type == VectorEntryType::StackPointer {
                continue;
            }

            // Track addresses for shared handler detection (before marking as shared)
            if entry.handler_address != 0 && entry.handler_address != 0xFFFFFFFF {
                handler_addresses
                    .entry(entry.handler_address)
                    .or_default()
                    .push(idx);
            }
        }

        // Mark shared handlers
        self.mark_shared_handlers(vector_table, &handler_addresses);

        // Now count by status and type
        for entry in vector_table.entries.iter() {
            // Skip stack pointer entry
            if entry.entry_type == VectorEntryType::StackPointer {
                continue;
            }

            // Count by type
            match entry.entry_type {
                VectorEntryType::CoreException => stats.core_exceptions += 1,
                VectorEntryType::DeviceIRQ => stats.device_irqs += 1,
                _ => {}
            }

            // Count by status
            match &entry.status {
                VectorStatus::Implemented => stats.custom_handlers += 1,
                VectorStatus::DefaultHandler => stats.default_handlers += 1,
                VectorStatus::Shared(_) => stats.shared_handlers += 1,
                VectorStatus::Invalid => stats.invalid_handlers += 1,
                VectorStatus::Unassigned => stats.unassigned_handlers += 1,
            }
        }

        // Generate warnings about shared handlers
        stats
            .warnings
            .extend(self.detect_shared_handlers(vector_table, &handler_addresses));

        // Check for critical missing handlers
        stats
            .warnings
            .extend(self.check_critical_handlers(vector_table));

        // Check for invalid handlers
        stats
            .warnings
            .extend(self.check_invalid_handlers(vector_table));

        // Check for oversized handlers
        stats
            .warnings
            .extend(self.check_oversized_handlers(vector_table));

        // Check vector table alignment
        if let Some(warning) = self.check_alignment(vector_table) {
            stats.warnings.push(warning);
        }

        stats
    }

    /// Mark handlers that are shared between multiple vectors
    fn mark_shared_handlers(
        &self,
        vector_table: &mut VectorTable,
        handler_addresses: &HashMap<u64, Vec<usize>>,
    ) {
        for (addr, indices) in handler_addresses {
            if indices.len() > 1 {
                // Find the primary handler (first one, or one with a real name)
                let primary_idx = *indices.first().unwrap();
                let primary_name = vector_table.entries[primary_idx]
                    .handler_name
                    .clone()
                    .unwrap_or_else(|| format!("0x{:08x}", addr));

                // Mark all entries at this address as shared
                for &idx in indices {
                    if let Some(entry) = vector_table.entries.get_mut(idx) {
                        // Only mark as shared if it's not already marked as something more specific
                        if matches!(
                            entry.status,
                            VectorStatus::Implemented | VectorStatus::DefaultHandler
                        ) {
                            entry.status = VectorStatus::Shared(primary_name.clone());
                        }
                    }
                }
            }
        }
    }

    /// Detect handlers that are shared between multiple vectors
    fn detect_shared_handlers(
        &self,
        vector_table: &VectorTable,
        handler_addresses: &HashMap<u64, Vec<usize>>,
    ) -> Vec<String> {
        let mut warnings = Vec::new();

        for (addr, indices) in handler_addresses {
            if indices.len() > 1 {
                // Multiple vectors point to same handler
                let handler_names: Vec<String> = indices
                    .iter()
                    .filter_map(|&idx| {
                        let entry = &vector_table.entries[idx];
                        entry
                            .handler_name
                            .as_ref()
                            .map(|n| format!("{} (IRQ {})", n, entry.irq_number))
                    })
                    .collect();

                if !handler_names.is_empty() {
                    warnings.push(format!(
                        "Shared handler at 0x{:08x}: {} vectors share the same implementation: {}",
                        addr,
                        indices.len(),
                        handler_names.join(", ")
                    ));
                }
            }
        }

        warnings
    }

    /// Check for critical exception handlers that should be implemented
    fn check_critical_handlers(&self, vector_table: &VectorTable) -> Vec<String> {
        let mut warnings = Vec::new();

        for entry in &vector_table.entries {
            if self.db.is_critical_exception(entry.irq_number) {
                match &entry.status {
                    VectorStatus::DefaultHandler => {
                        warnings.push(format!(
                            "CRITICAL: {} (IRQ {}) uses default handler - will infinite loop on fault!",
                            entry.description, entry.irq_number
                        ));
                    }
                    VectorStatus::Invalid => {
                        warnings.push(format!(
                            "CRITICAL: {} (IRQ {}) has invalid/NULL handler - will crash!",
                            entry.description, entry.irq_number
                        ));
                    }
                    VectorStatus::Unassigned => {
                        warnings.push(format!(
                            "WARNING: {} (IRQ {}) has no named handler",
                            entry.description, entry.irq_number
                        ));
                    }
                    _ => {}
                }
            }
        }

        warnings
    }

    /// Check for invalid handler addresses
    fn check_invalid_handlers(&self, vector_table: &VectorTable) -> Vec<String> {
        let mut warnings = Vec::new();

        for entry in &vector_table.entries {
            if entry.entry_type == VectorEntryType::StackPointer {
                continue;
            }

            if entry.handler_address == 0 {
                warnings.push(format!(
                    "ERROR: {} (IRQ {}) has NULL handler address",
                    entry.description, entry.irq_number
                ));
            } else if entry.handler_address == 0xFFFFFFFF {
                warnings.push(format!(
                    "ERROR: {} (IRQ {}) has invalid handler address (0xFFFFFFFF)",
                    entry.description, entry.irq_number
                ));
            }
        }

        warnings
    }

    /// Check for handlers that are unusually large
    fn check_oversized_handlers(&self, vector_table: &VectorTable) -> Vec<String> {
        let mut warnings = Vec::new();
        const LARGE_HANDLER_THRESHOLD: u64 = 512;

        for entry in &vector_table.entries {
            if entry.handler_size > LARGE_HANDLER_THRESHOLD {
                warnings.push(format!(
                    "WARNING: {} handler is very large ({} bytes) - consider offloading work to a task",
                    entry.handler_name.as_deref().unwrap_or("Unknown"),
                    entry.handler_size
                ));
            }
        }

        warnings
    }

    /// Check vector table alignment
    fn check_alignment(&self, vector_table: &VectorTable) -> Option<String> {
        // Vector table must be aligned to a power-of-2 that is >= table size
        let table_size = vector_table.table_size;
        let required_alignment = table_size.next_power_of_two();

        if !vector_table.base_address.is_multiple_of(required_alignment) {
            Some(format!(
                "ERROR: Vector table at 0x{:08x} is misaligned! \
                 Required alignment: {} bytes (table size: {} bytes)",
                vector_table.base_address, required_alignment, table_size
            ))
        } else {
            None
        }
    }

    /// Get statistics summary as formatted string
    #[allow(dead_code)]
    pub fn format_stats(&self, stats: &VectorTableStats) -> String {
        let mut output = String::new();

        output.push_str(&format!("Total Vectors:       {}\n", stats.total_vectors));
        output.push_str(&format!(
            "Custom Handlers:     {} ({:.1}%)\n",
            stats.custom_handlers,
            (stats.custom_handlers as f64 / stats.total_vectors as f64) * 100.0
        ));
        output.push_str(&format!(
            "Default Handlers:    {} ({:.1}%)\n",
            stats.default_handlers,
            (stats.default_handlers as f64 / stats.total_vectors as f64) * 100.0
        ));
        output.push_str(&format!(
            "Shared Handlers:     {} ({:.1}%)\n",
            stats.shared_handlers,
            (stats.shared_handlers as f64 / stats.total_vectors as f64) * 100.0
        ));
        output.push_str(&format!(
            "Invalid Handlers:    {}\n",
            stats.invalid_handlers
        ));
        output.push_str(&format!(
            "Unassigned Handlers: {}\n",
            stats.unassigned_handlers
        ));
        output.push_str(&format!(
            "\nCore Exceptions:     {}\n",
            stats.core_exceptions
        ));
        output.push_str(&format!("Device IRQs:         {}\n", stats.device_irqs));

        if !stats.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &stats.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        output
    }
}

impl Default for VectorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{VectorEntry, VectorEntryType, VectorStatus, VectorTable};

    #[test]
    fn test_analyzer_basic() {
        let analyzer = VectorAnalyzer::new();

        let entries = vec![
            VectorEntry {
                offset: 0,
                irq_number: 0,
                handler_address: 0x20010000,
                handler_name: Some("__stack_top__".to_string()),
                handler_size: 0,
                entry_type: VectorEntryType::StackPointer,
                status: VectorStatus::Unassigned,
                description: "Initial Stack Pointer".to_string(),
            },
            VectorEntry {
                offset: 4,
                irq_number: -15,
                handler_address: 0x08000100,
                handler_name: Some("Reset_Handler".to_string()),
                handler_size: 64,
                entry_type: VectorEntryType::CoreException,
                status: VectorStatus::Implemented,
                description: "Reset Handler".to_string(),
            },
        ];

        let mut table = VectorTable {
            base_address: 0x08000000,
            initial_stack_pointer: 0x20010000,
            entries,
            table_size: 256,
            mcu_family: None,
        };

        let stats = analyzer.analyze(&mut table);
        assert_eq!(stats.total_vectors, 2);
        assert_eq!(stats.custom_handlers, 1);
        assert_eq!(stats.core_exceptions, 1);
    }
}
