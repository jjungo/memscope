//! MCU-specific knowledge database for ARM Cortex-M vector tables
//!
//! Contains standard ARM exception names and descriptions,
//! as well as device-specific IRQ information for common MCU families.

use std::collections::HashMap;

/// ARM Cortex-M exception/IRQ database
pub struct ArmDatabase {
    /// Maps IRQ number to human-readable description
    exception_descriptions: HashMap<i16, &'static str>,
}

impl ArmDatabase {
    /// Create a new ARM exception database
    pub fn new() -> Self {
        let mut db = Self {
            exception_descriptions: HashMap::new(),
        };
        db.initialize_core_exceptions();
        db
    }

    /// Initialize standard ARM Cortex-M core exception descriptions
    fn initialize_core_exceptions(&mut self) {
        // IRQ numbers are offset by 16 for ARM exceptions
        // Exception number = IRQ number + 16
        // So Reset (exception 1) = IRQ -15
        self.exception_descriptions.insert(-15, "Reset Handler");
        self.exception_descriptions
            .insert(-14, "Non-Maskable Interrupt (NMI)");
        self.exception_descriptions
            .insert(-13, "Hard Fault Handler");
        self.exception_descriptions
            .insert(-12, "Memory Management Fault");
        self.exception_descriptions.insert(-11, "Bus Fault Handler");
        self.exception_descriptions
            .insert(-10, "Usage Fault Handler");
        // -9 to -6 are reserved
        self.exception_descriptions
            .insert(-5, "Supervisor Call (SVCall)");
        self.exception_descriptions.insert(-4, "Debug Monitor");
        // -3 is reserved
        self.exception_descriptions
            .insert(-2, "Pendable Service Request (PendSV)");
        self.exception_descriptions
            .insert(-1, "System Tick Timer (SysTick)");
    }

    /// Get description for an IRQ number
    pub fn get_description(&self, irq_number: i16) -> String {
        if let Some(&desc) = self.exception_descriptions.get(&irq_number) {
            desc.to_string()
        } else if irq_number >= 0 {
            format!("Device IRQ {}", irq_number)
        } else if (-9..=-6).contains(&irq_number) || irq_number == -3 {
            "Reserved".to_string()
        } else {
            "Unknown Exception".to_string()
        }
    }

    /// Check if IRQ is a core ARM exception
    pub fn is_core_exception(&self, irq_number: i16) -> bool {
        irq_number < 0
    }

    /// Check if IRQ is a critical exception that should be implemented
    pub fn is_critical_exception(&self, irq_number: i16) -> bool {
        matches!(irq_number, -15..=-10)
    }

    /// Get handler name suggestion for an IRQ number
    #[allow(dead_code)]
    pub fn get_handler_name_hint(&self, irq_number: i16) -> Option<&'static str> {
        match irq_number {
            -15 => Some("Reset_Handler"),
            -14 => Some("NMI_Handler"),
            -13 => Some("HardFault_Handler"),
            -12 => Some("MemManage_Handler"),
            -11 => Some("BusFault_Handler"),
            -10 => Some("UsageFault_Handler"),
            -5 => Some("SVC_Handler"),
            -4 => Some("DebugMon_Handler"),
            -2 => Some("PendSV_Handler"),
            -1 => Some("SysTick_Handler"),
            _ => None,
        }
    }

    /// Detect MCU family from vector table size
    pub fn detect_mcu_family(&self, vector_count: usize) -> Option<String> {
        match vector_count {
            // STM32 families
            82 => Some("STM32F0xx".to_string()),
            98 => Some("STM32F1xx/F2xx".to_string()),
            114 => Some("STM32F4xx".to_string()),
            240 => Some("STM32H7xx".to_string()),
            // Nordic nRF52
            48 => Some("nRF52832/nRF52840".to_string()),
            // NXP/Freescale
            118 => Some("Kinetis K series".to_string()),
            // TI
            155 => Some("TM4C123x".to_string()),
            _ => None,
        }
    }

    /// Get common default handler names that indicate weak/stub implementations
    pub fn is_default_handler_name(&self, name: &str) -> bool {
        matches!(
            name,
            "Default_Handler"
                | "DefaultHandler"
                | "default_handler"
                | "Dummy_Handler"
                | "DummyHandler"
                | "IntDefaultHandler"
                | "__default_handler"
        )
    }
}

impl Default for ArmDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_exceptions() {
        let db = ArmDatabase::new();
        assert_eq!(db.get_description(-15), "Reset Handler");
        assert_eq!(db.get_description(-13), "Hard Fault Handler");
        assert_eq!(db.get_description(-1), "System Tick Timer (SysTick)");
    }

    #[test]
    fn test_is_critical() {
        let db = ArmDatabase::new();
        assert!(db.is_critical_exception(-13)); // HardFault
        assert!(db.is_critical_exception(-12)); // MemManage
        assert!(!db.is_critical_exception(-1)); // SysTick
        assert!(!db.is_critical_exception(0)); // Device IRQ
    }

    #[test]
    fn test_default_handler_detection() {
        let db = ArmDatabase::new();
        assert!(db.is_default_handler_name("Default_Handler"));
        assert!(db.is_default_handler_name("DefaultHandler"));
        assert!(!db.is_default_handler_name("USB_Handler"));
    }
}
