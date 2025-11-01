//! Symbol filtering by type, size, address, and other criteria

#![allow(dead_code)]

use crate::models::{Symbol, SymbolBinding, SymbolType};

/// Filter for selecting symbols by various criteria
#[derive(Debug, Clone)]
pub struct SymbolFilter {
    pub criteria: FilterCriteria,
}

/// Criteria for symbol filtering (all are ANDed together)
#[derive(Debug, Clone, Default)]
pub struct FilterCriteria {
    /// Only include symbols of these types
    pub types: Option<Vec<SymbolType>>,
    /// Only include symbols with these bindings
    pub bindings: Option<Vec<SymbolBinding>>,
    /// Minimum symbol size in bytes
    pub size_min: Option<u64>,
    /// Maximum symbol size in bytes
    pub size_max: Option<u64>,
    /// Minimum address
    pub address_min: Option<u64>,
    /// Maximum address
    pub address_max: Option<u64>,
    /// Only include symbols in these sections
    pub section_names: Option<Vec<String>>,
}

impl SymbolFilter {
    /// Create a new filter with the given criteria
    pub fn new(criteria: FilterCriteria) -> Self {
        Self { criteria }
    }

    /// Filter symbols, returning only those matching all criteria
    pub fn filter<'a>(&self, symbols: &'a [Symbol]) -> Vec<&'a Symbol> {
        symbols
            .iter()
            .filter(|symbol| self.matches(symbol))
            .collect()
    }

    fn matches(&self, symbol: &Symbol) -> bool {
        // Check type filter
        if let Some(ref types) = self.criteria.types
            && !types.contains(&symbol.symbol_type)
        {
            return false;
        }

        // Check binding filter
        if let Some(ref bindings) = self.criteria.bindings
            && !bindings.contains(&symbol.binding)
        {
            return false;
        }

        // Check size range
        if let Some(min_size) = self.criteria.size_min
            && symbol.size < min_size
        {
            return false;
        }

        if let Some(max_size) = self.criteria.size_max
            && symbol.size > max_size
        {
            return false;
        }

        // Check address range
        if let Some(min_addr) = self.criteria.address_min
            && symbol.address < min_addr
        {
            return false;
        }

        if let Some(max_addr) = self.criteria.address_max
            && symbol.address > max_addr
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SymbolVisibility;

    fn create_test_symbol(name: &str, size: u64, sym_type: SymbolType) -> Symbol {
        Symbol {
            name: name.to_string(),
            address: 0x1000,
            size,
            symbol_type: sym_type,
            binding: SymbolBinding::Global,
            visibility: SymbolVisibility::Default,
            section_index: 0,
            source_file: None,
        }
    }

    #[test]
    fn test_filter_by_type() {
        let symbols = vec![
            create_test_symbol("func1", 100, SymbolType::Function),
            create_test_symbol("var1", 50, SymbolType::Object),
            create_test_symbol("func2", 200, SymbolType::Function),
        ];

        let filter = SymbolFilter::new(FilterCriteria {
            types: Some(vec![SymbolType::Function]),
            ..Default::default()
        });

        let filtered = filter.filter(&symbols);
        assert_eq!(filtered.len(), 2);
        assert!(
            filtered
                .iter()
                .all(|s| s.symbol_type == SymbolType::Function)
        );
    }

    #[test]
    fn test_filter_by_size_range() {
        let symbols = vec![
            create_test_symbol("small", 50, SymbolType::Function),
            create_test_symbol("medium", 150, SymbolType::Function),
            create_test_symbol("large", 500, SymbolType::Function),
        ];

        let filter = SymbolFilter::new(FilterCriteria {
            size_min: Some(100),
            size_max: Some(300),
            ..Default::default()
        });

        let filtered = filter.filter(&symbols);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "medium");
    }

    #[test]
    fn test_no_filter() {
        let symbols = vec![
            create_test_symbol("sym1", 100, SymbolType::Function),
            create_test_symbol("sym2", 200, SymbolType::Object),
        ];

        let filter = SymbolFilter::new(FilterCriteria::default());
        let filtered = filter.filter(&symbols);
        assert_eq!(filtered.len(), 2);
    }
}
