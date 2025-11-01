//! Fuzzy symbol search using Sublime Text-style matching

use fuzzy_matcher::FuzzyMatcher as FuzzyMatcherTrait;
use fuzzy_matcher::skim::SkimMatcherV2;

use crate::models::Symbol;

/// Result of a fuzzy match with score and matched character indices
#[derive(Debug, Clone)]
pub struct FuzzyMatch {
    /// Index of the matched symbol in the original array
    pub symbol_index: usize,
    /// Match quality score (higher is better)
    pub score: i64,
    /// Character indices that matched (for future highlighting)
    #[allow(dead_code)]
    pub matched_indices: Vec<usize>,
}

/// Fuzzy matcher for symbol names using skim algorithm
pub struct FuzzyMatcher {
    matcher: SkimMatcherV2,
}

impl FuzzyMatcher {
    /// Create a new fuzzy matcher with default settings
    pub fn new() -> Self {
        Self {
            matcher: SkimMatcherV2::default(),
        }
    }

    /// Search symbols with fuzzy matching, returning sorted results
    ///
    /// Results are sorted by score (best matches first)
    pub fn search(&self, query: &str, symbols: &[Symbol]) -> Vec<FuzzyMatch> {
        if query.is_empty() {
            return Vec::new();
        }

        let mut matches: Vec<FuzzyMatch> = symbols
            .iter()
            .enumerate()
            .filter_map(|(idx, symbol)| {
                self.matcher
                    .fuzzy_indices(&symbol.name, query)
                    .map(|(score, indices)| FuzzyMatch {
                        symbol_index: idx,
                        score,
                        matched_indices: indices,
                    })
            })
            .collect();

        // Sort by score (highest first)
        matches.sort_by(|a, b| b.score.cmp(&a.score));

        matches
    }

    #[allow(dead_code)]
    pub fn match_symbol(&self, query: &str, symbol: &Symbol) -> Option<FuzzyMatch> {
        self.matcher
            .fuzzy_indices(&symbol.name, query)
            .map(|(score, indices)| FuzzyMatch {
                symbol_index: 0, // Not used in this context
                score,
                matched_indices: indices,
            })
    }

    /// Search generic strings with fuzzy matching
    pub fn search_strings(&self, query: &str, strings: &[String]) -> Vec<FuzzyMatch> {
        if query.is_empty() {
            return Vec::new();
        }

        let mut matches: Vec<FuzzyMatch> = strings
            .iter()
            .enumerate()
            .filter_map(|(idx, s)| {
                self.matcher
                    .fuzzy_indices(s, query)
                    .map(|(score, indices)| FuzzyMatch {
                        symbol_index: idx,
                        score,
                        matched_indices: indices,
                    })
            })
            .collect();

        // Sort by score (highest first)
        matches.sort_by(|a, b| b.score.cmp(&a.score));

        matches
    }
}

impl Default for FuzzyMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Symbol, SymbolBinding, SymbolType, SymbolVisibility};

    fn create_test_symbol(name: &str) -> Symbol {
        Symbol {
            name: name.to_string(),
            address: 0,
            size: 0,
            symbol_type: SymbolType::Function,
            binding: SymbolBinding::Global,
            visibility: SymbolVisibility::Default,
            section_index: 0,
            source_file: None,
        }
    }

    #[test]
    fn test_fuzzy_match_exact() {
        let matcher = FuzzyMatcher::new();
        let symbols = vec![
            create_test_symbol("uart_init"),
            create_test_symbol("spi_init"),
        ];

        let matches = matcher.search("uart_init", &symbols);
        assert!(!matches.is_empty());
        assert_eq!(symbols[matches[0].symbol_index].name, "uart_init");
    }

    #[test]
    fn test_fuzzy_match_partial() {
        let matcher = FuzzyMatcher::new();
        let symbols = vec![
            create_test_symbol("uart_init"),
            create_test_symbol("uart_send"),
            create_test_symbol("spi_init"),
        ];

        let matches = matcher.search("uart", &symbols);
        assert_eq!(matches.len(), 2);
        // Both uart symbols should match
        assert!(symbols[matches[0].symbol_index].name.starts_with("uart"));
        assert!(symbols[matches[1].symbol_index].name.starts_with("uart"));
    }

    #[test]
    fn test_fuzzy_match_scoring() {
        let matcher = FuzzyMatcher::new();
        let symbols = vec![
            create_test_symbol("uart_init"),  // Exact prefix match
            create_test_symbol("debug_uart"), // Contains uart
        ];

        let matches = matcher.search("uart", &symbols);
        // uart_init should score higher (prefix match)
        assert_eq!(symbols[matches[0].symbol_index].name, "uart_init");
    }

    #[test]
    fn test_fuzzy_match_empty_query() {
        let matcher = FuzzyMatcher::new();
        let symbols = vec![create_test_symbol("uart_init")];

        let matches = matcher.search("", &symbols);
        assert!(matches.is_empty());
    }
}
