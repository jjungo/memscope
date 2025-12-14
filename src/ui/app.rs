use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    Frame, Terminal,
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap},
};

use super::theme;
use crate::elf::ElfParser;
use crate::models::{
    AnalysisResult, MemoryLayout, Symbol, SymbolType, VectorTable, VectorTableStats,
};
use crate::symbol::{FuzzyMatch, FuzzyMatcher};
use crate::utils::{format_size_human, truncate};
use log::warn;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewTab {
    Memory,
    Symbols,
    Files,
    Statistics,
    RegionExplorer,
    VectorTable,
}

// Statistics data structure
#[derive(Debug, Clone)]
struct SymbolStatistics {
    total_count: usize,
    function_count: usize,
    object_count: usize,
    other_count: usize,
    // Size distribution
    tiny_count: usize,   // < 100 bytes
    small_count: usize,  // 100B - 1KB
    medium_count: usize, // 1KB - 10KB
    large_count: usize,  // > 10KB
    // Top symbols
    top_10_largest: Vec<usize>, // indices into all_symbols
    // Namespace analysis (prefix -> count)
    namespaces: Vec<(String, usize, u64)>, // (prefix, count, total_size)
}

pub struct App {
    layout: MemoryLayout,
    analysis: AnalysisResult,
    selected_section: usize,
    list_state: ListState,
    show_help: bool,
    detail_scroll: u16,
    // Tab state
    current_tab: ViewTab,
    // Symbol/File view state
    all_symbols: Vec<Symbol>,
    search_query: String,
    fuzzy_results: Vec<FuzzyMatch>,
    selected_symbol_index: usize,
    symbol_list_state: ListState,
    matcher: FuzzyMatcher,
    search_mode: bool, // When true, all keys go to search input
    // File view state
    files: Vec<String>,
    file_symbols: HashMap<String, Vec<usize>>,
    file_fuzzy_results: Vec<FuzzyMatch>,
    selected_file_index: usize,
    file_list_state: ListState,
    // Statistics
    statistics: SymbolStatistics,
    // Region Explorer state
    region_scroll: u16,             // Scroll position in memory map
    region_zoom_level: u8,          // 0=overview, 1=section, 2=page, 3=detailed
    region_selected_symbol: usize,  // Index of selected symbol in address order
    symbols_by_address: Vec<usize>, // Symbol indices sorted by address
    // Vector Table state
    vector_table: Option<VectorTable>,
    vector_stats: Option<VectorTableStats>,
    selected_vector_index: usize,
    vector_list_state: ListState,
    vector_scroll: u16,
}

impl App {
    pub fn new(layout: MemoryLayout, analysis: AnalysisResult, parser: &ElfParser) -> Self {
        let mut list_state = ListState::default();
        if !layout.sections.is_empty() {
            list_state.select(Some(0));
        }

        // Extract all symbols from ELF
        let mut all_symbols = parser.parse_all_symbols().unwrap_or_else(|e| {
            warn!("Warning: Failed to parse symbols: {}", e);
            Vec::new()
        });
        all_symbols.sort_by(|a, b| b.size.cmp(&a.size));

        // Build file -> symbols mapping
        let mut file_symbols: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, symbol) in all_symbols.iter().enumerate() {
            let file_name = symbol
                .source_file
                .clone()
                .unwrap_or_else(|| "UNKNOWN".to_string());
            file_symbols.entry(file_name).or_default().push(idx);
        }

        let mut files: Vec<String> = file_symbols.keys().cloned().collect();
        files.sort();

        let mut symbol_list_state = ListState::default();
        if !all_symbols.is_empty() {
            symbol_list_state.select(Some(0));
        }

        let mut file_list_state = ListState::default();
        if !files.is_empty() {
            file_list_state.select(Some(0));
        }

        // Calculate statistics
        let statistics = Self::calculate_statistics(&all_symbols);

        // Sort symbols by address for Region Explorer
        // Filter out symbols with zero or invalid addresses
        let mut symbols_by_address: Vec<usize> = (0..all_symbols.len())
            .filter(|&i| all_symbols[i].address > 0 && all_symbols[i].size > 0)
            .collect();
        symbols_by_address.sort_by(|&a, &b| all_symbols[a].address.cmp(&all_symbols[b].address));

        // Parse vector table if present
        use crate::vector::{VectorAnalyzer, VectorTableParser};
        let vector_parser = VectorTableParser::new();
        let vector_analyzer = VectorAnalyzer::new();

        let (vector_table, vector_stats) = parser
            .get_bytes()
            .ok()
            .and_then(|bytes| vector_parser.parse(bytes, &all_symbols).ok().flatten())
            .map(|mut table| {
                let stats = vector_analyzer.analyze(&mut table);
                (Some(table), Some(stats))
            })
            .unwrap_or((None, None));

        let mut vector_list_state = ListState::default();
        if vector_table
            .as_ref()
            .map(|vt| !vt.entries.is_empty())
            .unwrap_or(false)
        {
            vector_list_state.select(Some(0));
        }

        Self {
            layout,
            analysis,
            selected_section: 0,
            list_state,
            show_help: false,
            detail_scroll: 0,
            current_tab: ViewTab::Memory,
            all_symbols,
            search_query: String::new(),
            fuzzy_results: Vec::new(),
            selected_symbol_index: 0,
            symbol_list_state,
            matcher: FuzzyMatcher::new(),
            search_mode: false,
            files,
            file_symbols,
            file_fuzzy_results: Vec::new(),
            selected_file_index: 0,
            file_list_state,
            statistics,
            region_scroll: 0,
            region_zoom_level: 0,
            region_selected_symbol: 0,
            symbols_by_address,
            vector_table,
            vector_stats,
            selected_vector_index: 0,
            vector_list_state,
            vector_scroll: 0,
        }
    }

    fn calculate_statistics(symbols: &[Symbol]) -> SymbolStatistics {
        let mut stats = SymbolStatistics {
            total_count: symbols.len(),
            function_count: 0,
            object_count: 0,
            other_count: 0,
            tiny_count: 0,
            small_count: 0,
            medium_count: 0,
            large_count: 0,
            top_10_largest: Vec::new(),
            namespaces: Vec::new(),
        };

        // Count by type and size distribution
        for symbol in symbols {
            match symbol.symbol_type {
                SymbolType::Function => stats.function_count += 1,
                SymbolType::Object => stats.object_count += 1,
                _ => stats.other_count += 1,
            }

            // Size distribution
            if symbol.size < 100 {
                stats.tiny_count += 1;
            } else if symbol.size < 1024 {
                stats.small_count += 1;
            } else if symbol.size < 10240 {
                stats.medium_count += 1;
            } else {
                stats.large_count += 1;
            }
        }

        // Top 10 largest (symbols are already sorted by size)
        stats.top_10_largest = (0..symbols.len().min(10)).collect();

        // Namespace analysis - group by prefix (before first _ or ::)
        let mut namespace_map: HashMap<String, (usize, u64)> = HashMap::new();
        for symbol in symbols {
            let prefix = if let Some(idx) = symbol.name.find('_') {
                &symbol.name[..idx]
            } else if let Some(idx) = symbol.name.find("::") {
                &symbol.name[..idx]
            } else {
                continue; // Skip symbols without prefix
            };

            // Only track meaningful prefixes (at least 2 chars)
            if prefix.len() >= 2 {
                let entry = namespace_map.entry(prefix.to_string()).or_insert((0, 0));
                entry.0 += 1;
                entry.1 += symbol.size;
            }
        }

        // Convert to vec and sort by count
        let mut namespaces: Vec<(String, usize, u64)> = namespace_map
            .into_iter()
            .map(|(prefix, (count, size))| (prefix, count, size))
            .collect();
        namespaces.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending

        // Keep top 10 namespaces
        namespaces.truncate(10);
        stats.namespaces = namespaces;

        stats
    }

    pub fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            terminal.draw(|f| self.render(f))?;

            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                // Handle search mode separately - all keys go to search input
                if self.search_mode {
                    match key.code {
                        KeyCode::Esc => {
                            // Exit search mode and clear query
                            self.search_mode = false;
                            self.search_query.clear();
                            self.fuzzy_results.clear();
                            self.file_fuzzy_results.clear();
                        }
                        KeyCode::Enter => {
                            // Exit search mode but keep results
                            self.search_mode = false;
                        }
                        KeyCode::Backspace => {
                            self.search_query.pop();
                            self.update_search();
                        }
                        KeyCode::Down => match self.current_tab {
                            ViewTab::Symbols => self.next_symbol(),
                            ViewTab::Files => self.next_file(),
                            _ => {}
                        },
                        KeyCode::Up => match self.current_tab {
                            ViewTab::Symbols => self.previous_symbol(),
                            ViewTab::Files => self.previous_file(),
                            _ => {}
                        },
                        KeyCode::Char(c) => {
                            // All characters go to search in search mode
                            self.search_query.push(c);
                            self.update_search();
                        }
                        _ => {}
                    }
                } else {
                    // Normal mode - navigation and commands
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            return Ok(());
                        }
                        KeyCode::Char('/')
                            if self.current_tab == ViewTab::Symbols
                                || self.current_tab == ViewTab::Files =>
                        {
                            // Enter search mode
                            self.search_mode = true;
                        }
                        KeyCode::Char('h') | KeyCode::Char('?') => {
                            self.show_help = !self.show_help;
                        }
                        KeyCode::Tab
                        | KeyCode::Char('1')
                        | KeyCode::Char('2')
                        | KeyCode::Char('3')
                        | KeyCode::Char('4')
                        | KeyCode::Char('5')
                        | KeyCode::Char('6') => {
                            self.handle_tab_switch(key.code);
                        }
                        KeyCode::Down | KeyCode::Char('j') => match self.current_tab {
                            ViewTab::Memory => self.next_section(),
                            ViewTab::Symbols => self.next_symbol(),
                            ViewTab::Files => self.next_file(),
                            ViewTab::Statistics => {}
                            ViewTab::RegionExplorer => self.region_next_symbol(),
                            ViewTab::VectorTable => self.next_vector(),
                        },
                        KeyCode::Up | KeyCode::Char('k') => match self.current_tab {
                            ViewTab::Memory => self.previous_section(),
                            ViewTab::Symbols => self.previous_symbol(),
                            ViewTab::Files => self.previous_file(),
                            ViewTab::Statistics => {}
                            ViewTab::RegionExplorer => self.region_previous_symbol(),
                            ViewTab::VectorTable => self.previous_vector(),
                        },
                        KeyCode::Char('z') if self.current_tab == ViewTab::RegionExplorer => {
                            self.region_zoom_in();
                        }
                        KeyCode::Char('Z') if self.current_tab == ViewTab::RegionExplorer => {
                            self.region_zoom_out();
                        }
                        KeyCode::PageDown => {
                            if self.current_tab == ViewTab::RegionExplorer {
                                self.region_scroll = self.region_scroll.saturating_add(5);
                            } else if self.current_tab == ViewTab::VectorTable {
                                self.vector_scroll = self.vector_scroll.saturating_add(5);
                            } else {
                                self.detail_scroll = self.detail_scroll.saturating_add(5);
                            }
                        }
                        KeyCode::PageUp => {
                            if self.current_tab == ViewTab::RegionExplorer {
                                self.region_scroll = self.region_scroll.saturating_sub(5);
                            } else if self.current_tab == ViewTab::VectorTable {
                                self.vector_scroll = self.vector_scroll.saturating_sub(5);
                            } else {
                                self.detail_scroll = self.detail_scroll.saturating_sub(5);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn next_section(&mut self) {
        if self.layout.sections.is_empty() {
            return;
        }
        self.selected_section = (self.selected_section + 1) % self.layout.sections.len();
        self.list_state.select(Some(self.selected_section));
        self.detail_scroll = 0;
    }

    fn previous_section(&mut self) {
        if self.layout.sections.is_empty() {
            return;
        }
        if self.selected_section == 0 {
            self.selected_section = self.layout.sections.len() - 1;
        } else {
            self.selected_section -= 1;
        }
        self.list_state.select(Some(self.selected_section));
        self.detail_scroll = 0;
    }

    fn handle_tab_switch(&mut self, key: KeyCode) {
        self.current_tab = match key {
            KeyCode::Char('1') => ViewTab::Memory,
            KeyCode::Char('2') => ViewTab::Symbols,
            KeyCode::Char('3') => ViewTab::Files,
            KeyCode::Char('4') => ViewTab::Statistics,
            KeyCode::Char('5') => ViewTab::RegionExplorer,
            KeyCode::Char('6') => ViewTab::VectorTable,
            KeyCode::Tab => match self.current_tab {
                ViewTab::Memory => ViewTab::Symbols,
                ViewTab::Symbols => ViewTab::Files,
                ViewTab::Files => ViewTab::Statistics,
                ViewTab::Statistics => ViewTab::RegionExplorer,
                ViewTab::RegionExplorer => ViewTab::VectorTable,
                ViewTab::VectorTable => ViewTab::Memory,
            },
            _ => self.current_tab,
        };
        self.search_query.clear();
        self.fuzzy_results.clear();
        self.file_fuzzy_results.clear();
    }

    fn update_search(&mut self) {
        match self.current_tab {
            ViewTab::Symbols => {
                if self.search_query.is_empty() {
                    self.fuzzy_results.clear();
                } else {
                    self.fuzzy_results = self.matcher.search(&self.search_query, &self.all_symbols);
                    self.selected_symbol_index = 0;
                    if !self.fuzzy_results.is_empty() {
                        self.symbol_list_state.select(Some(0));
                    }
                }
            }
            ViewTab::Files => {
                if self.search_query.is_empty() {
                    self.file_fuzzy_results.clear();
                } else {
                    self.file_fuzzy_results =
                        self.matcher.search_strings(&self.search_query, &self.files);
                    self.selected_file_index = 0;
                    if !self.file_fuzzy_results.is_empty() {
                        self.file_list_state.select(Some(0));
                    }
                }
            }
            _ => {}
        }
    }

    fn next_symbol(&mut self) {
        let len = if self.search_query.is_empty() {
            self.all_symbols.len()
        } else {
            self.fuzzy_results.len()
        };
        if len == 0 {
            return;
        }
        self.selected_symbol_index = (self.selected_symbol_index + 1) % len;
        self.symbol_list_state
            .select(Some(self.selected_symbol_index));
    }

    fn previous_symbol(&mut self) {
        let len = if self.search_query.is_empty() {
            self.all_symbols.len()
        } else {
            self.fuzzy_results.len()
        };
        if len == 0 {
            return;
        }
        if self.selected_symbol_index == 0 {
            self.selected_symbol_index = len - 1;
        } else {
            self.selected_symbol_index -= 1;
        }
        self.symbol_list_state
            .select(Some(self.selected_symbol_index));
    }

    fn next_file(&mut self) {
        let len = if self.search_query.is_empty() {
            self.files.len()
        } else {
            self.file_fuzzy_results.len()
        };
        if len == 0 {
            return;
        }
        self.selected_file_index = (self.selected_file_index + 1) % len;
        self.file_list_state.select(Some(self.selected_file_index));
    }

    fn previous_file(&mut self) {
        let len = if self.search_query.is_empty() {
            self.files.len()
        } else {
            self.file_fuzzy_results.len()
        };
        if len == 0 {
            return;
        }
        if self.selected_file_index == 0 {
            self.selected_file_index = len - 1;
        } else {
            self.selected_file_index -= 1;
        }
        self.file_list_state.select(Some(self.selected_file_index));
    }

    fn next_vector(&mut self) {
        if let Some(ref vt) = self.vector_table {
            if vt.entries.is_empty() {
                return;
            }
            self.selected_vector_index = (self.selected_vector_index + 1) % vt.entries.len();
            self.vector_list_state
                .select(Some(self.selected_vector_index));
        }
    }

    fn previous_vector(&mut self) {
        if let Some(ref vt) = self.vector_table {
            if vt.entries.is_empty() {
                return;
            }
            if self.selected_vector_index == 0 {
                self.selected_vector_index = vt.entries.len() - 1;
            } else {
                self.selected_vector_index -= 1;
            }
            self.vector_list_state
                .select(Some(self.selected_vector_index));
        }
    }

    fn region_next_symbol(&mut self) {
        if self.symbols_by_address.is_empty() {
            return;
        }
        self.region_selected_symbol =
            (self.region_selected_symbol + 1) % self.symbols_by_address.len();
        self.update_region_scroll();
    }

    fn region_previous_symbol(&mut self) {
        if self.symbols_by_address.is_empty() {
            return;
        }
        if self.region_selected_symbol == 0 {
            self.region_selected_symbol = self.symbols_by_address.len() - 1;
        } else {
            self.region_selected_symbol -= 1;
        }
        self.update_region_scroll();
    }

    fn update_region_scroll(&mut self) {
        if self.symbols_by_address.is_empty() {
            return;
        }

        // Get selected symbol
        let symbol_idx = self.symbols_by_address[self.region_selected_symbol];
        let selected_symbol = &self.all_symbols[symbol_idx];

        // Calculate approximate line number where this symbol appears
        let mut line_num = 3; // Start after header lines

        // Count Flash sections and symbols before our symbol
        let flash_sections: Vec<_> = self
            .layout
            .sections
            .iter()
            .filter(|s| s.address < 0x20000000)
            .collect();

        for section in &flash_sections {
            line_num += 1; // Section line itself

            // If symbol is in this section and zoom > 0, we need to count symbols before it
            if selected_symbol.address >= section.address
                && selected_symbol.address < (section.address + section.size)
                && self.region_zoom_level > 0
            {
                // Count symbols in this section that come before selected symbol
                let section_symbols: Vec<_> = self
                    .symbols_by_address
                    .iter()
                    .map(|&idx| &self.all_symbols[idx])
                    .filter(|sym| {
                        sym.address >= section.address
                            && sym.address < (section.address + section.size)
                    })
                    .collect();

                let max_symbols = match self.region_zoom_level {
                    1 => 3,
                    2 => 10,
                    _ => 1000,
                };

                let mut display_symbols: Vec<_> = section_symbols.to_vec();
                display_symbols.sort_by(|a, b| b.size.cmp(&a.size));

                for (i, sym) in display_symbols.iter().take(max_symbols).enumerate() {
                    if sym.name == selected_symbol.name {
                        line_num += i;
                        break;
                    }
                }
                break;
            }

            // If we haven't found it yet, skip past this section's symbols
            if selected_symbol.address >= (section.address + section.size)
                && self.region_zoom_level > 0
            {
                let section_symbols_count = self
                    .symbols_by_address
                    .iter()
                    .map(|&idx| &self.all_symbols[idx])
                    .filter(|sym| {
                        sym.address >= section.address
                            && sym.address < (section.address + section.size)
                    })
                    .count();

                let max_symbols = match self.region_zoom_level {
                    1 => 3,
                    2 => 10,
                    _ => 1000,
                };

                let displayed = section_symbols_count.min(max_symbols);
                line_num += displayed;
                if section_symbols_count > max_symbols {
                    line_num += 1; // "... more symbols" line
                }
            }
        }

        // Similar for RAM sections if symbol is in RAM
        if selected_symbol.address >= 0x20000000 {
            line_num += 3; // Gap + RAM header

            let ram_sections: Vec<_> = self
                .layout
                .sections
                .iter()
                .filter(|s| s.address >= 0x20000000)
                .collect();

            for section in &ram_sections {
                line_num += 1;

                if selected_symbol.address >= section.address
                    && selected_symbol.address < (section.address + section.size)
                    && self.region_zoom_level > 0
                {
                    let section_symbols: Vec<_> = self
                        .symbols_by_address
                        .iter()
                        .map(|&idx| &self.all_symbols[idx])
                        .filter(|sym| {
                            sym.address >= section.address
                                && sym.address < (section.address + section.size)
                        })
                        .collect();

                    let max_symbols = match self.region_zoom_level {
                        1 => 3,
                        2 => 10,
                        _ => 1000,
                    };

                    let mut display_symbols: Vec<_> = section_symbols.to_vec();
                    display_symbols.sort_by(|a, b| b.size.cmp(&a.size));

                    for (i, sym) in display_symbols.iter().take(max_symbols).enumerate() {
                        if sym.name == selected_symbol.name {
                            line_num += i;
                            break;
                        }
                    }
                    break;
                }

                if selected_symbol.address >= (section.address + section.size)
                    && self.region_zoom_level > 0
                {
                    let section_symbols_count = self
                        .symbols_by_address
                        .iter()
                        .map(|&idx| &self.all_symbols[idx])
                        .filter(|sym| {
                            sym.address >= section.address
                                && sym.address < (section.address + section.size)
                        })
                        .count();

                    let max_symbols = match self.region_zoom_level {
                        1 => 3,
                        2 => 10,
                        _ => 1000,
                    };

                    let displayed = section_symbols_count.min(max_symbols);
                    line_num += displayed;
                    if section_symbols_count > max_symbols {
                        line_num += 1;
                    }
                }
            }
        }

        // Set scroll to keep symbol in middle of screen (approximate)
        self.region_scroll = line_num.saturating_sub(10) as u16;
    }

    fn region_zoom_in(&mut self) {
        if self.region_zoom_level < 3 {
            self.region_zoom_level += 1;
            self.update_region_scroll();
        }
    }

    fn region_zoom_out(&mut self) {
        if self.region_zoom_level > 0 {
            self.region_zoom_level -= 1;
            self.update_region_scroll();
        }
    }

    fn render(&mut self, f: &mut Frame) {
        if self.show_help {
            self.render_help(f);
            return;
        }

        match self.current_tab {
            ViewTab::Memory => {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3), // Title
                        Constraint::Length(6), // Memory summary
                        Constraint::Min(10),   // Main content
                        Constraint::Length(3), // Footer
                    ])
                    .split(f.area());

                self.render_title(f, chunks[0]);
                self.render_memory_summary(f, chunks[1]);
                self.render_main_content(f, chunks[2]);
                self.render_footer(f, chunks[3]);
            }
            ViewTab::Symbols | ViewTab::Files => {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3), // Title
                        Constraint::Length(3), // Search input
                        Constraint::Min(10),   // Main content
                        Constraint::Length(3), // Footer
                    ])
                    .split(f.area());

                self.render_title(f, chunks[0]);
                self.render_search_input(f, chunks[1]);
                self.render_main_content(f, chunks[2]);
                self.render_footer(f, chunks[3]);
            }
            ViewTab::Statistics => {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3), // Title
                        Constraint::Min(10),   // Main content
                        Constraint::Length(3), // Footer
                    ])
                    .split(f.area());

                self.render_title(f, chunks[0]);
                self.render_main_content(f, chunks[1]);
                self.render_footer(f, chunks[2]);
            }
            ViewTab::RegionExplorer => {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3), // Title
                        Constraint::Min(10),   // Main content (memory map)
                        Constraint::Length(3), // Footer
                    ])
                    .split(f.area());

                self.render_title(f, chunks[0]);
                self.render_region_explorer(f, chunks[1]);
                self.render_footer(f, chunks[2]);
            }
            ViewTab::VectorTable => {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3), // Title
                        Constraint::Min(10),   // Main content
                        Constraint::Length(3), // Footer
                    ])
                    .split(f.area());

                self.render_title(f, chunks[0]);
                self.render_vector_table(f, chunks[1]);
                self.render_footer(f, chunks[2]);
            }
        }
    }

    fn render_title(&self, f: &mut Frame, area: Rect) {
        let (tab1_style, tab2_style, tab3_style, tab4_style, tab5_style, tab6_style) =
            match self.current_tab {
                ViewTab::Memory => (
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                ),
                ViewTab::Symbols => (
                    Style::default().fg(Color::Gray),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                ),
                ViewTab::Files => (
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                ),
                ViewTab::Statistics => (
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                ),
                ViewTab::RegionExplorer => (
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                    Style::default().fg(Color::Gray),
                ),
                ViewTab::VectorTable => (
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::Gray),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
            };

        let title = Line::from(vec![
            Span::styled("[1] Memory", tab1_style),
            Span::raw("  |  "),
            Span::styled("[2] Symbols", tab2_style),
            Span::raw("  |  "),
            Span::styled("[3] Files", tab3_style),
            Span::raw("  |  "),
            Span::styled("[4] Statistics", tab4_style),
            Span::raw("  |  "),
            Span::styled("[5] Region Explorer", tab5_style),
            Span::raw("  |  "),
            Span::styled("[6] Vector Table", tab6_style),
        ]);

        let title_widget = Paragraph::new(title)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title_widget, area);
    }

    fn render_memory_summary(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Length(3)])
            .split(area);

        // Flash gauge
        let flash_ratio = if let Some(size) = self.layout.flash_size {
            self.layout.total_flash_used as f64 / size as f64
        } else {
            0.0
        };

        let flash_label = if let Some(pct) = self.layout.flash_percentage() {
            format!(
                "Flash: {:.2} KB / {:.2} KB ({:.1}%)",
                self.layout.total_flash_used as f64 / 1024.0,
                self.layout.flash_size.unwrap_or(0) as f64 / 1024.0,
                pct
            )
        } else {
            format!(
                "Flash: {:.2} KB",
                self.layout.total_flash_used as f64 / 1024.0
            )
        };

        let flash_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Flash"))
            .gauge_style(Style::default().fg(Color::Green))
            .ratio(flash_ratio)
            .label(flash_label);
        f.render_widget(flash_gauge, chunks[0]);

        // RAM gauge
        let ram_ratio = if let Some(size) = self.layout.ram_size {
            self.layout.total_ram_used as f64 / size as f64
        } else {
            0.0
        };

        let ram_label = if let Some(pct) = self.layout.ram_percentage() {
            format!(
                "RAM: {:.2} KB / {:.2} KB ({:.1}%)",
                self.layout.total_ram_used as f64 / 1024.0,
                self.layout.ram_size.unwrap_or(0) as f64 / 1024.0,
                pct
            )
        } else {
            format!("RAM: {:.2} KB", self.layout.total_ram_used as f64 / 1024.0)
        };

        let ram_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("RAM"))
            .gauge_style(Style::default().fg(Color::Yellow))
            .ratio(ram_ratio)
            .label(ram_label);
        f.render_widget(ram_gauge, chunks[1]);
    }

    fn render_search_input(&self, f: &mut Frame, area: Rect) {
        let (title, style, content) = if self.search_mode {
            (
                "Search (Esc to cancel, Enter to confirm)",
                Style::default().fg(Color::Yellow),
                format!("> {}█", self.search_query), // Show cursor
            )
        } else if !self.search_query.is_empty() {
            (
                "Search (/ to edit)",
                Style::default(),
                format!("> {}", self.search_query),
            )
        } else {
            (
                "Search (press / to search)",
                Style::default().fg(Color::DarkGray),
                "> ".to_string(),
            )
        };

        let input = Paragraph::new(content)
            .style(style)
            .block(Block::default().borders(Borders::ALL).title(title));
        f.render_widget(input, area);
    }

    fn render_main_content(&mut self, f: &mut Frame, area: Rect) {
        match self.current_tab {
            ViewTab::Statistics => {
                self.render_statistics_dashboard(f, area);
            }
            ViewTab::RegionExplorer => {
                // Region Explorer is handled separately in render()
                unreachable!("RegionExplorer should not call render_main_content")
            }
            _ => {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                    .split(area);

                match self.current_tab {
                    ViewTab::Memory => {
                        self.render_section_list(f, chunks[0]);
                        self.render_details(f, chunks[1]);
                    }
                    ViewTab::Symbols => {
                        self.render_symbol_list(f, chunks[0]);
                        self.render_symbol_details(f, chunks[1]);
                    }
                    ViewTab::Files => {
                        self.render_file_list(f, chunks[0]);
                        self.render_file_symbols(f, chunks[1]);
                    }
                    ViewTab::Statistics => unreachable!(),
                    ViewTab::RegionExplorer => unreachable!(),
                    ViewTab::VectorTable => unreachable!(),
                }
            }
        }
    }

    fn render_section_list(&mut self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .layout
            .sections
            .iter()
            .map(|section| {
                let color = theme::section_color(&section.section_type);
                let content = format!(
                    "{:<18} 0x{:08x}  {:>8} B",
                    section.name, section.address, section.size
                );
                ListItem::new(content).style(Style::default().fg(color))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Memory Sections"),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        f.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_details(&mut self, f: &mut Frame, area: Rect) {
        if self.layout.sections.is_empty() {
            let text = Paragraph::new("No sections found")
                .block(Block::default().borders(Borders::ALL).title("Details"));
            f.render_widget(text, area);
            return;
        }

        let section = &self.layout.sections[self.selected_section];
        let color = theme::section_color(&section.section_type);

        let mut lines = vec![
            Line::from(vec![
                Span::styled("Name: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(&section.name, Style::default().fg(color)),
            ]),
            Line::from(vec![
                Span::styled("Type: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!("{:?}", section.section_type)),
            ]),
            Line::from(vec![
                Span::styled("Address: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!("0x{:08x}", section.address)),
            ]),
            Line::from(vec![
                Span::styled("Size: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!(
                    "{} bytes ({:.2} KB)",
                    section.size,
                    section.size as f64 / 1024.0
                )),
            ]),
            Line::from(vec![
                Span::styled("End: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!("0x{:08x}", section.address + section.size)),
            ]),
            Line::from(""),
        ];

        // Add symbols if present
        if !section.symbols.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("Symbols ({}):", section.symbols.len()),
                Style::default().add_modifier(Modifier::BOLD),
            )));
            for symbol in section.symbols.iter().take(20) {
                lines.push(Line::from(format!(
                    "  {} @ 0x{:08x} ({} B)",
                    symbol.name, symbol.address, symbol.size
                )));
            }
            if section.symbols.len() > 20 {
                lines.push(Line::from(format!(
                    "  ... and {} more",
                    section.symbols.len() - 20
                )));
            }
        }

        // Add warnings if any apply to this section
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Analysis:",
            Style::default().add_modifier(Modifier::BOLD),
        )));

        if !self.analysis.warnings.is_empty() {
            for warning in &self.analysis.warnings {
                lines.push(Line::from(Span::styled(
                    warning,
                    Style::default().fg(Color::Red),
                )));
            }
        }

        let text = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Section Details"),
            )
            .wrap(Wrap { trim: true })
            .scroll((self.detail_scroll, 0));

        f.render_widget(text, area);
    }

    fn render_symbol_list(&mut self, f: &mut Frame, area: Rect) {
        let symbols_to_display: Vec<&Symbol> = if self.search_query.is_empty() {
            self.all_symbols.iter().collect()
        } else {
            self.fuzzy_results
                .iter()
                .map(|m| &self.all_symbols[m.symbol_index])
                .collect()
        };

        let items: Vec<ListItem> = symbols_to_display
            .iter()
            .map(|symbol| {
                let color = symbol_type_color(&symbol.symbol_type);
                let size_str = format_size_human(symbol.size);
                let content = format!(
                    "{:<30} {:>10}  {:?}",
                    truncate(&symbol.name, 30),
                    size_str,
                    symbol.symbol_type
                );
                ListItem::new(content).style(Style::default().fg(color))
            })
            .collect();

        let title = if self.search_query.is_empty() {
            "All Symbols"
        } else {
            "Search Results"
        };

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        f.render_stateful_widget(list, area, &mut self.symbol_list_state);
    }

    fn render_symbol_details(&self, f: &mut Frame, area: Rect) {
        let symbol = if self.search_query.is_empty() {
            if self.selected_symbol_index < self.all_symbols.len() {
                Some(&self.all_symbols[self.selected_symbol_index])
            } else {
                None
            }
        } else if self.selected_symbol_index < self.fuzzy_results.len() {
            let match_result = &self.fuzzy_results[self.selected_symbol_index];
            Some(&self.all_symbols[match_result.symbol_index])
        } else {
            None
        };

        if let Some(sym) = symbol {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("Name: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(&sym.name),
                ]),
                Line::from(vec![
                    Span::styled("Type: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!("{:?}", sym.symbol_type)),
                ]),
                Line::from(vec![
                    Span::styled("Binding: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!("{:?}", sym.binding)),
                ]),
                Line::from(vec![
                    Span::styled(
                        "Visibility: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("{:?}", sym.visibility)),
                ]),
            ];

            // Add source file (or UNKNOWN in orange if not available)
            let source_file_span = if let Some(ref source_file) = sym.source_file {
                Span::styled(source_file, Style::default().fg(Color::Cyan))
            } else {
                Span::styled("UNKNOWN", Style::default().fg(Color::Rgb(255, 165, 0)))
                // Orange
            };
            lines.push(Line::from(vec![
                Span::styled(
                    "Source File: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                source_file_span,
            ]));

            // Add section name
            let section_span = if let Some(ref section_name) = sym.section_name {
                Span::styled(section_name, Style::default().fg(Color::Green))
            } else {
                Span::styled("UNKNOWN", Style::default().fg(Color::Rgb(255, 165, 0)))
            };
            lines.push(Line::from(vec![
                Span::styled("Section: ", Style::default().add_modifier(Modifier::BOLD)),
                section_span,
            ]));

            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Address: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!("0x{:08x}", sym.address)),
            ]));

            // Add address range (start → end)
            let end_address = sym.address + sym.size;
            lines.push(Line::from(vec![
                Span::styled("Range: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!("0x{:08x} → 0x{:08x}", sym.address, end_address)),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Size: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format_size_human(sym.size)),
            ]));

            // Calculate alignment (must be power of 2)
            let alignment = if sym.address > 0 {
                let trailing_zeros = sym.address.trailing_zeros();
                1u64 << trailing_zeros.min(16) // Cap at 64KB alignment
            } else {
                0
            };
            lines.push(Line::from(vec![
                Span::styled("Alignment: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!("{} bytes", alignment)),
            ]));

            // Calculate percentile ranking by size (symbols are sorted by size)
            let symbol_index = if self.search_query.is_empty() {
                self.selected_symbol_index
            } else {
                self.fuzzy_results[self.selected_symbol_index].symbol_index
            };

            let percentile = if !self.all_symbols.is_empty() {
                ((symbol_index as f64 / self.all_symbols.len() as f64) * 100.0) as u32
            } else {
                0
            };

            let percentile_color = if percentile <= 10 {
                Color::Red // Top 10%
            } else if percentile <= 25 {
                Color::Yellow // Top 25%
            } else {
                Color::Gray
            };

            lines.push(Line::from(vec![
                Span::styled("Size Rank: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(
                    format!("Top {}% ", percentile),
                    Style::default().fg(percentile_color),
                ),
                Span::styled(
                    format!("(#{} of {})", symbol_index + 1, self.all_symbols.len()),
                    Style::default().fg(Color::Gray),
                ),
            ]));

            // Add neighboring symbols (previous and next in address order)
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "Neighbors:",
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Cyan),
            )]));

            // Find this symbol's position in address-sorted list
            if let Some(pos) = self.symbols_by_address.iter().position(|&idx| {
                self.all_symbols[idx].address == sym.address
                    && self.all_symbols[idx].name == sym.name
            }) {
                // Previous symbol
                if pos > 0 {
                    let prev_idx = self.symbols_by_address[pos - 1];
                    let prev_sym = &self.all_symbols[prev_idx];
                    lines.push(Line::from(vec![
                        Span::styled("  ◄ ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            truncate(&prev_sym.name, 35),
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::raw(format!(
                            " @ 0x{:08x} ({})",
                            prev_sym.address,
                            format_size_human(prev_sym.size)
                        )),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("  ◄ ", Style::default().fg(Color::DarkGray)),
                        Span::styled("(first symbol)", Style::default().fg(Color::DarkGray)),
                    ]));
                }

                // Next symbol
                if pos + 1 < self.symbols_by_address.len() {
                    let next_idx = self.symbols_by_address[pos + 1];
                    let next_sym = &self.all_symbols[next_idx];
                    lines.push(Line::from(vec![
                        Span::styled("  ► ", Style::default().fg(Color::Gray)),
                        Span::styled(
                            truncate(&next_sym.name, 35),
                            Style::default().fg(Color::Green),
                        ),
                        Span::raw(format!(
                            " @ 0x{:08x} ({})",
                            next_sym.address,
                            format_size_human(next_sym.size)
                        )),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("  ► ", Style::default().fg(Color::DarkGray)),
                        Span::styled("(last symbol)", Style::default().fg(Color::DarkGray)),
                    ]));
                }

                // Calculate gap to next symbol if there is one
                if pos + 1 < self.symbols_by_address.len() {
                    let next_idx = self.symbols_by_address[pos + 1];
                    let next_sym = &self.all_symbols[next_idx];
                    let gap = next_sym.address.saturating_sub(sym.address + sym.size);
                    if gap > 0 {
                        lines.push(Line::from(vec![
                            Span::styled("  Gap: ", Style::default().add_modifier(Modifier::BOLD)),
                            Span::styled(
                                format_size_human(gap),
                                Style::default().fg(if gap > 1024 {
                                    Color::Red
                                } else {
                                    Color::Gray
                                }),
                            ),
                        ]));
                    }
                }
            }

            // Add fuzzy match score if searching
            if !self.search_query.is_empty()
                && self.selected_symbol_index < self.fuzzy_results.len()
            {
                let score = self.fuzzy_results[self.selected_symbol_index].score;
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled(
                        "Match Score: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("{}", score)),
                ]));
            }

            let text = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Symbol Details"),
                )
                .wrap(Wrap { trim: true });
            f.render_widget(text, area);
        } else {
            let text = Paragraph::new("No symbol selected").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Symbol Details"),
            );
            f.render_widget(text, area);
        }
    }

    fn render_file_list(&mut self, f: &mut Frame, area: Rect) {
        let files_to_display: Vec<&String> = if self.search_query.is_empty() {
            self.files.iter().collect()
        } else {
            self.file_fuzzy_results
                .iter()
                .map(|m| &self.files[m.symbol_index])
                .collect()
        };

        let items: Vec<ListItem> = files_to_display
            .iter()
            .map(|filename| {
                let symbol_count = self
                    .file_symbols
                    .get(*filename)
                    .map(|v| v.len())
                    .unwrap_or(0);
                let total_size: u64 = self
                    .file_symbols
                    .get(*filename)
                    .map(|indices| indices.iter().map(|&idx| self.all_symbols[idx].size).sum())
                    .unwrap_or(0);

                let color = if *filename == "UNKNOWN" {
                    Color::Rgb(255, 165, 0) // Orange
                } else {
                    Color::White
                };

                let content = format!(
                    "{:<30} {:>4} symbols  {:>10}",
                    truncate(filename, 30),
                    symbol_count,
                    format_size_human(total_size)
                );
                ListItem::new(content).style(Style::default().fg(color))
            })
            .collect();

        let title = if self.search_query.is_empty() {
            format!("Files ({})", self.files.len())
        } else {
            format!("Files ({} matches)", self.file_fuzzy_results.len())
        };

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        f.render_stateful_widget(list, area, &mut self.file_list_state);
    }

    fn render_file_symbols(&mut self, f: &mut Frame, area: Rect) {
        let file_name = if self.search_query.is_empty() {
            if self.selected_file_index < self.files.len() {
                Some(&self.files[self.selected_file_index])
            } else {
                None
            }
        } else if self.selected_file_index < self.file_fuzzy_results.len() {
            let idx = self.file_fuzzy_results[self.selected_file_index].symbol_index;
            Some(&self.files[idx])
        } else {
            None
        };

        if let Some(file) = file_name {
            if let Some(symbol_indices) = self.file_symbols.get(file) {
                let mut lines = vec![
                    Line::from(vec![
                        Span::styled("File: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::styled(file, Style::default().fg(Color::Cyan)),
                    ]),
                    Line::from(vec![
                        Span::styled("Symbols: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(format!("{}", symbol_indices.len())),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled(
                        "Top 10 largest symbols:",
                        Style::default().add_modifier(Modifier::BOLD),
                    )),
                ];

                // Get symbols and sort by size
                let mut file_symbols: Vec<&Symbol> = symbol_indices
                    .iter()
                    .map(|&idx| &self.all_symbols[idx])
                    .collect();
                file_symbols.sort_by(|a, b| b.size.cmp(&a.size));

                for sym in file_symbols.iter().take(10) {
                    lines.push(Line::from(format!(
                        "  {:>10}  {}",
                        format_size_human(sym.size),
                        truncate(&sym.name, 45)
                    )));
                }

                if symbol_indices.len() > 10 {
                    lines.push(Line::from(format!(
                        "  ... and {} more",
                        symbol_indices.len() - 10
                    )));
                }

                let text = Paragraph::new(lines)
                    .block(Block::default().borders(Borders::ALL).title("File Symbols"))
                    .wrap(Wrap { trim: true });
                f.render_widget(text, area);
            }
        } else {
            let text = Paragraph::new("No file selected")
                .block(Block::default().borders(Borders::ALL).title("File Symbols"));
            f.render_widget(text, area);
        }
    }

    fn render_statistics_dashboard(&self, f: &mut Frame, area: Rect) {
        // Split into top and bottom sections
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        // Top section: Split into left (counts/distribution) and right (top 10)
        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(main_chunks[0]);

        // Render symbol counts and distribution
        self.render_symbol_counts(f, top_chunks[0]);

        // Render top 10 largest symbols
        self.render_top_10(f, top_chunks[1]);

        // Render namespace analysis
        self.render_namespaces(f, main_chunks[1]);
    }

    fn render_symbol_counts(&self, f: &mut Frame, area: Rect) {
        let stats = &self.statistics;

        let lines = vec![
            Line::from(Span::styled(
                "Symbol Statistics",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Total Symbols: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{}", stats.total_count)),
            ]),
            Line::from(vec![
                Span::styled("  Functions:   ", Style::default().fg(Color::Green)),
                Span::raw(format!(
                    "{:>6} ({:>5.1}%)",
                    stats.function_count,
                    if stats.total_count > 0 {
                        stats.function_count as f64 / stats.total_count as f64 * 100.0
                    } else {
                        0.0
                    }
                )),
            ]),
            Line::from(vec![
                Span::styled("  Objects:     ", Style::default().fg(Color::Yellow)),
                Span::raw(format!(
                    "{:>6} ({:>5.1}%)",
                    stats.object_count,
                    if stats.total_count > 0 {
                        stats.object_count as f64 / stats.total_count as f64 * 100.0
                    } else {
                        0.0
                    }
                )),
            ]),
            Line::from(vec![
                Span::styled("  Other:       ", Style::default().fg(Color::Gray)),
                Span::raw(format!(
                    "{:>6} ({:>5.1}%)",
                    stats.other_count,
                    if stats.total_count > 0 {
                        stats.other_count as f64 / stats.total_count as f64 * 100.0
                    } else {
                        0.0
                    }
                )),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Size Distribution",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled("  < 100 bytes:    ", Style::default()),
                Span::raw(format!(
                    "{:>6} ({:>5.1}%)",
                    stats.tiny_count,
                    if stats.total_count > 0 {
                        stats.tiny_count as f64 / stats.total_count as f64 * 100.0
                    } else {
                        0.0
                    }
                )),
            ]),
            Line::from(vec![
                Span::styled("  100B - 1KB:     ", Style::default()),
                Span::raw(format!(
                    "{:>6} ({:>5.1}%)",
                    stats.small_count,
                    if stats.total_count > 0 {
                        stats.small_count as f64 / stats.total_count as f64 * 100.0
                    } else {
                        0.0
                    }
                )),
            ]),
            Line::from(vec![
                Span::styled("  1KB - 10KB:     ", Style::default()),
                Span::raw(format!(
                    "{:>6} ({:>5.1}%)",
                    stats.medium_count,
                    if stats.total_count > 0 {
                        stats.medium_count as f64 / stats.total_count as f64 * 100.0
                    } else {
                        0.0
                    }
                )),
            ]),
            Line::from(vec![
                Span::styled("  > 10KB:         ", Style::default()),
                Span::raw(format!(
                    "{:>6} ({:>5.1}%)",
                    stats.large_count,
                    if stats.total_count > 0 {
                        stats.large_count as f64 / stats.total_count as f64 * 100.0
                    } else {
                        0.0
                    }
                )),
            ]),
        ];

        let paragraph = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Overview"))
            .wrap(Wrap { trim: true });
        f.render_widget(paragraph, area);
    }

    fn render_top_10(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![
            Line::from(Span::styled(
                "Top 10 Largest Symbols",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        let mut total_top10_size = 0u64;

        for (i, &idx) in self.statistics.top_10_largest.iter().enumerate() {
            if idx < self.all_symbols.len() {
                let symbol = &self.all_symbols[idx];
                total_top10_size += symbol.size;
                lines.push(Line::from(vec![
                    Span::styled(format!("{:>2}. ", i + 1), Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{:>10}", format_size_human(symbol.size)),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::raw("  "),
                    Span::raw(truncate(&symbol.name, 30)),
                ]));
            }
        }

        // Add separator and totals
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "─".repeat(45),
            Style::default().fg(Color::DarkGray),
        )]));

        lines.push(Line::from(vec![
            Span::styled("Total: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                format_size_human(total_top10_size),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        // Calculate percentage of total RAM if available
        if let Some(total_ram) = self.layout.ram_size {
            let ram_percentage = (total_top10_size as f64 / total_ram as f64) * 100.0;
            lines.push(Line::from(vec![
                Span::styled("RAM Usage: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(
                    format!("{:.2}%", ram_percentage),
                    Style::default().fg(if ram_percentage > 10.0 {
                        Color::Red
                    } else {
                        Color::Green
                    }),
                ),
                Span::styled(
                    format!(" of {} total", format_size_human(total_ram)),
                    Style::default().fg(Color::Gray),
                ),
            ]));
        }

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Largest Symbols"),
            )
            .wrap(Wrap { trim: true });
        f.render_widget(paragraph, area);
    }

    fn render_namespaces(&self, f: &mut Frame, area: Rect) {
        let mut lines = vec![
            Line::from(Span::styled(
                "Top 10 Symbol Prefixes/Namespaces",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Prefix",
                    Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
                Span::raw("                 "),
                Span::styled(
                    "Count",
                    Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
                Span::raw("     "),
                Span::styled(
                    "Total Size",
                    Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
            ]),
            Line::from(""),
        ];

        for (prefix, count, size) in &self.statistics.namespaces {
            let percentage = if self.statistics.total_count > 0 {
                *count as f64 / self.statistics.total_count as f64 * 100.0
            } else {
                0.0
            };

            lines.push(Line::from(vec![
                Span::styled(
                    format!("{:<20}", truncate(prefix, 20)),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw("  "),
                Span::raw(format!("{:>6} ({:>5.1}%)", count, percentage)),
                Span::raw("   "),
                Span::styled(
                    format!("{:>10}", format_size_human(*size)),
                    Style::default().fg(Color::Yellow),
                ),
            ]));
        }

        if self.statistics.namespaces.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "No namespaces detected (symbols lack prefixes)",
                Style::default().fg(Color::Gray),
            )));
        }

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Namespace Analysis"),
            )
            .wrap(Wrap { trim: true });
        f.render_widget(paragraph, area);
    }

    fn render_region_explorer(&self, f: &mut Frame, area: Rect) {
        // Split into left (memory map) and right (symbol details)
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        self.render_memory_map(f, chunks[0]);
        self.render_region_symbol_details(f, chunks[1]);
    }

    fn render_memory_map(&self, f: &mut Frame, area: Rect) {
        // Get currently selected symbol for highlighting
        let (selected_symbol_addr, selected_symbol_name) = if !self.symbols_by_address.is_empty() {
            let symbol_idx = self.symbols_by_address[self.region_selected_symbol];
            let symbol = &self.all_symbols[symbol_idx];
            (Some(symbol.address), Some(symbol.name.as_str()))
        } else {
            (None, None)
        };

        let zoom_desc = match self.region_zoom_level {
            0 => "Sections Only",
            1 => "Sections + Top Symbols",
            2 => "More Symbols",
            3 => "All Symbols",
            _ => "Unknown",
        };

        let mut lines = vec![
            Line::from(Span::styled(
                format!(
                    "Memory Map - Zoom {}: {}",
                    self.region_zoom_level, zoom_desc
                ),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        // Get memory region information
        let total_flash = self
            .layout
            .flash_size
            .unwrap_or(self.layout.total_flash_used);
        let total_ram = self.layout.ram_size.unwrap_or(self.layout.total_ram_used);

        // Add memory region headers
        lines.push(Line::from(vec![
            Span::styled(
                "FLASH ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("(0x00000000 - 0x{:08x})", total_flash)),
        ]));
        lines.push(Line::from(""));

        // Render Flash sections
        let mut flash_sections: Vec<_> = self
            .layout
            .sections
            .iter()
            .filter(|s| s.address < 0x20000000) // Flash typically below 0x20000000 in ARM
            .collect();
        flash_sections.sort_by_key(|s| s.address);

        let mut last_addr = 0u64;
        for section in &flash_sections {
            // Show gap if there is one
            if section.address > last_addr {
                let gap_size = section.address - last_addr;
                if gap_size > 0 {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(
                            format!("--- GAP: {} bytes ---", format_size_human(gap_size)),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            }

            // Show section with proportional bar
            let bar_width = ((section.size as f64 / total_flash as f64) * 40.0) as usize;
            let bar = "█".repeat(bar_width.max(1));
            let color = theme::section_color(&section.section_type);

            // Check if selected symbol is in this section
            let section_has_selected = if let Some(addr) = selected_symbol_addr {
                addr >= section.address && addr < (section.address + section.size)
            } else {
                false
            };

            let mut line_spans = vec![Span::raw(if section_has_selected { "►" } else { " " })];
            line_spans.push(Span::raw(" "));
            line_spans.push(Span::styled(bar, Style::default().fg(color)));
            line_spans.push(Span::raw(" "));
            line_spans.push(Span::styled(
                &section.name,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ));
            line_spans.push(Span::raw(format!(
                " {} @ 0x{:08x}",
                format_size_human(section.size),
                section.address
            )));

            lines.push(Line::from(line_spans));

            // Show symbols in this section based on zoom level
            if self.region_zoom_level > 0 {
                let section_symbols: Vec<_> = self
                    .symbols_by_address
                    .iter()
                    .map(|&idx| &self.all_symbols[idx])
                    .filter(|sym| {
                        sym.address >= section.address
                            && sym.address < (section.address + section.size)
                    })
                    .collect();

                let max_symbols = match self.region_zoom_level {
                    1 => 3,    // Show top 3 largest symbols
                    2 => 10,   // Show top 10 symbols
                    _ => 1000, // Show many symbols (effectively all for most sections)
                };

                let mut display_symbols: Vec<_> = section_symbols.to_vec();
                display_symbols.sort_by(|a, b| b.size.cmp(&a.size)); // Sort by size descending

                for sym in display_symbols.iter().take(max_symbols) {
                    let is_selected = selected_symbol_name == Some(sym.name.as_str());
                    let sym_color = symbol_type_color(&sym.symbol_type);

                    lines.push(Line::from(vec![
                        Span::raw(if is_selected { "  ►►" } else { "    " }),
                        Span::raw(" "),
                        Span::styled(
                            format!("{:>10}", format_size_human(sym.size)),
                            Style::default().fg(sym_color).add_modifier(if is_selected {
                                Modifier::BOLD | Modifier::UNDERLINED
                            } else {
                                Modifier::empty()
                            }),
                        ),
                        Span::raw("  "),
                        Span::styled(
                            truncate(&sym.name, 45),
                            Style::default().fg(sym_color).add_modifier(if is_selected {
                                Modifier::BOLD
                            } else {
                                Modifier::empty()
                            }),
                        ),
                    ]));
                }

                if section_symbols.len() > max_symbols {
                    lines.push(Line::from(vec![
                        Span::raw("      "),
                        Span::styled(
                            format!(
                                "... {} more symbols (zoom in to see more)",
                                section_symbols.len() - max_symbols
                            ),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            }

            last_addr = section.address + section.size;
        }

        // Add RAM section
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(
                "RAM ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("(0x20000000 - 0x{:08x})", 0x20000000 + total_ram)),
        ]));
        lines.push(Line::from(""));

        // Render RAM sections
        let mut ram_sections: Vec<_> = self
            .layout
            .sections
            .iter()
            .filter(|s| s.address >= 0x20000000) // RAM typically starts at 0x20000000
            .collect();
        ram_sections.sort_by_key(|s| s.address);

        let mut last_addr = 0x20000000u64;
        for section in &ram_sections {
            // Show gap if there is one
            if section.address > last_addr {
                let gap_size = section.address - last_addr;
                if gap_size > 0 {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(
                            format!("--- GAP: {} bytes ---", format_size_human(gap_size)),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            }

            // Show section with proportional bar
            let bar_width = ((section.size as f64 / total_ram as f64) * 40.0) as usize;
            let bar = "█".repeat(bar_width.max(1));
            let color = theme::section_color(&section.section_type);

            // Check if selected symbol is in this section
            let section_has_selected = if let Some(addr) = selected_symbol_addr {
                addr >= section.address && addr < (section.address + section.size)
            } else {
                false
            };

            let mut line_spans = vec![Span::raw(if section_has_selected { "►" } else { " " })];
            line_spans.push(Span::raw(" "));
            line_spans.push(Span::styled(bar, Style::default().fg(color)));
            line_spans.push(Span::raw(" "));
            line_spans.push(Span::styled(
                &section.name,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ));
            line_spans.push(Span::raw(format!(
                " {} @ 0x{:08x}",
                format_size_human(section.size),
                section.address
            )));

            lines.push(Line::from(line_spans));

            // Show symbols in this section based on zoom level
            if self.region_zoom_level > 0 {
                let section_symbols: Vec<_> = self
                    .symbols_by_address
                    .iter()
                    .map(|&idx| &self.all_symbols[idx])
                    .filter(|sym| {
                        sym.address >= section.address
                            && sym.address < (section.address + section.size)
                    })
                    .collect();

                let max_symbols = match self.region_zoom_level {
                    1 => 3,    // Show top 3 largest symbols
                    2 => 10,   // Show top 10 symbols
                    _ => 1000, // Show many symbols (effectively all for most sections)
                };

                let mut display_symbols: Vec<_> = section_symbols.to_vec();
                display_symbols.sort_by(|a, b| b.size.cmp(&a.size)); // Sort by size descending

                for sym in display_symbols.iter().take(max_symbols) {
                    let is_selected = selected_symbol_name == Some(sym.name.as_str());
                    let sym_color = symbol_type_color(&sym.symbol_type);

                    lines.push(Line::from(vec![
                        Span::raw(if is_selected { "  ►►" } else { "    " }),
                        Span::raw(" "),
                        Span::styled(
                            format!("{:>10}", format_size_human(sym.size)),
                            Style::default().fg(sym_color).add_modifier(if is_selected {
                                Modifier::BOLD | Modifier::UNDERLINED
                            } else {
                                Modifier::empty()
                            }),
                        ),
                        Span::raw("  "),
                        Span::styled(
                            truncate(&sym.name, 45),
                            Style::default().fg(sym_color).add_modifier(if is_selected {
                                Modifier::BOLD
                            } else {
                                Modifier::empty()
                            }),
                        ),
                    ]));
                }

                if section_symbols.len() > max_symbols {
                    lines.push(Line::from(vec![
                        Span::raw("      "),
                        Span::styled(
                            format!(
                                "... {} more symbols (zoom in to see more)",
                                section_symbols.len() - max_symbols
                            ),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            }

            last_addr = section.address + section.size;
        }

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Memory Regions"),
            )
            .wrap(Wrap { trim: true })
            .scroll((self.region_scroll, 0));
        f.render_widget(paragraph, area);
    }

    fn render_region_symbol_details(&self, f: &mut Frame, area: Rect) {
        if self.symbols_by_address.is_empty() {
            let text = Paragraph::new("No symbols found").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Symbol Details"),
            );
            f.render_widget(text, area);
            return;
        }

        let symbol_idx = self.symbols_by_address[self.region_selected_symbol];
        let symbol = &self.all_symbols[symbol_idx];

        let mut lines = vec![
            Line::from(vec![Span::styled(
                "Selected Symbol",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Name: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(&symbol.name),
            ]),
            Line::from(vec![
                Span::styled("Address: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!("0x{:08x}", symbol.address)),
            ]),
            Line::from(vec![
                Span::styled("Size: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format_size_human(symbol.size)),
            ]),
            Line::from(vec![
                Span::styled("Type: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!("{:?}", symbol.symbol_type)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Navigation: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "{} of {}",
                    self.region_selected_symbol + 1,
                    self.symbols_by_address.len()
                )),
            ]),
        ];

        // Show which section this symbol belongs to
        if let Some(ref section_name) = symbol.section_name {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Section: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(section_name, Style::default().fg(Color::Green)),
            ]));
        }

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Symbol Details"),
            )
            .wrap(Wrap { trim: true });
        f.render_widget(paragraph, area);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let help_text = if self.show_help {
            "Press h or ? to close help"
        } else if self.search_mode {
            "Type to search | ↑/↓: Navigate results | Esc: Cancel | Enter: Confirm"
        } else {
            match self.current_tab {
                ViewTab::Memory => {
                    "1-6 or Tab: Switch tabs | ↑/↓: Navigate | PgUp/PgDn: Scroll | h/?: Help | q/Esc: Quit"
                }
                ViewTab::Symbols | ViewTab::Files => {
                    "1-6 or Tab: Switch tabs | /: Search | ↑/↓/j/k: Navigate | h/?: Help | q/Esc: Quit"
                }
                ViewTab::Statistics => "1-6 or Tab: Switch tabs | h/?: Help | q/Esc: Quit",
                ViewTab::RegionExplorer => {
                    "1-6 or Tab: Switch tabs | ↑/↓: Navigate symbols | z/Z: Zoom in/out | PgUp/PgDn: Scroll | h/?: Help | q/Esc: Quit"
                }
                ViewTab::VectorTable => {
                    "1-6 or Tab: Switch tabs | ↑/↓: Navigate vectors | PgUp/PgDn: Scroll details | h/?: Help | q/Esc: Quit"
                }
            }
        };

        let footer = Paragraph::new(help_text)
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, area);
    }

    fn render_help(&self, f: &mut Frame) {
        let help_text = vec![
            Line::from(Span::styled(
                "MemScope - Keyboard Shortcuts",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Navigation:",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled("1-6/Tab", Style::default().fg(Color::Yellow)),
                Span::raw("    - Switch between tabs"),
            ]),
            Line::from(vec![
                Span::styled("↑/k", Style::default().fg(Color::Yellow)),
                Span::raw("        - Move up in list"),
            ]),
            Line::from(vec![
                Span::styled("↓/j", Style::default().fg(Color::Yellow)),
                Span::raw("        - Move down in list"),
            ]),
            Line::from(vec![
                Span::styled("PgUp/PgDn", Style::default().fg(Color::Yellow)),
                Span::raw("  - Scroll details"),
            ]),
            Line::from(vec![
                Span::styled("h/?", Style::default().fg(Color::Yellow)),
                Span::raw("        - Toggle this help"),
            ]),
            Line::from(vec![
                Span::styled("q/Esc", Style::default().fg(Color::Yellow)),
                Span::raw("      - Quit application"),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Search (Symbols/Files tabs):",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled("/", Style::default().fg(Color::Yellow)),
                Span::raw("          - Enter search mode"),
            ]),
            Line::from(vec![
                Span::styled("Type", Style::default().fg(Color::Yellow)),
                Span::raw("       - Fuzzy search"),
            ]),
            Line::from(vec![
                Span::styled("Enter", Style::default().fg(Color::Yellow)),
                Span::raw("      - Confirm & exit search"),
            ]),
            Line::from(vec![
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::raw("        - Cancel & clear search"),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Section Color Codes:",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled("Green   ", Style::default().fg(Color::Green)),
                Span::raw("- Code (.text)"),
            ]),
            Line::from(vec![
                Span::styled("Blue    ", Style::default().fg(Color::Blue)),
                Span::raw("- Read-only data (.rodata)"),
            ]),
            Line::from(vec![
                Span::styled("Yellow  ", Style::default().fg(Color::Yellow)),
                Span::raw("- Initialized data (.data)"),
            ]),
            Line::from(vec![
                Span::styled("Magenta ", Style::default().fg(Color::Magenta)),
                Span::raw("- Uninitialized data (.bss)"),
            ]),
            Line::from(vec![
                Span::styled("Red     ", Style::default().fg(Color::Red)),
                Span::raw("- Stack"),
            ]),
            Line::from(vec![
                Span::styled("Cyan    ", Style::default().fg(Color::Cyan)),
                Span::raw("- Heap"),
            ]),
            Line::from(vec![
                Span::styled("Gray    ", Style::default().fg(Color::Gray)),
                Span::raw("- Custom sections"),
            ]),
            Line::from(""),
            Line::from("Press h or ? to close this help"),
        ];

        let help = Paragraph::new(help_text)
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Help")
                    .style(Style::default().bg(Color::Black)),
            )
            .wrap(Wrap { trim: true });

        let area = centered_rect(60, 80, f.area());
        f.render_widget(ratatui::widgets::Clear, area);
        f.render_widget(help, area);
    }

    fn render_vector_table(&mut self, f: &mut Frame, area: Rect) {
        // Check if vector table exists
        if self.vector_table.is_none() {
            let text = Paragraph::new("No vector table found in this binary.\n\nVector tables are typically found in ARM Cortex-M binaries in sections like .isr_vector or .vectors")
                .block(Block::default().borders(Borders::ALL).title("Vector Table"))
                .wrap(Wrap { trim: true });
            f.render_widget(text, area);
            return;
        }

        // Split into left (vector list) and right (details + stats)
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Render vector list
        self.render_vector_list(f, chunks[0]);

        // Render details and stats
        self.render_vector_details(f, chunks[1]);
    }

    fn render_vector_list(&mut self, f: &mut Frame, area: Rect) {
        use crate::models::{VectorEntryType, VectorStatus};

        let vector_table = self.vector_table.as_ref().unwrap();

        let items: Vec<ListItem> = vector_table
            .entries
            .iter()
            .map(|entry| {
                // Choose color based on status
                let color = match &entry.status {
                    VectorStatus::Implemented => Color::Green,
                    VectorStatus::DefaultHandler => Color::Yellow,
                    VectorStatus::Shared(_) => Color::Cyan,
                    VectorStatus::Invalid => Color::Red,
                    VectorStatus::Unassigned => Color::Gray,
                };

                // Format the entry
                let content = if entry.entry_type == VectorEntryType::StackPointer {
                    format!("Stack: 0x{:08x}", entry.handler_address)
                } else {
                    let handler = entry.handler_name.as_deref().unwrap_or("<unnamed>");
                    format!("IRQ {:>3}: {:<20}", entry.irq_number, truncate(handler, 20))
                };

                ListItem::new(content).style(Style::default().fg(color))
            })
            .collect();

        let title = if let Some(ref mcu) = vector_table.mcu_family {
            format!("Vectors ({}) - {}", vector_table.entries.len(), mcu)
        } else {
            format!("Vectors ({})", vector_table.entries.len())
        };

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        f.render_stateful_widget(list, area, &mut self.vector_list_state);
    }

    fn render_vector_details(&self, f: &mut Frame, area: Rect) {
        use crate::models::{VectorEntryType, VectorStatus};

        let vector_table = self.vector_table.as_ref().unwrap();

        // Split into top (stats) and bottom (entry details)
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        // Render stats
        if let Some(ref stats) = self.vector_stats {
            let mut lines = vec![
                Line::from(Span::styled(
                    "Vector Table Statistics",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(format!("Total Vectors:       {}", stats.total_vectors)),
                Line::from(vec![
                    Span::raw("Custom Handlers:     "),
                    Span::styled(
                        format!("{}", stats.custom_handlers),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(format!(
                        " ({:.1}%)",
                        (stats.custom_handlers as f64 / stats.total_vectors as f64) * 100.0
                    )),
                ]),
                Line::from(vec![
                    Span::raw("Default Handlers:    "),
                    Span::styled(
                        format!("{}", stats.default_handlers),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::raw(format!(
                        " ({:.1}%)",
                        (stats.default_handlers as f64 / stats.total_vectors as f64) * 100.0
                    )),
                ]),
                Line::from(vec![
                    Span::raw("Shared Handlers:     "),
                    Span::styled(
                        format!("{}", stats.shared_handlers),
                        Style::default().fg(Color::Cyan),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("Invalid Handlers:    "),
                    Span::styled(
                        format!("{}", stats.invalid_handlers),
                        Style::default().fg(Color::Red),
                    ),
                ]),
                Line::from(""),
                Line::from(format!(
                    "Table Size:          {} bytes",
                    vector_table.table_size
                )),
                Line::from(format!(
                    "Base Address:        0x{:08x}",
                    vector_table.base_address
                )),
            ];

            if !stats.warnings.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("⚠ {} Warnings", stats.warnings.len()),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
            }

            let paragraph = Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title("Statistics"))
                .wrap(Wrap { trim: true });
            f.render_widget(paragraph, chunks[0]);
        }

        // Render selected entry details
        if self.selected_vector_index < vector_table.entries.len() {
            let entry = &vector_table.entries[self.selected_vector_index];

            let mut lines = vec![
                Line::from(Span::styled(
                    &entry.description,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];

            if entry.entry_type == VectorEntryType::StackPointer {
                lines.push(Line::from(vec![
                    Span::styled(
                        "Initial SP: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("0x{:08x}", entry.handler_address)),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled(
                        "IRQ Number: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("{}", entry.irq_number)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled(
                        "Vector Offset: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("0x{:03x}", entry.offset)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled(
                        "Handler Address: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("0x{:08x}", entry.handler_address)),
                ]));

                if let Some(ref name) = entry.handler_name {
                    lines.push(Line::from(vec![
                        Span::styled(
                            "Handler Name: ",
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(name),
                    ]));
                }

                if entry.handler_size > 0 {
                    lines.push(Line::from(vec![
                        Span::styled(
                            "Handler Size: ",
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("{} bytes", entry.handler_size)),
                    ]));
                }

                lines.push(Line::from(""));
                let (status_text, status_color) = match &entry.status {
                    VectorStatus::Implemented => ("✓ Custom Implementation", Color::Green),
                    VectorStatus::DefaultHandler => ("⚠ Default Handler (stub)", Color::Yellow),
                    VectorStatus::Shared(primary) => {
                        lines.push(Line::from(vec![
                            Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
                            Span::styled("⇄ Shared Handler", Style::default().fg(Color::Cyan)),
                        ]));
                        lines.push(Line::from(vec![
                            Span::styled(
                                "Shares with: ",
                                Style::default().add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(primary),
                        ]));
                        ("", Color::White)
                    }
                    VectorStatus::Invalid => ("✗ Invalid/NULL Handler", Color::Red),
                    VectorStatus::Unassigned => ("○ Unassigned", Color::Gray),
                };

                if !status_text.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::styled(status_text, Style::default().fg(status_color)),
                    ]));
                }

                // Show type
                let type_str = match entry.entry_type {
                    VectorEntryType::CoreException => "ARM Core Exception",
                    VectorEntryType::DeviceIRQ => "Device IRQ",
                    _ => "Other",
                };
                lines.push(Line::from(vec![
                    Span::styled("Type: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(type_str),
                ]));
            }

            let paragraph = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Vector Details"),
                )
                .wrap(Wrap { trim: true })
                .scroll((self.vector_scroll, 0));
            f.render_widget(paragraph, chunks[1]);
        }
    }
}

fn symbol_type_color(symbol_type: &SymbolType) -> Color {
    match symbol_type {
        SymbolType::Function => Color::Green,
        SymbolType::Object => Color::Yellow,
        SymbolType::File => Color::Magenta,
        SymbolType::Section => Color::Cyan,
        _ => Color::Gray,
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
