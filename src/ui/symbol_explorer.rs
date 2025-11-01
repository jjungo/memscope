// Keep this module for future reference/alternative implementation
#![allow(dead_code)]

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    Frame, Terminal,
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::elf::ElfParser;
use crate::models::{MemoryLayout, Symbol, SymbolType};
use crate::symbol::{FuzzyMatch, FuzzyMatcher};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Symbols,
    Files,
}

pub struct SymbolExplorer {
    layout: MemoryLayout,
    all_symbols: Vec<Symbol>,
    search_query: String,
    fuzzy_results: Vec<FuzzyMatch>,
    selected_index: usize,
    list_state: ListState,
    matcher: FuzzyMatcher,
    show_help: bool,
    view_mode: ViewMode,
    // File view state
    files: Vec<String>,
    file_symbols: HashMap<String, Vec<usize>>, // filename -> symbol indices
    file_fuzzy_results: Vec<FuzzyMatch>,
    selected_file_index: usize,
    file_list_state: ListState,
    file_symbol_list_state: ListState,
}

impl SymbolExplorer {
    pub fn new(layout: MemoryLayout, parser: &ElfParser) -> Self {
        // Extract all symbols from the ELF file
        let mut all_symbols = parser.parse_all_symbols().unwrap_or_else(|e| {
            eprintln!("Warning: Failed to parse symbols: {}", e);
            Vec::new()
        });

        // Sort symbols by size (largest first)
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

        // Extract sorted list of files
        let mut files: Vec<String> = file_symbols.keys().cloned().collect();
        files.sort();

        let mut list_state = ListState::default();
        if !all_symbols.is_empty() {
            list_state.select(Some(0));
        }

        let mut file_list_state = ListState::default();
        if !files.is_empty() {
            file_list_state.select(Some(0));
        }

        Self {
            layout,
            all_symbols,
            search_query: String::new(),
            fuzzy_results: Vec::new(),
            selected_index: 0,
            list_state,
            matcher: FuzzyMatcher::new(),
            show_help: false,
            view_mode: ViewMode::Symbols,
            files,
            file_symbols,
            file_fuzzy_results: Vec::new(),
            selected_file_index: 0,
            file_list_state,
            file_symbol_list_state: ListState::default(),
        }
    }

    pub fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            terminal.draw(|f| self.render(f))?;

            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc if self.search_query.is_empty() => {
                        return Ok(());
                    }
                    KeyCode::Esc if !self.search_query.is_empty() => {
                        self.search_query.clear();
                        self.fuzzy_results.clear();
                        self.file_fuzzy_results.clear();
                        self.selected_index = 0;
                        self.selected_file_index = 0;
                        if self.view_mode == ViewMode::Symbols {
                            self.list_state.select(Some(0));
                        } else {
                            self.file_list_state.select(Some(0));
                        }
                    }
                    KeyCode::Tab => {
                        // Switch between Symbol and File views
                        self.view_mode = match self.view_mode {
                            ViewMode::Symbols => ViewMode::Files,
                            ViewMode::Files => ViewMode::Symbols,
                        };
                        self.search_query.clear();
                        self.fuzzy_results.clear();
                        self.file_fuzzy_results.clear();
                    }
                    KeyCode::Char('h') | KeyCode::Char('?') => {
                        self.show_help = !self.show_help;
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        if self.view_mode == ViewMode::Symbols {
                            self.next_symbol();
                        } else {
                            self.next_file();
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        if self.view_mode == ViewMode::Symbols {
                            self.previous_symbol();
                        } else {
                            self.previous_file();
                        }
                    }
                    KeyCode::Backspace => {
                        self.search_query.pop();
                        self.update_search();
                    }
                    KeyCode::Char(c) => {
                        self.search_query.push(c);
                        self.update_search();
                    }
                    _ => {}
                }
            }
        }
    }

    fn update_search(&mut self) {
        if self.view_mode == ViewMode::Symbols {
            if self.search_query.is_empty() {
                self.fuzzy_results.clear();
            } else {
                self.fuzzy_results = self.matcher.search(&self.search_query, &self.all_symbols);
                self.selected_index = 0;
                if !self.fuzzy_results.is_empty() {
                    self.list_state.select(Some(0));
                }
            }
        } else {
            // File fuzzy search
            if self.search_query.is_empty() {
                self.file_fuzzy_results.clear();
            } else {
                self.file_fuzzy_results = self.search_files(&self.search_query);
                self.selected_file_index = 0;
                if !self.file_fuzzy_results.is_empty() {
                    self.file_list_state.select(Some(0));
                }
            }
        }
    }

    fn search_files(&self, query: &str) -> Vec<FuzzyMatch> {
        self.matcher.search_strings(query, &self.files)
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

        self.selected_index = (self.selected_index + 1) % len;
        self.list_state.select(Some(self.selected_index));
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

        if self.selected_index == 0 {
            self.selected_index = len - 1;
        } else {
            self.selected_index -= 1;
        }
        self.list_state.select(Some(self.selected_index));
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

    fn render(&mut self, f: &mut Frame) {
        if self.show_help {
            self.render_help(f);
            return;
        }

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

    fn render_title(&self, f: &mut Frame, area: Rect) {
        let (tab1_style, tab2_style) = match self.view_mode {
            ViewMode::Symbols => (
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                Style::default().fg(Color::Gray),
            ),
            ViewMode::Files => (
                Style::default().fg(Color::Gray),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
        };

        let title = Line::from(vec![
            Span::styled("[1] Symbols", tab1_style),
            Span::raw("  |  "),
            Span::styled("[2] Files", tab2_style),
            Span::raw("  (Tab to switch)"),
        ]);

        let title_widget = Paragraph::new(title)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title_widget, area);
    }

    fn render_search_input(&self, f: &mut Frame, area: Rect) {
        let input = Paragraph::new(format!("> {}", self.search_query))
            .style(Style::default())
            .block(Block::default().borders(Borders::ALL).title("Search"));
        f.render_widget(input, area);
    }

    fn render_main_content(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        match self.view_mode {
            ViewMode::Symbols => {
                self.render_symbol_list(f, chunks[0]);
                self.render_symbol_details(f, chunks[1]);
            }
            ViewMode::Files => {
                self.render_file_list(f, chunks[0]);
                self.render_file_symbols(f, chunks[1]);
            }
        }
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

        f.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_symbol_details(&self, f: &mut Frame, area: Rect) {
        let symbol = if self.search_query.is_empty() {
            if self.selected_index < self.all_symbols.len() {
                Some(&self.all_symbols[self.selected_index])
            } else {
                None
            }
        } else if self.selected_index < self.fuzzy_results.len() {
            let match_result = &self.fuzzy_results[self.selected_index];
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

            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Address: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!("0x{:08x}", sym.address)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Size: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format_size_human(sym.size)),
            ]));

            // Add fuzzy match score if searching
            if !self.search_query.is_empty() && self.selected_index < self.fuzzy_results.len() {
                let score = self.fuzzy_results[self.selected_index].score;
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

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let help_text = "Type to search | Tab: Switch view | ↑/↓: Navigate | Esc: Clear/Exit | h/?: Help | q: Quit";
        let footer = Paragraph::new(help_text)
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, area);
    }

    fn render_help(&self, f: &mut Frame) {
        let help_text = vec![
            Line::from(Span::styled(
                "Symbol Explorer - Help",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("Type", Style::default().fg(Color::Yellow)),
                Span::raw("         - Fuzzy search symbols"),
            ]),
            Line::from(vec![
                Span::styled("↑/k", Style::default().fg(Color::Yellow)),
                Span::raw("          - Navigate up"),
            ]),
            Line::from(vec![
                Span::styled("↓/j", Style::default().fg(Color::Yellow)),
                Span::raw("          - Navigate down"),
            ]),
            Line::from(vec![
                Span::styled("Backspace", Style::default().fg(Color::Yellow)),
                Span::raw("    - Delete character"),
            ]),
            Line::from(vec![
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::raw("          - Clear search / Exit"),
            ]),
            Line::from(vec![
                Span::styled("h/?", Style::default().fg(Color::Yellow)),
                Span::raw("          - Toggle this help"),
            ]),
            Line::from(vec![
                Span::styled("q", Style::default().fg(Color::Yellow)),
                Span::raw("            - Quit"),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Symbol Type Colors:",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled("Green   ", Style::default().fg(Color::Green)),
                Span::raw("- Functions"),
            ]),
            Line::from(vec![
                Span::styled("Yellow  ", Style::default().fg(Color::Yellow)),
                Span::raw("- Objects/Variables"),
            ]),
            Line::from(vec![
                Span::styled("Gray    ", Style::default().fg(Color::Gray)),
                Span::raw("- Other types"),
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

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn format_size_human(size: u64) -> String {
    if size < 1024 {
        format!("{} B", size)
    } else if size < 1024 * 1024 {
        format!("{:.2} KB", size as f64 / 1024.0)
    } else {
        format!("{:.2} MB", size as f64 / (1024.0 * 1024.0))
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
