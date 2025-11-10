//! MemScope - Interactive Memory Layout Visualizer for ARM Embedded Systems
//!
//! Analyzes ELF binaries from `arm-none-eabi-gcc` to show Flash/RAM usage,
//! detect memory issues, and export reports in multiple formats.

mod elf;
mod export;
mod linker;
mod models;
mod symbol;
mod ui;
mod utils;
mod vector;

use anyhow::Result;
use clap::Parser;
use colored::*;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;
use std::path::PathBuf;

use elf::{ElfParser, MemoryAnalyzer};
use log::{LevelFilter, info, warn};
use models::{MemoryLayout, SectionType};
use ui::App;
use utils::{format_size_human, round_to_common_size};

/// Auto-detect Flash and RAM sizes from section addresses
///
/// Returns (flash_size, ram_size) rounded to common embedded sizes
fn detect_memory_ranges(layout: &MemoryLayout) -> (Option<u64>, Option<u64>) {
    let mut flash_max = 0u64;
    let mut ram_max = 0u64;

    for section in &layout.sections {
        let end_addr = section.address + section.size;

        // Typical ARM Flash starts at 0x00000000 or 0x08000000
        if section.address < 0x20000000 {
            flash_max = flash_max.max(end_addr);
        }
        // Typical ARM RAM starts at 0x20000000
        else if section.address >= 0x20000000 && section.address < 0x40000000 {
            ram_max = ram_max.max(end_addr);
        }
    }

    let flash_size = if flash_max > 0 {
        // Round up to nearest power of 2 or common size
        Some(round_to_common_size(flash_max))
    } else {
        None
    };

    let ram_size = if ram_max > 0 {
        // Calculate from base (0x20000000) and round up
        let ram_used = ram_max - 0x20000000;
        Some(round_to_common_size(ram_used))
    } else {
        None
    };

    (flash_size, ram_size)
}

#[derive(Parser, Debug)]
#[command(name = "memscope")]
#[command(about = "Interactive Memory Layout Visualizer for ARM Embedded Systems", long_about = None)]
struct Args {
    /// Path to the ELF binary file
    #[arg(value_name = "ELF_FILE")]
    elf_file: PathBuf,

    /// Show detailed symbol information
    #[arg(short, long)]
    detailed: bool,

    /// Display summary and exit (non-interactive, no TUI)
    #[arg(long)]
    no_tui: bool,

    /// Total Flash size in bytes (e.g., 524288 for 512KB)
    #[arg(long, value_name = "BYTES")]
    flash_size: Option<u64>,

    /// Total RAM size in bytes (e.g., 262144 for 256KB)
    #[arg(long, value_name = "BYTES")]
    ram_size: Option<u64>,

    /// Show top N symbols by size and exit (non-interactive)
    #[arg(long, value_name = "N")]
    top: Option<usize>,

    /// Export format: json, csv, csv:sections, csv:analysis, markdown, md
    #[arg(long, value_name = "FORMAT")]
    export: Option<String>,

    /// Output file path for export (stdout if not specified)
    #[arg(long, value_name = "PATH", requires = "export")]
    output: Option<std::path::PathBuf>,

    /// Path to linker script for accurate memory region definitions (optional)
    #[arg(long, value_name = "LD_FILE")]
    linker_script: Option<PathBuf>,

    /// Quiet mode (no output)
    #[arg(short, long)]
    quiet: bool,
}

fn log_formatter(buf: &mut env_logger::fmt::Formatter, record: &log::Record) -> io::Result<()> {
    use colored::Colorize;
    use std::io::Write;

    let formatted_level = match record.level() {
        log::Level::Error => format!("[{}]", "E").red().bold().to_string(),
        log::Level::Warn => format!("[{}]", "W").yellow().bold().to_string(),
        log::Level::Info => format!("[{}]", "I").green().to_string(),
        log::Level::Debug => format!("[{}]", "D").blue().to_string(),
        log::Level::Trace => format!("[{}]", "T").magenta().to_string(),
    };

    writeln!(buf, "{} {}", formatted_level, record.args())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = if args.quiet {
        LevelFilter::Off
    } else {
        LevelFilter::Info
    };
    env_logger::Builder::new()
        .filter_level(log_level)
        .format(log_formatter)
        .init();

    info!(
        "{}",
        "MemScope - ARM Memory Layout Visualizer"
            .bright_cyan()
            .bold()
    );
    info!("{}", "=".repeat(50).bright_cyan());
    info!("");

    // Parse linker script if provided
    let linker_regions = if let Some(ref linker_path) = args.linker_script {
        info!("Parsing linker script: {}", linker_path.display());
        match linker::parse_linker_script(linker_path) {
            Ok(regions) => {
                info!("  Found {} memory regions", regions.len());

                // Check if we found usable RAM/Flash regions
                let has_ram = regions.iter().any(|r| {
                    let name = r.name.to_lowercase();
                    name.contains("ram") || name.contains("sram") || name.contains("tcm")
                });
                let has_flash = regions.iter().any(|r| {
                    let name = r.name.to_lowercase();
                    name.contains("flash") || name.contains("rom") || r.attributes.contains('x')
                });

                for region in &regions {
                    info!(
                        "    {} @ 0x{:08x} - 0x{:08x} ({}) [{}]",
                        region.name,
                        region.origin,
                        region.origin + region.length,
                        format_size_human(region.length),
                        region.attributes
                    );
                }

                if !has_ram && !has_flash {
                    warn!("  Warning: No RAM or Flash regions found in linker script");
                    warn!("  (Linker script may use variables that cannot be evaluated)");
                    warn!("  Falling back to ARM Cortex-M standard memory map");
                }

                Some(regions)
            }
            Err(e) => {
                warn!("Warning: Failed to parse linker script: {}", e);
                warn!("Falling back to ELF-only analysis");
                None
            }
        }
    } else {
        None
    };

    // Parse ELF file
    info!("Parsing ELF file: {}", args.elf_file.display());
    let parser = ElfParser::new(&args.elf_file)?;

    // Handle --top option (early exit, but need layout for RAM info)
    if let Some(n) = args.top {
        let mut layout = parser.parse(linker_regions.as_deref())?;
        layout.flash_size = args.flash_size;
        layout.ram_size = args.ram_size;

        // Auto-detect memory sizes if not provided
        if layout.flash_size.is_none() || layout.ram_size.is_none() {
            let detected = detect_memory_ranges(&layout);
            if layout.flash_size.is_none() {
                layout.flash_size = detected.0;
            }
            if layout.ram_size.is_none() {
                layout.ram_size = detected.1;
            }
        }

        display_top_symbols(&parser, n, layout.ram_size)?;
        return Ok(());
    }

    if args.detailed {
        info!("\n{}", parser.get_elf_info()?);
    }

    let mut layout = parser.parse(linker_regions.as_deref())?;

    // Set memory sizes if provided
    layout.flash_size = args.flash_size;
    layout.ram_size = args.ram_size;

    // Auto-detect memory sizes if not provided
    if layout.flash_size.is_none() || layout.ram_size.is_none() {
        let detected = detect_memory_ranges(&layout);
        if layout.flash_size.is_none() {
            layout.flash_size = detected.0;
        }
        if layout.ram_size.is_none() {
            layout.ram_size = detected.1;
        }
    }

    // Display sections
    info!("");
    info!("{}", "Memory Sections:".bright_yellow().bold());
    info!("{}", "-".repeat(80).bright_black());
    info!(
        "{:<20} {:<12} {:<12} {:<10}",
        "Section".bold(),
        "Address".bold(),
        "Size".bold(),
        "Type".bold()
    );
    info!("{}", "-".repeat(80).bright_black());

    for section in &layout.sections {
        let type_str = format!("{:?}", section.section_type);
        let colored_type = match section.section_type {
            SectionType::Text => type_str.bright_green(),
            SectionType::RoData => type_str.bright_blue(),
            SectionType::Data => type_str.bright_yellow(),
            SectionType::Bss => type_str.bright_magenta(),
            SectionType::Stack => type_str.bright_red(),
            SectionType::Heap => type_str.bright_cyan(),
            SectionType::Custom(_) => type_str.white(),
        };

        info!(
            "{:<20} 0x{:08x}   {:>8} B  {}",
            section.name, section.address, section.size, colored_type
        );

        if args.detailed && !section.symbols.is_empty() {
            for symbol in &section.symbols {
                info!(
                    "  └─ {} @ 0x{:08x} ({} B)",
                    symbol.name.dimmed(),
                    symbol.address,
                    symbol.size
                );
            }
        }
    }

    info!("");

    // Display summary
    info!("{}", "Memory Summary:".bright_yellow().bold());
    info!("{}", "-".repeat(80).bright_black());

    // Flash usage
    let mut flash_msg = format!(
        "Total Flash used: {} bytes (0x{:x}) / {:.2} KB",
        layout.total_flash_used,
        layout.total_flash_used,
        layout.total_flash_used as f64 / 1024.0
    );
    if let Some(percentage) = layout.flash_percentage() {
        flash_msg.push_str(&format!(" [{:.1}%]", percentage));
        if let Some(size) = layout.flash_size {
            flash_msg.push_str(&format!(" of {:.2} KB", size as f64 / 1024.0));
        }
    }
    info!("{}", flash_msg);

    // RAM usage
    let mut ram_msg = format!(
        "Total RAM used:   {} bytes (0x{:x}) / {:.2} KB",
        layout.total_ram_used,
        layout.total_ram_used,
        layout.total_ram_used as f64 / 1024.0
    );
    if let Some(percentage) = layout.ram_percentage() {
        ram_msg.push_str(&format!(" [{:.1}%]", percentage));
        if let Some(size) = layout.ram_size {
            ram_msg.push_str(&format!(" of {:.2} KB", size as f64 / 1024.0));
        }
    }
    info!("{}", ram_msg);

    // Run analyzer
    let analyzer = MemoryAnalyzer::new();
    let analysis = analyzer.analyze(&layout);

    // Handle export mode
    if let Some(export_format_str) = &args.export {
        let format = export::ExportFormat::from_str(export_format_str)
            .ok_or_else(|| anyhow::anyhow!("Invalid export format: {}", export_format_str))?;

        // Parse all symbols for export and sort by size (largest first)
        let mut symbols = parser.parse_all_symbols()?;
        symbols.sort_by(|a, b| b.size.cmp(&a.size));

        if let Some(output_path) = &args.output {
            // Export to file
            export::export_to_file(
                &layout,
                &analysis,
                &symbols,
                format,
                &args.elf_file,
                output_path,
            )?;
            info!("✓ Exported to: {}", output_path.display());
        } else {
            // Export to stdout
            let output =
                export::export_to_string(&layout, &analysis, &symbols, format, &args.elf_file)?;
            println!("{}", output);
        }

        return Ok(());
    }

    // Choose display mode
    if args.no_tui {
        // Text-based output
        info!("");
        display_analysis(&analysis);
    } else {
        // Interactive TUI with integrated symbol/file views
        run_tui(layout, analysis, &parser)?;
    }

    Ok(())
}

fn run_tui(
    layout: MemoryLayout,
    analysis: crate::models::AnalysisResult,
    parser: &ElfParser,
) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run
    let mut app = App::new(layout, analysis, parser);
    let res = app.run(&mut terminal);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

/// Display top N symbols by size with source file information
fn display_top_symbols(parser: &ElfParser, n: usize, ram_size: Option<u64>) -> Result<()> {
    info!(
        "{}",
        format!("Top {} Symbols by Size", n).bright_yellow().bold()
    );
    info!("{}", "-".repeat(100).bright_black());
    info!(
        "{:<40} {:<12} {:<14} {:<20}",
        "Symbol".bold(),
        "Size".bold(),
        "Address".bold(),
        "Source File".bold()
    );
    info!("{}", "-".repeat(100).bright_black());

    // Parse all symbols
    let mut symbols = parser.parse_all_symbols()?;

    // Sort by size (largest first)
    symbols.sort_by(|a, b| b.size.cmp(&a.size));

    let mut total_size = 0u64;

    // Display top N
    for symbol in symbols.iter().take(n) {
        total_size += symbol.size;

        let size_human = format_size_human(symbol.size);

        let source_file = symbol.source_file.as_deref().unwrap_or("UNKNOWN");

        info!(
            "{:<40} {:>10}  0x{:08x}     {:<20}",
            if symbol.name.len() > 40 {
                format!("{}...", &symbol.name[..37])
            } else {
                symbol.name.clone()
            },
            size_human.bright_yellow(),
            symbol.address,
            source_file
        );
    }

    // Display totals
    info!("{}", "-".repeat(100).bright_black());

    let total_human = format_size_human(total_size);

    info!(
        "{:<40} {:>10}",
        "Total:".bold(),
        total_human.bright_cyan().bold()
    );

    // Display RAM percentage if available
    if let Some(ram) = ram_size {
        let ram_percentage = (total_size as f64 / ram as f64) * 100.0;
        let ram_human = format_size_human(ram);

        let percentage_colored = if ram_percentage > 10.0 {
            format!("{:.2}%", ram_percentage).bright_red()
        } else {
            format!("{:.2}%", ram_percentage).bright_green()
        };

        info!(
            "{:<40} {} of {} total",
            "RAM Usage:".bold(),
            percentage_colored.bold(),
            ram_human.dimmed()
        );
    }

    info!("");
    Ok(())
}

/// Display memory analysis results in text mode (warnings, gaps, overlaps, padding)
fn display_analysis(analysis: &crate::models::AnalysisResult) {
    use colored::*;

    info!("{}", "Memory Analysis:".bright_yellow().bold());
    info!("{}", "-".repeat(80).bright_black());

    // Display warnings first (most important)
    if !analysis.warnings.is_empty() {
        info!("{}", "Warnings:".bright_red().bold());
        for warning in &analysis.warnings {
            info!("  {}", warning.bright_red());
        }
        info!("");
    }

    // Display gaps
    if !analysis.gaps.is_empty() {
        info!("{}", "Memory Gaps (unused regions):".bright_cyan());
        let mut flash_gaps = 0;
        let mut ram_gaps = 0;
        let mut flash_gap_size = 0u64;
        let mut ram_gap_size = 0u64;

        for gap in &analysis.gaps {
            match gap.region_type {
                crate::models::GapRegionType::Flash => {
                    flash_gaps += 1;
                    flash_gap_size += gap.size;
                }
                crate::models::GapRegionType::Ram => {
                    ram_gaps += 1;
                    ram_gap_size += gap.size;
                }
                _ => {}
            }

            info!(
                "  {:?}: 0x{:08x} - 0x{:08x} ({} bytes / {:.2} KB)",
                gap.region_type,
                gap.start,
                gap.end,
                gap.size,
                gap.size as f64 / 1024.0
            );
        }

        info!("");
        if flash_gaps > 0 {
            info!(
                "  Flash: {} gaps totaling {} bytes ({:.2} KB)",
                flash_gaps,
                flash_gap_size,
                flash_gap_size as f64 / 1024.0
            );
        }
        if ram_gaps > 0 {
            info!(
                "  RAM: {} gaps totaling {} bytes ({:.2} KB)",
                ram_gaps,
                ram_gap_size,
                ram_gap_size as f64 / 1024.0
            );
        }
        info!("");
    } else {
        info!(
            "  {} No memory gaps detected (sections are contiguous)",
            "✓".green()
        );
    }

    // Display overlaps
    if !analysis.overlaps.is_empty() {
        info!("\n{}", "Memory Overlaps:".bright_red().bold());
        for overlap in &analysis.overlaps {
            info!(
                "  {} ⚠ {} overlaps with {} at 0x{:08x}-0x{:08x} ({} bytes)",
                "ERROR:".bright_red().bold(),
                overlap.section1.bright_yellow(),
                overlap.section2.bright_yellow(),
                overlap.overlap_start,
                overlap.overlap_end,
                overlap.overlap_size
            );
        }
        info!("");
    }

    // Display padding
    if analysis.total_padding > 0 {
        info!(
            "Alignment Padding: {} bytes ({:.2} KB)",
            analysis.total_padding,
            analysis.total_padding as f64 / 1024.0
        );
    } else {
        info!("Alignment Padding: None detected");
    }

    // Display stack/heap gap
    if let Some(gap) = analysis.stack_heap_gap {
        let status = if gap == 0 {
            "CRITICAL".bright_red().bold()
        } else if gap < 1024 {
            "WARNING".bright_yellow().bold()
        } else if gap < 4096 {
            "CAUTION".yellow()
        } else {
            "OK".green()
        };

        info!(
            "Stack/Heap Gap: {} bytes ({:.2} KB) [{}]",
            gap,
            gap as f64 / 1024.0,
            status
        );
    } else {
        info!("Stack/Heap Gap: Not detected (no stack or heap sections found)");
    }
}
