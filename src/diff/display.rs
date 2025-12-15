//! Display formatting for memory diff output

use super::analyzer::{MemoryDiff, RegionStatus, SectionStatus};
use crate::utils::format_size_human;
use colored::*;

/// Display a complete memory diff to stdout
pub fn display_diff(diff: &MemoryDiff) {
    display_header(diff);

    if let Some(ref linker_diff) = diff.linker_diff {
        display_linker_changes(linker_diff);
    }

    display_section_summary(diff);
    display_text_section_changes(diff);
    display_data_section_changes(diff);
}

/// Display diff header with binary names
fn display_header(diff: &MemoryDiff) {
    println!();
    println!(
        "{}",
        format!("Memory Diff: {} → {}", diff.v1_info.path, diff.v2_info.path)
            .bright_cyan()
            .bold()
    );

    if let Some(ref linker_diff) = diff.linker_diff {
        if linker_diff.v1_script.is_some() && linker_diff.v2_script.is_some() {
            println!(
                "{}",
                format!(
                    "Linker Scripts: {} → {}",
                    linker_diff.v1_script.as_ref().unwrap(),
                    linker_diff.v2_script.as_ref().unwrap()
                )
                .dimmed()
            );
        } else if linker_diff.v1_script.is_some() {
            println!(
                "{}",
                format!("Linker Script: {}", linker_diff.v1_script.as_ref().unwrap()).dimmed()
            );
        }
    }

    println!("{}", "=".repeat(80).bright_black());
    println!();
}

/// Display linker script region changes
fn display_linker_changes(linker_diff: &super::analyzer::LinkerDiff) {
    let has_changes = linker_diff
        .region_changes
        .iter()
        .any(|r| r.status != RegionStatus::Unchanged);

    if !has_changes {
        return;
    }

    let scripts_changed = linker_diff.v1_script.is_some()
        && linker_diff.v2_script.is_some()
        && linker_diff.v1_script != linker_diff.v2_script;

    if scripts_changed {
        println!(
            "{}",
            "⚠️  Linker script changed! Memory region definitions updated:"
                .yellow()
                .bold()
        );
        println!();
    }

    // Show region changes
    let changed_regions: Vec<_> = linker_diff
        .region_changes
        .iter()
        .filter(|r| r.status != RegionStatus::Unchanged)
        .collect();

    if !changed_regions.is_empty() {
        println!("{}", "Region Changes:".bright_yellow().bold());
        println!("{}", "-".repeat(80).bright_black());
        println!(
            "{:<16} {:<12} {:<12} {}",
            "Region".bold(),
            "v1 Limit".bold(),
            "v2 Limit".bold(),
            "Change".bold()
        );
        println!("{}", "-".repeat(80).bright_black());

        for change in changed_regions {
            let v1_str = change
                .v1_size
                .map(format_size_human)
                .unwrap_or_else(|| "-".to_string());
            let v2_str = change
                .v2_size
                .map(format_size_human)
                .unwrap_or_else(|| "-".to_string());

            let change_str = match change.status {
                RegionStatus::New => "NEW".green().bold().to_string(),
                RegionStatus::Removed => "REMOVED ⚠️".red().bold().to_string(),
                RegionStatus::Modified => {
                    if let (Some(v1), Some(v2)) = (change.v1_size, change.v2_size) {
                        let delta = v2 as i64 - v1 as i64;
                        if delta > 0 {
                            format!(
                                "+{} ({})",
                                format_size_human(delta.unsigned_abs()),
                                if delta > (v1 as i64) {
                                    "doubled"
                                } else {
                                    "increased"
                                }
                            )
                            .green()
                            .to_string()
                        } else {
                            format!("-{} (decreased)", format_size_human(delta.unsigned_abs()))
                                .red()
                                .to_string()
                        }
                    } else {
                        "changed".yellow().to_string()
                    }
                }
                RegionStatus::Unchanged => "(no change)".dimmed().to_string(),
            };

            println!(
                "{:<16} {:<12} {:<12} {}",
                change.name, v1_str, v2_str, change_str
            );
        }

        println!();
        println!();
    }
}

/// Display section summary table
fn display_section_summary(diff: &MemoryDiff) {
    // Count new/removed sections
    let new_sections = diff
        .section_diffs
        .iter()
        .filter(|s| s.status == SectionStatus::New)
        .count();
    let removed_sections = diff
        .section_diffs
        .iter()
        .filter(|s| s.status == SectionStatus::Removed)
        .count();

    if new_sections > 0 || removed_sections > 0 {
        println!(
            "{}",
            format!(
                "⚠️  Section changes detected: {} new, {} removed",
                new_sections, removed_sections
            )
            .yellow()
            .bold()
        );
        println!();
    }

    println!("{}", "Section Summary:".bright_yellow().bold());
    println!("{}", "-".repeat(90).bright_black());
    println!(
        "{:<24} {:<12} {:<12} {:<12} {}",
        "Section".bold(),
        "v1 Size".bold(),
        "v2 Size".bold(),
        "Delta".bold(),
        "% Change".bold()
    );
    println!("{}", "-".repeat(90).bright_black());

    for section_diff in &diff.section_diffs {
        // Skip unchanged sections with zero size
        if section_diff.status == SectionStatus::Unchanged && section_diff.v1_size == Some(0) {
            continue;
        }

        let v1_str = section_diff
            .v1_size
            .map(|s| format!("{:>10} B", s.to_string().bright_white()))
            .unwrap_or_else(|| format!("{:>12}", "-"));

        let v2_str = section_diff
            .v2_size
            .map(|s| format!("{:>10} B", s.to_string().bright_white()))
            .unwrap_or_else(|| format!("{:>12}", "-"));

        let (delta_str, percent_str) = match section_diff.status {
            SectionStatus::New => {
                let delta = format!("+{:>9} B", section_diff.delta).green().bold();
                let percent = "NEW".green().bold();
                (delta.to_string(), percent.to_string())
            }
            SectionStatus::Removed => {
                let delta = format!("{:>10} B", section_diff.delta).red().bold();
                let percent = "REMOVED".red().bold();
                (delta.to_string(), percent.to_string())
            }
            SectionStatus::Modified => {
                let delta_colored = if section_diff.delta > 0 {
                    format!("+{:>9} B", section_diff.delta).yellow()
                } else if section_diff.delta < 0 {
                    format!("{:>10} B", section_diff.delta).green()
                } else {
                    format!("{:>10} B", section_diff.delta).dimmed()
                };

                let percent_colored = if section_diff.percent_change > 0.0 {
                    format!("{:+.2}%", section_diff.percent_change).yellow()
                } else if section_diff.percent_change < 0.0 {
                    format!("{:+.2}%", section_diff.percent_change).green()
                } else {
                    format!("{:.2}%", section_diff.percent_change).dimmed()
                };

                (delta_colored.to_string(), percent_colored.to_string())
            }
            SectionStatus::Unchanged => {
                let delta = format!("{:>10} B", 0).dimmed();
                let percent = format!("{:.2}%", 0.0).dimmed();
                (delta.to_string(), percent.to_string())
            }
        };

        // Mark new/removed sections
        let section_name = match section_diff.status {
            SectionStatus::New => format!("[NEW]     {}", section_diff.name)
                .green()
                .bold()
                .to_string(),
            SectionStatus::Removed => format!("[REMOVED] {}", section_diff.name)
                .red()
                .bold()
                .to_string(),
            _ => section_diff.name.clone(),
        };

        println!(
            "{:<24} {:<12} {:<12} {:<12} {}",
            section_name, v1_str, v2_str, delta_str, percent_str
        );
    }

    // Summary totals
    println!("{}", "-".repeat(90).bright_black());

    let flash_delta = diff.v2_info.total_flash_used as i64 - diff.v1_info.total_flash_used as i64;
    let ram_delta = diff.v2_info.total_ram_used as i64 - diff.v1_info.total_ram_used as i64;

    let flash_percent = if diff.v1_info.total_flash_used > 0 {
        (flash_delta as f64 / diff.v1_info.total_flash_used as f64) * 100.0
    } else {
        0.0
    };

    let ram_percent = if diff.v1_info.total_ram_used > 0 {
        (ram_delta as f64 / diff.v1_info.total_ram_used as f64) * 100.0
    } else {
        0.0
    };

    let flash_delta_str = if flash_delta > 0 {
        format!("+{:>9} B", flash_delta).yellow()
    } else if flash_delta < 0 {
        format!("{:>10} B", flash_delta).green()
    } else {
        format!("{:>10} B", flash_delta).dimmed()
    };

    let ram_delta_str = if ram_delta > 0 {
        format!("+{:>9} B", ram_delta).yellow()
    } else if ram_delta < 0 {
        format!("{:>10} B", ram_delta).green()
    } else {
        format!("{:>10} B", ram_delta).dimmed()
    };

    println!(
        "{:<24} {:<12} {:<12} {:<12} {}",
        "Total Flash".bold(),
        format!("{:>10} B", diff.v1_info.total_flash_used),
        format!("{:>10} B", diff.v2_info.total_flash_used),
        flash_delta_str,
        if flash_delta != 0 {
            format!("{:+.2}%", flash_percent).to_string()
        } else {
            format!("{:.2}%", flash_percent).dimmed().to_string()
        }
    );

    println!(
        "{:<24} {:<12} {:<12} {:<12} {}",
        "Total RAM".bold(),
        format!("{:>10} B", diff.v1_info.total_ram_used),
        format!("{:>10} B", diff.v2_info.total_ram_used),
        ram_delta_str,
        if ram_delta != 0 {
            format!("{:+.2}%", ram_percent).to_string()
        } else {
            format!("{:.2}%", ram_percent).dimmed().to_string()
        }
    );

    println!();
    println!();
}

/// Display .text section changes
fn display_text_section_changes(diff: &MemoryDiff) {
    if let Some(text_diff) = diff.section_diffs.iter().find(|s| s.name == ".text") {
        if text_diff.status == SectionStatus::Unchanged {
            return;
        }

        println!("{}", ".text Section Changes:".bright_yellow().bold());
        println!("{}", "-".repeat(80).bright_black());

        let delta_str = if text_diff.delta > 0 {
            format!(
                "+{} bytes ({:+.2}%)",
                text_diff.delta, text_diff.percent_change
            )
            .yellow()
        } else if text_diff.delta < 0 {
            format!(
                "{} bytes ({:+.2}%)",
                text_diff.delta, text_diff.percent_change
            )
            .green()
        } else {
            "0 bytes (0.00%)".to_string().dimmed()
        };

        println!("  {}", delta_str);
        println!();
        println!();
    }
}

/// Display data section symbol changes (.data, .rodata, .bss)
fn display_data_section_changes(diff: &MemoryDiff) {
    println!(
        "{}",
        "Data Sections Detailed Changes (.data, .rodata, .bss):"
            .bright_yellow()
            .bold()
    );
    println!("{}", "=".repeat(80).bright_black());
    println!();

    // Display .rodata changes
    display_section_symbol_changes(".rodata", &diff.symbol_changes.rodata_changes);

    // Display .data changes
    display_section_symbol_changes(".data", &diff.symbol_changes.data_changes);

    // Display .bss changes
    display_section_symbol_changes(".bss", &diff.symbol_changes.bss_changes);
}

/// Display symbol changes for a specific data section
fn display_section_symbol_changes(
    section_name: &str,
    changes: &super::analyzer::SectionSymbolChanges,
) {
    if changes.total_delta == 0
        && changes.new_symbols.is_empty()
        && changes.removed_symbols.is_empty()
        && changes.modified_symbols.is_empty()
    {
        println!("{} Changes: 0 bytes", section_name);
        println!("{}", "-".repeat(80).bright_black());
        println!("  No changes");
        println!();
        return;
    }

    let delta_str = if changes.total_delta > 0 {
        format!("+{} bytes", changes.total_delta).yellow()
    } else if changes.total_delta < 0 {
        format!("{} bytes", changes.total_delta).green()
    } else {
        "0 bytes".to_string().dimmed()
    };

    println!("{} Changes: {}", section_name, delta_str);
    println!("{}", "-".repeat(80).bright_black());

    // Summary line
    if !changes.new_symbols.is_empty()
        || !changes.removed_symbols.is_empty()
        || !changes.modified_symbols.is_empty()
    {
        println!(
            "[NEW symbols: {}, REMOVED: {}, MODIFIED: {}]",
            changes.new_symbols.len(),
            changes.removed_symbols.len(),
            changes.modified_symbols.len()
        );
        println!();
    }

    // Combine all changes and sort by absolute delta (largest impact first)
    let mut all_changes: Vec<(String, i64, ChangeType)> = Vec::new();

    for sym in &changes.new_symbols {
        all_changes.push((sym.name.clone(), sym.size as i64, ChangeType::New(sym.size)));
    }

    for sym in &changes.removed_symbols {
        all_changes.push((
            sym.name.clone(),
            -(sym.size as i64),
            ChangeType::Removed(sym.size),
        ));
    }

    for sym in &changes.modified_symbols {
        all_changes.push((
            sym.name.clone(),
            sym.delta,
            ChangeType::Modified(sym.v1_size, sym.v2_size),
        ));
    }

    // Sort by absolute delta (largest first)
    all_changes.sort_by(|a, b| b.1.abs().cmp(&a.1.abs()));

    // Display top changes (limit to 10 for readability)
    let display_count = all_changes.len().min(10);
    if display_count > 0 {
        println!(
            "Top Changes (showing top {} by absolute delta):",
            display_count
        );

        for (name, delta, change_type) in all_changes.iter().take(display_count) {
            match change_type {
                ChangeType::New(size) => {
                    println!(
                        "  {:<12} {:<40} {:>12} {:>12} {:>12}",
                        "[NEW]".green().bold(),
                        truncate_symbol_name(name, 40),
                        "-",
                        format!("{} B", size),
                        format!("+{} B", delta).green()
                    );
                }
                ChangeType::Removed(size) => {
                    println!(
                        "  {:<12} {:<40} {:>12} {:>12} {:>12}",
                        "[REMOVED]".red().bold(),
                        truncate_symbol_name(name, 40),
                        format!("{} B", size),
                        "-",
                        format!("{} B", delta).red()
                    );
                }
                ChangeType::Modified(v1_size, v2_size) => {
                    let delta_colored = if *delta > 0 {
                        format!("+{} B", delta).yellow()
                    } else {
                        format!("{} B", delta).green()
                    };

                    println!(
                        "  {:<12} {:<40} {:>12} {:>12} {:>12}",
                        "[MODIFIED]".yellow(),
                        truncate_symbol_name(name, 40),
                        format!("{} B", v1_size),
                        format!("{} B", v2_size),
                        delta_colored
                    );
                }
            }
        }

        if all_changes.len() > display_count {
            println!(
                "  {} (and {} more changes)",
                "...".dimmed(),
                all_changes.len() - display_count
            );
        }
    }

    println!();
}

enum ChangeType {
    New(u64),
    Removed(u64),
    Modified(u64, u64),
}

/// Truncate symbol name to max length
fn truncate_symbol_name(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else {
        format!("{}...", &name[..max_len - 3])
    }
}
