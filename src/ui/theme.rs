use crate::models::SectionType;
use ratatui::style::Color;

pub fn section_color(section_type: &SectionType) -> Color {
    match section_type {
        SectionType::Text => Color::Green,
        SectionType::RoData => Color::Blue,
        SectionType::Data => Color::Yellow,
        SectionType::Bss => Color::Magenta,
        SectionType::Stack => Color::Red,
        SectionType::Heap => Color::Cyan,
        SectionType::Custom(_) => Color::Gray,
    }
}
