# MemScope

**Interactive Memory Layout Visualizer for ARM Embedded Systems**

MemScope is a Rust-based CLI tool for analyzing and visualizing memory layouts of ARM embedded ELF binaries. It helps embedded developers understand firmware memory usage, detect issues, and optimize Flash and RAM allocation.

## Features

### Interactive TUI
- **Multi-tab interface**: Memory sections, Symbols, Files, Statistics, and Region Explorer
- **Visual memory gauges**: Real-time Flash and RAM usage with percentages
- **Color-coded display**: Quick identification of section types
- **Fuzzy search**: Fast symbol and file lookup
- **Keyboard navigation**: Vim-style keybindings (j/k, ↑/↓)

### Memory Analysis
- **Gap detection**: Identifies unused memory between sections
- **Overlap detection**: Catches memory conflicts
- **Padding analysis**: Reveals alignment waste
- **Stack/heap monitoring**: Warns about collision risks
- **Usage warnings**: Automatic alerts when approaching memory limits

### Symbol Explorer
- **Live fuzzy search**: Find symbols instantly as you type
- **Symbol details**: Address, size, type, binding, visibility, source file
- **Size ranking**: See top memory consumers
- **Neighbor analysis**: View adjacent symbols in memory
- **Statistics dashboard**: Symbol distribution and namespace analysis

### Display Modes
- **Interactive TUI** (default): Full-featured terminal interface
- **Text mode** (`--no-tui`)

## Installation

```bash
# Clone and build
git clone https://github.com/your-repo/memscope
cd memscope
cargo build --release

# The binary will be in target/release/memscope
```

## Usage

### Basic Usage

```bash
# Interactive TUI mode
memscope firmware.elf

# Text mode for scripting
memscope firmware.elf --no-tui

# With specific memory sizes
memscope firmware.elf --flash-size 524288 --ram-size 262144

# Show top N symbols by size
memscope firmware.elf --top 20
```

### Export Formats

MemScope supports multiple export formats for CI/CD integration and reporting:

```bash
# JSON export (machine-readable)
memscope firmware.elf --export json --output report.json
memscope firmware.elf --export json  # to stdout

# CSV exports
memscope firmware.elf --export csv --output symbols.csv           # Symbol table (default)
memscope firmware.elf --export csv:sections --output sections.csv # Section summary
memscope firmware.elf --export csv:analysis --output analysis.csv # Analysis data

# Markdown report
memscope firmware.elf --export markdown --output MEMORY.md
memscope firmware.elf --export md  # alias, to stdout
```

**Use Cases:**
- **JSON**: Automated size tracking, CI/CD pipelines, regression detection
- **CSV**: Spreadsheet analysis, symbol tracking, size optimization
- **Markdown**: Documentation, build reports, GitHub Actions summaries

### Keyboard Shortcuts

#### Memory View
- `1` or `Tab` - Memory sections tab
- `2` - Symbols tab
- `3` - Files tab
- `4` - Statistics tab
- `5` - Region Explorer tab
- `↑/↓` or `j/k` - Navigate list
- `PgUp/PgDn` - Scroll details
- `h/?` - Toggle help
- `q/Esc` - Quit

#### Symbol/Files View
- `ctrl+/` - To enter in search mode
- `Enter` - To validate the search entry
- `↑/↓` or `j/k` - Navigate results
- `Backspace` - Delete character
- `Esc` - Clear search and exit search mode

#### Region Explorer
- `↑/↓` or `j/k` - Navigate symbols
- `z` - Zoom in (show more symbols)
- `Z` - Zoom out (show fewer symbols)
- `PgUp/PgDn` - Scroll memory map

## CI/CD Integration Examples

### GitHub Actions - Size Regression Check

```yaml
name: Memory Check
on: [push, pull_request]

jobs:
  memory-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build firmware
        run: make build

      - name: Install MemScope
        run: |
          cargo install --git https://github.com/your-repo/memscope

      - name: Analyze memory
        run: |
          memscope build/firmware.elf --export json --output memory-report.json

      - name: Check Flash usage
        run: |
          FLASH_PCT=$(jq -r '.memory.flash.percentage // 0' memory-report.json)
          if (( $(echo "$FLASH_PCT > 85" | bc -l) )); then
            echo "⚠️ Flash usage is ${FLASH_PCT}% (exceeds 85% threshold)"
            exit 1
          fi

      - name: Generate report
        run: |
          memscope build/firmware.elf --export markdown --output MEMORY.md
          cat MEMORY.md >> $GITHUB_STEP_SUMMARY
```

### Track Memory Trends

```bash
# Compare two builds
memscope firmware-v1.elf --export json --output v1.json
memscope firmware-v2.elf --export json --output v2.json

# Calculate Flash change with jq
FLASH_DIFF=$(jq -n --slurpfile v1 v1.json --slurpfile v2 v2.json \
  '($v2[0].memory.flash.used - $v1[0].memory.flash.used)')

echo "Flash changed by: $FLASH_DIFF bytes"
```

## Example Output

### Text Mode Summary
```
Memory Summary:
--------------------------------------------------------------------------------
Total Flash used: 366776 bytes (0x598b8) / 358.18 KB [70.0%] of 512.00 KB
Total RAM used:   229996 bytes (0x3826c) / 224.61 KB [87.7%] of 256.00 KB

Memory Analysis:
--------------------------------------------------------------------------------
Warnings:
  ⚠ RAM usage is 87.7% - consider optimization

Memory Gaps (unused regions):
  Ram: 0x20002c60 - 0x20004000 (5024 bytes / 4.91 KB)
  RAM: 1 gaps totaling 5024 bytes (4.91 KB)

Alignment Padding: 4 bytes (0.00 KB)
```

## Memory Size Detection

MemScope automatically detects memory sizes based on section addresses and rounds to common embedded sizes (64KB, 128KB, 256KB, 512KB, 1MB, etc.).

Override with `--flash-size` and `--ram-size` for exact values:

```bash
memscope firmware.elf --flash-size 524288 --ram-size 262144
```

## Supported Platforms

- ARM Cortex-M microcontrollers (nRF52, STM32, etc.)
- ELF binaries from `arm-none-eabi-gcc` toolchain
- Any embedded ARM binary with standard ELF format

## Development

```bash
# Run tests
cargo test

# Check compilation
cargo c

# Run on sample firmware
cargo run -- file.elf

# Build optimized release
cargo build --release
```

## License

TBD

## Acknowledgments

Built with:
- [ratatui](https://github.com/ratatui-org/ratatui) - Terminal UI framework
- [goblin](https://github.com/m4b/goblin) - ELF parsing
- [fuzzy-matcher](https://github.com/lotabout/fuzzy-matcher) - Fuzzy searching
- [crossterm](https://github.com/crossterm-rs/crossterm) - Terminal manipulation
