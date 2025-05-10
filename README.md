# Escavator

Escavator is a command-line utility for locating “code caves” in executable files and optionally injecting shellcode or creating new executable sections. It supports PE, ELF and Mach-O formats, and provides extensive filtering, reporting and injection features.

## What Is a Code Cave?

A **code cave** is a contiguous run of padding bytes (for example, `0x00`, `0xCC`, or other patterns) inside an executable file. Attackers and researchers often use code caves to insert custom shellcode without enlarging the file. Escavator locates these runs, reports their offsets and sizes, and can inject shellcode into an existing cave or create a new section if none are large enough.

## Features

- **Multi-format support**: PE, ELF, Mach-O, or raw binaries  
- **Pattern-based scanning**: Search for any byte-pattern (repeatable flag `-p`)  
- **Section-constrained scan**: `--scan-sections` or `--skip-sections`  
- **Statistical summary**: count, min/max/mean/median, percentiles, ASCII histogram  
- **Filtering**: offset range (`--min-offset`, `--max-offset`), alignment (`--align`), disassembly-based (`--disasm-filter`)  
- **Progress bar**: configurable percent interval (`--progress-interval`)  
- **Structured output**: JSON (`--json`) or CSV export (`--export`)  
- **Injection**:  
  - In-place into existing cave (`--inject`)  
  - Interactive selection (`--interactive`)  
  - Add new section if needed (`--add-section`)  
  - PE checksum update (`--update-checksum`), Authenticode stripping (`--strip-cert`)  
  - Entry-point redirection (`--redirect-ep`)  
- **Logging & verbosity**: `--verbose`, `--log-file`  
- **Cross-platform**: Runs under Windows, Linux and macOS

## Installation

1. Create a virtual environment (recommended)  
   ```bash
   python3 -m venv venv
   source venv/bin/activate    # On Windows: venv\Scripts\activate
   ```
2. Install dependencies  
   ```bash
   pip install -r requirements.txt
   ```

## Usage

```text
usage: escavator.py [-h] [-p PATTERN] [--pattern-file FILE] [-m MIN_SIZE]
                    [--min-offset OFFSET] [--max-offset OFFSET]
                    [--scan-sections SECTIONS] [--skip-sections SECTIONS]
                    [--top N] [-e EXPORT] [-i INJECT] [--add-section]
                    [--update-checksum] [--strip-cert] [--align ALIGN]
                    [--disasm-filter] [--interactive]
                    [--progress-interval PERCENT] [--redirect-ep] [--json]
                    [--no-color] [-v] [--log-file LOG]
                    input
```

- **`input`**: Path to the target executable  
- `-p, --pattern` : Byte-pattern to search (e.g. `' '`), repeatable  
- `--pattern-file` : File containing one hex-pattern per line  
- `-m, --min-size` : Minimum cave size in bytes (default: 32)  
- `--min-offset`, `--max-offset` : Filter caves by file offset  
- `--scan-sections`, `--skip-sections` : Limit or exclude specific sections  
- `--top N` : Show only top N largest caves  
- `-e, --export` : Write full cave list to CSV  
- `-i, --inject` : Path to shellcode to inject  
- `--add-section` : If no cave is large enough, add a new section  
- `--update-checksum` : Recompute PE checksum after injection  
- `--strip-cert` : Remove PE Authenticode certificate  
- `--align` : Require injection offset alignment (bytes)  
- `--disasm-filter` : Skip runs that disassemble into valid instructions  
- `--interactive` : Prompt to select one cave for injection  
- `--progress-interval` : Percent step for progress bar (0 to disable)  
- `--redirect-ep` : Redirect entry point to injected code  
- `--json` : Output metadata, stats and runs in JSON  
- `--no-color` : Disable ANSI color output  
- `-v, --verbose` : Enable debug logging  
- `--log-file` : Write logs to a file  

## Examples

- **Scan for zero-byte caves of at least 64 bytes**  
  ```bash
  escavator.py target.bin -m 64
  ```

- **Scan only `.data` and `.rsrc` sections for `0xCC` padding**  
  ```bash
  escavator.py target.exe -p '\x00' --scan-sections .data,.rsrc
  ```

- **Export all found caves to CSV**  
  ```bash
  escavator.py target.elf --export caves.csv
  ```

- **Inject shellcode into the first suitable cave**  
  ```bash
  escavator.py target.bin --inject payload.bin
  ```

- **If no cave is large enough, add a new section and update PE checksum**  
  ```bash
  escavator.py target.exe --inject payload.bin --add-section --update-checksum
  ```

- **Interactive selection of cave and entry-point redirection**  
  ```bash
  escavator.py target.exe --inject payload.bin --interactive --redirect-ep
  ```

- **JSON output for automated pipelines**  
  ```bash
  escavator.py target.bin --json > results.json
  ```

## License

This project is licensed under MIT License. See [LICENSE](LICENSE) for details.
