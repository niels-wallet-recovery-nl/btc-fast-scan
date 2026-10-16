#!/usr/bin/env python3
"""
Bitcoin Address Sorter for Memory-Efficient BBF Accumulator Builds.

Sorts addresses by routing signature (prefix + first 2 chars) so that
the accumulator builder can stream chunks sequentially with minimal RAM.

Usage:
    # Internal Python sort (simple, good for < 1M addresses)
    python3 0_sort_addresses.py -i raw.txt -o sorted.txt
    
    # External GNU sort (recommended for 10M+ addresses)
    python3 0_sort_addresses.py -i raw.txt -o sorted.txt --external
    
    # Pipe support
    cat raw.txt | python3 0_sort_addresses.py -o sorted.txt --external
"""

import sys, os, argparse, tempfile, subprocess, hashlib

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
PREFIX_MAP = {
    '1': '0',   # Legacy (starts with 1)
    '3': '1',   # P2SH (starts with 3)
    'bc1q': '2', # Bech32 (segwit v0)
    'bc1p': '3', # Bech32m (taproot)
}

def parse_line(line):
    """Extract address from line."""
    addr = line.strip().split()[0].strip()
    return addr if addr and 20 <= len(addr) <= 62 else None

def get_prefix(addr):
    """Determine prefix type."""
    if addr.startswith('bc1p'):
        return 'bc1p'
    elif addr.startswith('bc1q'):
        return 'bc1q'
    elif addr.startswith('1'):
        return '1'
    elif addr.startswith('3'):
        return '3'
    return None

def compute_sort_key(addr):
    """
    Compute 3-byte sortable key for address.
    
    Format: [prefix_type][char1_idx][char2_idx]
    
    Examples:
        '1abc...' → [0][idx('a')][idx('b')]  → b'\x00\x00\x01'
        'bc1qar...' → [2][idx('a')][idx('r')] → b'\x02\x00\x17'
    """
    prefix = get_prefix(addr)
    if prefix is None:
        return b'\xff\xff\xff'  # Unknown prefixes sorted to end
    
    # Get characters after prefix
    if prefix in ('bc1q', 'bc1p'):
        char1 = addr[4] if len(addr) > 4 else '\x00'
        char2 = addr[5] if len(addr) > 5 else '\x00'
    else:  # '1' or '3'
        char1 = addr[1] if len(addr) > 1 else '\x00'
        char2 = addr[2] if len(addr) > 2 else '\x00'
    
    # Convert to base58 indices (0-57)
    idx1 = BASE58_ALPHABET.index(char1) if char1 in BASE58_ALPHABET else 0
    idx2 = BASE58_ALPHABET.index(char2) if char2 in BASE58_ALPHABET else 0
    
    # Return compact 3-byte key
    return bytes([
        ord(PREFIX_MAP[prefix]),
        idx1,
        idx2
    ])

def compute_sort_key_text(addr):
    """Alternative: Text-based sort key for GNU sort compatibility."""
    prefix = get_prefix(addr)
    if prefix is None:
        return 'zz:'  # Unknown prefixes sorted to end
    
    if prefix in ('bc1q', 'bc1p'):
        char1 = addr[4] if len(addr) > 4 else '1'
        char2 = addr[5] if len(addr) > 5 else '1'
    else:
        char1 = addr[1] if len(addr) > 1 else '1'
        char2 = addr[2] if len(addr) > 2 else '1'
    
    # Format: PREFIX:CHAR1CHAR2 (e.g., "2:ar" for bc1qar...)
    return f"{PREFIX_MAP[prefix]}:{char1}{char2}"

def internal_sort(input_src, output_path, verbose=True):
    """Sort using Python's in-memory Timsort."""
    if verbose:
        print("[INFO] Using Python internal sort...", flush=True)
        print(f"{'='*70}", flush=True)
    
    # Read and compute keys
    addresses = []
    count = 0
    unknown_count = 0
    
    source = sys.stdin if not input_src else open(input_src, 'r', errors='ignore')
    try:
        for line in source:
            addr = parse_line(line)
            if addr:
                sort_key = compute_sort_key(addr)
                addresses.append((sort_key, addr))
                count += 1
                
                if count % 1000000 == 0:
                    if verbose:
                        print(f"    Loaded {count:,} addresses...", flush=True)
    finally:
        if input_src:
            source.close()
    
    # Sort by binary key
    if verbose:
        print(f"\n[INFO] Sorting {count:,} addresses...", flush=True)
    
    addresses.sort(key=lambda x: x[0])
    
    if verbose:
        print(f"  ✓ Sorting complete", flush=True)
    
    # Write output (just addresses, no keys)
    if verbose:
        print(f"\n[INFO] Writing to {output_path}...", flush=True)
    
    with open(output_path, 'w') as f:
        for _, addr in addresses:
            f.write(addr + '\n')
    
    size = os.path.getsize(output_path)
    if verbose:
        print(f"\n{'='*70}\nCOMPLETE\n{'='*70}", flush=True)
        print(f"Total addresses:    {count:>12,}")
        print(f"Unknown prefixes:   {unknown_count:>12,}")
        print(f"Output size:        {size:>12,} bytes ({size/1024/1024:.1f} MB)")
        print(f"{'='*70}\n", flush=True)
    
    return count

def external_sort(input_src, output_path, temp_dir=None, verbose=True):
    """Sort using GNU sort with text keys (much faster for large files)."""
    if verbose:
        print("[INFO] Using external GNU sort...", flush=True)
        print(f"{'='*70}", flush=True)
        print("  Phase 1: Prepend sort keys to each address")
        print("  Phase 2: GNU sort (external, uses disk for overflow)")
        print("  Phase 3: Strip keys, write final output")
        print()
    
    # Create temporary files
    temp_dir = temp_dir or tempfile.gettempdir()
    keyed_file = os.path.join(temp_dir, f'bloom_tmp_keys_{os.getpid()}.txt')
    sorted_file = os.path.join(temp_dir, f'bloom_tmp_sorted_{os.getpid()}.txt')
    
    # Cleanup handler
    import atexit
    def cleanup():
        try:
            os.remove(keyed_file)
        except: pass
        try:
            os.remove(sorted_file)
        except: pass
    atexit.register(cleanup)
    
    # Phase 1: Add keys
    if verbose:
        print("[Phase 1] Adding sort keys...")
    
    count = 0
    source = sys.stdin if not input_src else open(input_src, 'r', errors='ignore')
    keyed_out = open(keyed_file, 'w')
    
    try:
        for line in source:
            addr = parse_line(line)
            if addr:
                key = compute_sort_key_text(addr)
                keyed_out.write(f"{key}\t{addr}\n")
                count += 1
                
                if count % 1000000 == 0:
                    if verbose:
                        print(f"    Added keys for {count:,} addresses...", flush=True)
    finally:
        if input_src:
            source.close()
        keyed_out.close()
    
    # Phase 2: GNU sort
    if verbose:
        print(f"[Phase 2] Running GNU sort on {os.path.getsize(keyed_file)/1024/1024:.1f} MB...")
    
    sort_cmd = [
        'sort', '-t\t', '-k1,1',  # Tab-separated, sort by key column
        '--parallel=8',           # Parallel sorting
        '--buffer-size=50%',      # Use half available RAM
        keyed_file,
        '-o', sorted_file
    ]
    
    try:
        subprocess.run(sort_cmd, check=True, capture_output=(not verbose))
    except FileNotFoundError:
        print("[ERROR] GNU 'sort' not found. Install coreutils or use --internal.", 
              file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] GNU sort failed: {e.stderr.decode()}", file=sys.stderr)
        sys.exit(1)
    
    if verbose:
        print(f"  ✓ Sorting complete")
    
    # Phase 3: Strip keys
    if verbose:
        print(f"[Phase 3] Stripping keys, writing to {output_path}...")
    
    with open(sorted_file, 'r') as src, open(output_path, 'w') as dst:
        for line in src:
            addr = line.split('\t', 1)[1].rstrip('\n')
            dst.write(addr + '\n')
    
    size = os.path.getsize(output_path)
    
    if verbose:
        print(f"\n{'='*70}\nCOMPLETE\n{'='*70}", flush=True)
        print(f"Total addresses:    {count:>12,}")
        print(f"Output size:        {size:>12,} bytes ({size/1024/1024:.1f} MB)")
        print(f"{'='*70}\n", flush=True)
    
    # Cleanup temp files
    try:
        os.remove(keyed_file)
        os.remove(sorted_file)
    except: pass
    
    return count

def validate_sorted(input_path, verbose=True):
    """Verify that addresses are properly sorted by chunk routing."""
    if verbose:
        print("[INFO] Validating sorted output...", flush=True)
    
    prev_key = None
    violations = 0
    count = 0
    
    with open(input_path, 'r') as f:
        for line in f:
            addr = parse_line(line)
            if addr:
                curr_key = compute_sort_key(addr)
                
                if prev_key is not None and curr_key < prev_key:
                    violations += 1
                    if violations <= 5 and verbose:
                        print(f"  WARNING: Out of order at line {count}: {curr_key} < {prev_key}", 
                              file=sys.stderr)
                
                prev_key = curr_key
                count += 1
            
            if count % 1000000 == 0 and verbose:
                print(f"    Validated {count:,} addresses...", flush=True)
    
    if verbose:
        print(f"  ✓ Validation complete: {violations} violations in {count:,} addresses")
    
    return violations == 0

def main():
    parser = argparse.ArgumentParser(
        description='Bitcoin Address Sorter for BBF Accumulator (Memory Optimized)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    Examples:
        # Internal Python sort (small datasets)
        python3 0_sort_addresses.py -i addresses.txt -o sorted.txt
        
        # External GNU sort (large datasets, recommended)
        python3 0_sort_addresses.py -i addresses.txt -o sorted.txt --external
        
        # Pipe from stdin
        cat addresses.txt | python3 0_sort_addresses.py -o sorted.txt --external
        
        # Validate existing sorted file
        python3 0_sort_addresses.py -i sorted.txt --validate
    """
    )

    parser.add_argument('-i', '--input', dest='src', default=None,
                        help='Input address file (default: STDIN)')
    parser.add_argument('-o', '--output', default=None,  # Changed: required=False
                        help='Output sorted file')
    parser.add_argument('--internal', action='store_true',
                        help='Use Python internal sort (default for < 1M addresses)')
    parser.add_argument('--external', action='store_true',
                        help='Use GNU sort (recommended for 10M+ addresses)')
    parser.add_argument('-t', '--temp-dir', default=None,
                        help='Temporary directory for external sort')
    parser.add_argument('--validate', action='store_true',
                        help='Validate that input is already sorted')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress progress output')

    args = parser.parse_args()

    # Validate mode - output not required
    if args.validate:
        if not args.src:
            print("[ERROR] --validate requires -i/--input", file=sys.stderr)
            sys.exit(1)
        success = validate_sorted(args.src, not args.quiet)
        sys.exit(0 if success else 1)

    # Non-validate mode - output IS required
    if args.output is None:
        print("[ERROR] -o/--output is required for sort mode", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()