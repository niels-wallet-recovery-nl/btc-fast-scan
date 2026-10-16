#!/usr/bin/env python3
"""BBF Accumulator Verifier - pipes addresses through, outputs matches only.
Compatible with chunked RSA accumulator (base64, prime_bits, patterns).

Example use:

# FROM FILE (stdout = matched addresses only)
cat test_addresses.txt | python3 2_verify.py -f accumulator.json > matched.txt

# FROM STDIN (pipe)
grep "bc1q" my_wallet.log | python3 2_verify.py -f accumulator.json

# WITH DEBUG (timing on stderr)
cat wallet_dump.txt | python3 2_verify.py -f accumulator.json --debug

# SAVE MATCHES AND LOG TIMING
cat addresses.txt | python3 2_verify.py -f accumulator.json --debug > matches.txt 2> timing.log
##################################

Example usage
# Basic filter (fast, divisibility only)
cat addresses.txt | python3 2_verify.py -f accumulator.json > matches.txt

# With full proofs (slow - multi-second per match!)
cat addresses.txt | python3 2_verify.py -f accumulator.json --prove > matches.txt

# Debug mode (timing to stderr)
cat addresses.txt | python3 2_verify.py -f accumulator.json --debug 2> timing.log > matches.txt

"""

from Crypto.Util.number import bytes_to_long, isPrime
import json, sys, argparse, hashlib, time, base64, os

try:
    sys.set_int_max_str_digits(0)
except AttributeError:
    pass

# ==============================================================================
# CONSTANTS (matching our accumulator)
# ==============================================================================

PRIME_BITS_DEFAULT = 112
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
DEFAULT_PREFIXES_BTC = ['bc1q', 'bc1p', '1', '3']
DEFAULT_PREFIXES_ETH = ['0x']

# ==============================================================================
# HELPER FUNCTIONS (matching our accumulator)
# ==============================================================================

def get_alphabet(encoding):
    """Return alphabet based on encoding type."""
    if encoding.lower() == 'hex':
        return '0123456789abcdefABCDEF'
    return BASE58_ALPHABET

def addr_to_prime(addr: str, bits: int = PRIME_BITS_DEFAULT) -> int:
    """Address -> prime via SHA256, masked to fixed bit width (matches build)."""
    h = hashlib.sha256(addr.encode()).digest()
    candidate = (1 << (bits - 1)) | (bytes_to_long(h) & ((1 << (bits - 1)) - 1))
    candidate |= 1
    while not isPrime(candidate):
        candidate += 2
    return candidate

def b64d(s: str) -> int:
    """Base64 decode big-int (matches our b64e)."""
    return int.from_bytes(base64.b64decode(s), 'big')

def get_chunk_pattern(addr, prefixes, depth, alphabet):
    """Extract chunk pattern (matches our build process)."""
    matched_prefix = None
    for prefix in prefixes:
        if addr.startswith(prefix):
            matched_prefix = prefix
            break
    
    if not matched_prefix:
        return None, None, None
    
    start_idx = len(matched_prefix)
    chars_needed = depth
    
    if len(addr) < start_idx + chars_needed:
        chars = addr[start_idx:].ljust(chars_needed, alphabet[0])
    else:
        chars = addr[start_idx:start_idx + chars_needed]
    
    for i, c in enumerate(chars):
        if c not in alphabet:
            chars = chars[:i] + alphabet[0] * (chars_needed - i)
            break
    
    pattern = f"{matched_prefix}:{chars}"
    return matched_prefix, chars, pattern

# ==============================================================================
# LOADER (lazy cache for chunk products)
# ==============================================================================

class AccumulatorContext:
    """Lazy-loaded accumulator with cached chunk products."""
    
    def __init__(self, path: str):
        with open(path) as f:
            self.data = json.load(f)
        
        chunk_path = path.replace('.json', '_chunks.json')
        if not os.path.exists(chunk_path):
            raise FileNotFoundError(f"Chunk file not found: {chunk_path}")
        
        with open(chunk_path) as f:
            self.chunks = json.load(f)
        
        # Parse once
        self.n = int(self.data['rsa_params']['modulus_n'], 16)
        self.g = int(self.data['rsa_params']['generator_g'])
        self.s = int(self.data['trapdoor_s'], 16)
        self.encoding = self.data.get('encoding', 'base58')
        self.depth = self.data.get('chunk_depth', 2)
        self.prefixes = self.data.get('prefixes', DEFAULT_PREFIXES_BTC)
        self.prime_bits = self.data.get('prime_bits', PRIME_BITS_DEFAULT)
        self.alphabet = get_alphabet(self.encoding)
        
        # Chunk index for O(1) pattern lookup
        self.chunk_map = {c['pattern']: c for c in self.chunks}
        
        # Lazy-decoded products (cache per pattern)
        self.product_cache = {}
    
    def get_chunk_product(self, pattern: str) -> int:
        """Lazy-decode chunk product, cache for reuse."""
        if pattern not in self.product_cache:
            chunk = self.chunk_map.get(pattern)
            if not chunk:
                return None
            self.product_cache[pattern] = b64d(chunk['chunk_product'])
        return self.product_cache[pattern]

# ==============================================================================
# VERIFICATION (divisibility oracle, optional proof)
# ==============================================================================

def verify_one(ctx: AccumulatorContext, address: str, prove=False) -> tuple:
    """
    Verify single address.
    
    Returns: (found: bool, time_us: float, reason: str)
    
    Fast path: divisibility check (s+x) | P
    Slow path: full witness verification (optional)
    """
    t0 = time.perf_counter()
    
    # Get pattern
    prefix, chars, pattern = get_chunk_pattern(address, ctx.prefixes, ctx.depth, ctx.alphabet)
    if not pattern:
        return False, (time.perf_counter() - t0) * 1_000_000, "no prefix match"
    
    # Get chunk
    chunk = ctx.chunk_map.get(pattern)
    if not chunk:
        return False, (time.perf_counter() - t0) * 1_000_000, "no chunk"
    
    # Derive prime
    x = addr_to_prime(address, bits=ctx.prime_bits)
    term = ctx.s + x
    
    # Get chunk product (cached)
    P = ctx.get_chunk_product(pattern)
    if P is None:
        return False, (time.perf_counter() - t0) * 1_000_000, "missing product"
    
    # Fast path: divisibility oracle
    if P % term != 0:
        return False, (time.perf_counter() - t0) * 1_000_000, "not divisible"
    
    # If prove=True, verify witness (slow)
    if prove:
        A = b64d(chunk['chunk_accumulator'])
        excluded = P // term
        proof = pow(ctx.g, excluded, ctx.n)
        if pow(proof, term, ctx.n) != A:
            return False, (time.perf_counter() - t0) * 1_000_000, "proof mismatch"
    
    return True, (time.perf_counter() - t0) * 1_000_000, "found"

# ==============================================================================
# BATCH PROCESSING (stdin -> stdout, matches only)
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description='BBF Accumulator Verifier (chunked, base64)')
    parser.add_argument('-f', '--file', required=True, help='Accumulator JSON file')
    parser.add_argument('--debug', action='store_true', help='Verbose output to stderr')
    parser.add_argument('--prove', action='store_true', help='Full witness verification (slow)')
    parser.add_argument('--show-nonmembers', action='store_true', help='Print non-members (commented)')
    args = parser.parse_args()
    
    # Load context (cached)
    try:
        ctx = AccumulatorContext(args.file)
        if args.debug:
            print(f"[DEBUG] Loaded {len(ctx.chunks)} chunks, {ctx.data.get('address_count', '?'):,} addresses",
                  file=sys.stderr, flush=True)
    except Exception as e:
        print(f"[ERROR] Failed to load accumulator: {e}", file=sys.stderr)
        sys.exit(1)
    
    total_start = time.perf_counter()
    matches, total = 0, 0
    seen = set()  # Dedup
    
    for line_num, line in enumerate(sys.stdin, 1):
        addr = line.strip().split()[0] if line.strip() else None
        if not addr or len(addr) < 20:
            continue
        
        # Dedup
        if addr in seen:
            if args.debug:
                print(f"[DEBUG] Line {line_num}: DUPLICATE", file=sys.stderr, flush=True)
            continue
        seen.add(addr)
        
        total += 1
        found, elapsed_us, reason = verify_one(ctx, addr, prove=args.prove)
        
        if found:
            matches += 1
            print(addr, flush=True)  # Matched addresses -> stdout
            if args.debug:
                print(f"[DEBUG] Line {line_num}: {addr[:20]}... FOUND ({elapsed_us:.1f}µs)",
                      file=sys.stderr, flush=True)
        else:
            if args.show_nonmembers:
                print(f"# NONMEMBER {addr} ({reason})", file=sys.stderr, flush=True)
            if args.debug:
                print(f"[DEBUG] Line {line_num}: {addr[:20]}... NOT FOUND ({elapsed_us:.1f}µs, {reason})",
                      file=sys.stderr, flush=True)
        
        # Progress every 10K
        if total % 10000 == 0 and args.debug:
            elapsed = time.perf_counter() - total_start
            print(f"[DEBUG] Progress: {total:,}/{matches:,} ({elapsed:.1f}s)",
                  file=sys.stderr, flush=True)
    
    total_elapsed = time.perf_counter() - total_start
    if args.debug:
        avg_us = (total_elapsed * 1_000_000) / max(total, 1)
        print(f"[DEBUG] Processed {total:,} addresses | {matches:,} matches",
              file=sys.stderr, flush=True)
        print(f"[DEBUG] Total: {total_elapsed:.1f}s ({total_elapsed/max(total,1)*1000:.2f}ms/addr avg)",
              file=sys.stderr, flush=True)
        print(f"[DEBUG] Throughput: {total/max(total_elapsed,1):,.0f} addr/sec",
              file=sys.stderr, flush=True)

if __name__ == '__main__':
    main()