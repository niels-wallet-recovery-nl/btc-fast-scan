#!/usr/bin/env python3
"""BBF Accumulator Verifier - works with unsorted input, multiprocess, MEMORY-EFFICIENT."""

from Crypto.Util.number import bytes_to_long, isPrime
import json, sys, argparse, hashlib, time, base64, os, multiprocessing, gc
from concurrent.futures import ProcessPoolExecutor, as_completed

try:
    sys.set_int_max_str_digits(0)
except AttributeError:
    pass

PRIME_BITS_DEFAULT = 112
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
DEFAULT_PREFIXES_BTC = ['bc1q', 'bc1p', '1', '3']
DEFAULT_PREFIXES_ETH = ['0x']

_CTX = None

def get_alphabet(encoding):
    if encoding.lower() == 'hex':
        return '0123456789abcdefABCDEF'
    return BASE58_ALPHABET

def addr_to_prime(addr: str, bits: int = PRIME_BITS_DEFAULT) -> int:
    h = hashlib.sha256(addr.encode()).digest()
    candidate = (1 << (bits - 1)) | (bytes_to_long(h) & ((1 << (bits - 1)) - 1))
    candidate |= 1
    while not isPrime(candidate):
        candidate += 2
    return candidate

def b64d(s: str) -> int:
    return int.from_bytes(base64.b64decode(s), 'big')

def get_chunk_pattern(addr, prefixes, depth, alphabet):
    matched_prefix = None
    for prefix in prefixes:
        if addr.startswith(prefix):
            matched_prefix = prefix
            break
    if not matched_prefix:
        return None, None, None

    start_idx = len(matched_prefix)
    if len(addr) < start_idx + depth:
        chars = addr[start_idx:].ljust(depth, alphabet[0])
    else:
        chars = addr[start_idx:start_idx + depth]

    for i, c in enumerate(chars):
        if c not in alphabet:
            chars = chars[:i] + alphabet[0] * (depth - i)
            break

    return matched_prefix, chars, f"{matched_prefix}:{chars}"


class AccumulatorContext:
    """Read-only after init. Safe to share across forked processes."""

    def __init__(self, path: str):
        with open(path) as f:
            self.data = json.load(f)

        chunk_path = path.replace('.json', '_chunks.json')
        if not os.path.exists(chunk_path):
            raise FileNotFoundError(f"Chunk file not found: {chunk_path}")
        with open(chunk_path) as f:
            self.chunks = json.load(f)

        self.n = int(self.data['rsa_params']['modulus_n'], 16)
        self.g = int(self.data['rsa_params']['generator_g'])
        self.s = int(self.data['trapdoor_s'], 16)
        self.encoding = self.data.get('encoding', 'base58')
        self.depth = self.data.get('chunk_depth', 2)
        self.prefixes = self.data.get('prefixes', DEFAULT_PREFIXES_BTC)
        self.prime_bits = self.data.get('prime_bits', PRIME_BITS_DEFAULT)
        self.alphabet = get_alphabet(self.encoding)

        self.chunk_map = {c['pattern']: c for c in self.chunks}
        self.product_cache = {}

    def get_chunk_product(self, pattern: str):
        if pattern not in self.product_cache:
            chunk = self.chunk_map.get(pattern)
            if not chunk:
                return None
            self.product_cache[pattern] = b64d(chunk['chunk_product'])
        return self.product_cache[pattern]


def _init_worker(ctx):
    global _CTX
    _CTX = ctx


def verify_batch(addresses):
    """Verify a list of addresses. Returns ONLY the matches."""
    ctx = _CTX
    hits = []

    for addr in addresses:
        _, _, pattern = get_chunk_pattern(addr, ctx.prefixes, ctx.depth, ctx.alphabet)
        if not pattern:
            continue

        P = ctx.get_chunk_product(pattern)
        if P is None:
            continue

        x = addr_to_prime(addr, bits=ctx.prime_bits)
        if P % (ctx.s + x) == 0:
            hits.append(addr)

    return hits


def main():
    ap = argparse.ArgumentParser(description='BBF Accumulator Verifier (MEMORY-EFFICIENT)')
    ap.add_argument('-f', '--file', required=True, help='Accumulator JSON file')
    ap.add_argument('-w', '--workers', type=int, default=os.cpu_count(),
                    help='Worker processes (default: CPU count)')
    ap.add_argument('--batch-size', type=int, default=2000, help='Addresses per task')
    ap.add_argument('--max-inflight', type=int, default=None,
                    help='Max outstanding tasks before waiting (default: 2×workers)')
    ap.add_argument('--debug', action='store_true', help='Timing/progress to stderr')
    args = ap.parse_args()

    t_load = time.perf_counter()
    try:
        ctx = AccumulatorContext(args.file)
    except Exception as e:
        print(f"[ERROR] Failed to load accumulator: {e}", file=sys.stderr)
        sys.exit(1)

    if args.debug:
        print(f"[DEBUG] Loaded {len(ctx.chunks):,} chunks "
              f"({ctx.data.get('address_count', '?')} addresses) in "
              f"{time.perf_counter() - t_load:.1f}s", file=sys.stderr, flush=True)

    mp_ctx = multiprocessing.get_context('fork') if hasattr(os, 'fork') \
        else multiprocessing.get_context()

    total_start = time.perf_counter()
    total = matches = 0
    batch = []
    
    # Bounded inflight to prevent memory explosion
    max_inflight = args.max_inflight or (args.workers * 2)

    with ProcessPoolExecutor(max_workers=args.workers, mp_context=mp_ctx,
                             initializer=_init_worker, initargs=(ctx,)) as ex:

        active_futures = []

        for line in sys.stdin:
            addr = line.strip().split()[0] if line.strip() else None
            if not addr or len(addr) < 20:
                continue

            total += 1
            batch.append(addr)

            if len(batch) >= args.batch_size:
                # Submit batch
                fut = ex.submit(verify_batch, batch)
                active_futures.append(fut)
                
                # IMMEDIATELY discard batch - it's now owned by the future
                batch = []

                # BACKPRESSURE: Wait if too many inflight
                while len(active_futures) >= max_inflight:
                    # Wait for ONE to complete and consume it immediately
                    done = next(as_completed(active_futures))
                    active_futures.remove(done)
                    
                    for matched_addr in done.result():
                        print(matched_addr, flush=True)
                        matches += 1
                    
                    del done
                    gc.collect() if total % 100000 == 0 else None

                if args.debug and total % 100000 == 0:
                    el = time.perf_counter() - total_start
                    print(f"[DEBUG] read {total:,} | inflight {len(active_futures)} ({el:.1f}s)",
                          file=sys.stderr, flush=True)

        # Final batch
        if batch:
            fut = ex.submit(verify_batch, batch)
            active_futures.append(fut)
            batch = []

        # Drain remaining futures with immediate consumption
        for fut in as_completed(active_futures):
            for matched_addr in fut.result():
                print(matched_addr, flush=True)
                matches += 1
            del fut  # Release reference

        active_futures.clear()

    el = time.perf_counter() - total_start
    if args.debug:
        print(f"[DEBUG] {total:,} addresses | {matches:,} matches | {el:.1f}s "
              f"| {total/max(el,1):,.0f} addr/sec | {args.workers} workers",
              file=sys.stderr, flush=True)
        print(f"[DEBUG] Peak inflight: ~{max_inflight} tasks (~{max_inflight*args.batch_size} addresses)",
              file=sys.stderr, flush=True)

if __name__ == '__main__':
    main()
