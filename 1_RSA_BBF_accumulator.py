#!/usr/bin/env python3
"""
BBF RSA Accumulator — streaming, sorted-input, bounded-memory.

Design contract
---------------
  term_i  = s + x_i                 (x_i = prime derived from address i)
  P       = prod(term_i)            per chunk  -> stored base64
  A       = g^P mod N               per chunk  -> stored base64
  member  <=>  P % (s + x) == 0
  witness w = g^(P/(s+x)) mod N ;  w^(s+x) == A

Input MUST be sorted. Consecutive identical patterns form one chunk, which is
processed and released immediately. Nothing is buffered beyond the current run
plus a bounded number of in-flight tasks.

Outputs
-------
  <stem>.json          metadata (rsa_params, trapdoor_s, schema info)
  <stem>_chunks.json   list of chunk records

Usage
-----
  # build (default action, stdin)
  cat addresses_sorted.tsv | ./acc.py -o utxo_rsa.json -w 16 \
        --trapdoor-bits 96 --prime-bits 112

  # build from file
  ./acc.py build -i addresses_sorted.tsv -o utxo_rsa.json -w 16

  # incremental update (non-destructive; writes a new stem)
  ./acc.py update -f utxo_rsa.json -i new_sorted.tsv -o utxo_rsa_v2.json

  # single address
  ./acc.py verify -f utxo_rsa.json -a bc1q...

  # batch filter: stdin -> stdout, matches only
  cat candidates.tsv | ./acc.py verify-batch -f utxo_rsa.json --debug
"""

import argparse
import base64
import gc
import hashlib
import json
import math
import os
import secrets
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from datetime import datetime, timezone

from Crypto.Util.number import bytes_to_long, getPrime, isPrime

try:
    sys.set_int_max_str_digits(0)
except AttributeError:
    pass

# ==============================================================================
# CONSTANTS
# ==============================================================================

FORMAT_VERSION     = "1.0-stream"
PRIME_BITS_DEFAULT = 112
TRAPDOOR_BITS_DEFAULT = 128
RSA_BITS_DEFAULT   = 2048
DEPTH_DEFAULT      = 2
MIN_ADDR_LEN       = 20

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
HEX_ALPHABET    = '0123456789abcdefABCDEF'

DEFAULT_PREFIXES_BTC = ['bc1q', 'bc1p', '1', '3']
DEFAULT_PREFIXES_ETH = ['0x']

TABLE_RULE = "|----:|:-------------|------:|---------:|-------:|-----------:|-----------:|-------:|"


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
def _check_eth_encoding(prefixes, alphabet):
    """If first address starts with 0x, warn and offer to quit."""
    def notify():
        print("\n⚠️  WARNING: '0x' (Ethereum-style) prefix detected!", flush=True)
        print("   Recommended: restart with --encoding hex", flush=True)
        print("   Press Enter to continue with base58, or q to exit:", end='', flush=True)
        try:
            resp = input()
            if resp.lower() == 'q':
                print("\nAborted by user.", flush=True)
                sys.exit(1)
        except (EOFError, KeyboardInterrupt):
            print("\nContinuing (interrupted input treated as 'continue').", flush=True)
    return notify


# ==============================================================================
# PRIMITIVES
# ==============================================================================

def get_alphabet(encoding):
    return HEX_ALPHABET if encoding.lower() == 'hex' else BASE58_ALPHABET


def addr_to_prime(addr, bits=PRIME_BITS_DEFAULT):
    """Address -> odd prime of exactly `bits` bits (top bit forced)."""
    h = hashlib.sha256(addr.encode()).digest()
    candidate = (1 << (bits - 1)) | (bytes_to_long(h) & ((1 << (bits - 1)) - 1))
    candidate |= 1
    while not isPrime(candidate):
        candidate += 2
    return candidate


def b64e(value):
    if value == 0:
        return ""
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return base64.b64encode(raw).decode()


def b64d(text):
    if not text:
        return 0
    return int.from_bytes(base64.b64decode(text), 'big')


def prod_tree(values):
    """Balanced product — avoids the O(n^2) blow-up of left-fold multiplication."""
    vals = list(values)
    if not vals:
        return 1
    while len(vals) > 1:
        nxt = [vals[i] * vals[i + 1] for i in range(0, len(vals) - 1, 2)]
        if len(vals) & 1:
            nxt.append(vals[-1])
        vals = nxt
    return vals[0]


def get_chunk_pattern(addr, prefixes, depth, alphabet):
    """Return (prefix, chars, pattern) or (None, None, None)."""
    matched = None
    for prefix in prefixes:
        if addr.startswith(prefix):
            matched = prefix
            break
    if not matched:
        return None, None, None

    start = len(matched)
    if len(addr) < start + depth:
        chars = addr[start:].ljust(depth, alphabet[0])
    else:
        chars = addr[start:start + depth]

    for i, ch in enumerate(chars):
        if ch not in alphabet:
            chars = chars[:i] + alphabet[0] * (depth - i)
            break

    return matched, chars, f"{matched}:{chars}"


def gen_rsa_params(trapdoor_bits, rsa_bits):
    """Fresh RSA modulus, generator, and secret trapdoor offset."""
    p = getPrime(rsa_bits // 2)
    q = getPrime(rsa_bits - rsa_bits // 2)
    n = p * q
    while True:
        g = secrets.randbelow(n - 3) + 2
        if math.gcd(g, n) == 1:
            break
    s = secrets.randbits(trapdoor_bits) | 1 | (1 << (trapdoor_bits - 1))
    return s, g, n


# ==============================================================================
# WORKER (timing measured around the computation only)
# ==============================================================================

def process_chunk(task):
    pattern, addresses, s, g, n, prime_bits = task
    t0 = time.perf_counter()

    terms = [s + addr_to_prime(a, prime_bits) for a in addresses]
    product = prod_tree(terms)
    acc = pow(g, product, n)

    return {
        'pattern': pattern,
        'address_count': len(addresses),
        'chunk_product': b64e(product),
        'chunk_accumulator': b64e(acc),
        'proc_seconds': time.perf_counter() - t0,
    }


# ==============================================================================
# STREAMING RUN READER
# ==============================================================================

def iter_pattern_runs(handle, prefixes, depth, alphabet, notify=None):
    current = None
    buf = []
    announced = False

    for line in handle:
        line = line.strip()
        if not line:
            continue
        addr = line.split()[0]
        if len(addr) < MIN_ADDR_LEN:
            continue

        # One-shot 0x detection + user prompt
        if not announced and addr.startswith('0x'):
            announced = True
            if notify:
                notify()

        _, _, pattern = get_chunk_pattern(addr, prefixes, depth, alphabet)
        if pattern is None:
            continue

        if pattern != current:
            if current is not None:
                yield current, buf
            current = pattern
            buf = []
        buf.append(addr)

    if current is not None:
        yield current, buf


def dedup_run(buf):
    seen = set()
    out = []
    for a in buf:
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out


# ==============================================================================
# PROGRESS TABLE
# ==============================================================================

class ProgressTable:
    HEADER = ("| Chk | Pattern      |  Addr |  Proc(s) | Addr/s |    Cumul   |  Elapsed | Avg/s |")
    RULE   = "|----:|:-------------|------:|---------:|-------:|-----------:|---------:|------:|"

    def __init__(self, enabled=True, total_addresses=None):
        self.enabled = enabled
        self.total = total_addresses
        self.printed_header = False
        self.cumulative = 0
        self.chunks = 0
        self.t_start = time.perf_counter()

    def _header(self):
        if not self.printed_header and self.enabled:
            print(self.HEADER, flush=True)
            print(self.RULE, flush=True)
            self.printed_header = True

    def row(self, pattern, count, proc_seconds):
        self.chunks += 1
        self.cumulative += count
        if not self.enabled:
            return

        self._header()
        elapsed = time.perf_counter() - self.t_start
        rate = count / proc_seconds if proc_seconds > 0 else 0.0
        avg = self.cumulative / elapsed if elapsed > 0 else 0.0

        print(
            f"| {self.chunks:4d} | {pattern:<12s} | {count:5d} | {proc_seconds:8.2f} | "
            f"{rate:6.1f} | {self.cumulative:10,d} | {elapsed:7.1f}s | {avg:5.0f} |",
            flush=True,
        )

    def footer(self):
        if not self.enabled:
            return
        elapsed = time.perf_counter() - self.t_start
        avg = self.cumulative / elapsed if elapsed > 0 else 0.0
        print("", flush=True)
        print(f"Chunks: {self.chunks:,} | Addresses: {self.cumulative:,} | "
              f"Elapsed: {elapsed/3600:.2f}h | Average: {avg:,.0f} addr/s", flush=True)


# ==============================================================================
# SERIALISATION
# ==============================================================================

def split_stem(path):
    return path[:-5] if path.endswith('.json') else path


def write_outputs(out_path, records, s, g, n, opts, total_addresses):
    stem = split_stem(out_path)
    meta_path = stem + '.json'
    chunk_path = stem + '_chunks.json'

    meta = {
        'format_version': FORMAT_VERSION,
        'created': datetime.now(timezone.utc).isoformat(),
        'encoding': opts.encoding,
        'chunk_depth': opts.depth,
        'prefixes': opts.prefixes,
        'prime_bits': opts.prime_bits,
        'trapdoor_bits': opts.trapdoor_bits,
        'rsa_bits': opts.rsa_bits,
        'address_count': total_addresses,
        'chunk_count': len(records),
        'rsa_params': {
            'modulus_n': format(n, 'x'),
            'generator_g': str(g),
        },
        'trapdoor_s': format(s, 'x'),
    }

    tmp_meta = meta_path + '.tmp'
    tmp_chunks = chunk_path + '.tmp'

    with open(tmp_meta, 'w') as f:
        json.dump(meta, f, indent=2)
    with open(tmp_chunks, 'w') as f:
        json.dump(records, f, separators=(',', ':'))

    os.replace(tmp_meta, meta_path)
    os.replace(tmp_chunks, chunk_path)

    return meta_path, chunk_path


def load_context(path):
    stem = split_stem(path)
    with open(stem + '.json') as f:
        meta = json.load(f)
    with open(stem + '_chunks.json') as f:
        chunks = json.load(f)

    ctx = {
        'meta': meta,
        'chunks': chunks,
        'by_pattern': {c['pattern']: c for c in chunks},
        'n': int(meta['rsa_params']['modulus_n'], 16),
        'g': int(meta['rsa_params']['generator_g']),
        's': int(meta['trapdoor_s'], 16),
        'prime_bits': meta.get('prime_bits', PRIME_BITS_DEFAULT),
        'depth': meta.get('chunk_depth', DEPTH_DEFAULT),
        'prefixes': meta.get('prefixes', DEFAULT_PREFIXES_BTC),
        'encoding': meta.get('encoding', 'base58'),
    }
    ctx['alphabet'] = get_alphabet(ctx['encoding'])
    return ctx


# ==============================================================================
# BUILD
# ==============================================================================
def cmd_build(opts):
    s, g, n = gen_rsa_params(opts.trapdoor_bits, opts.rsa_bits)

    if not opts.quiet:
        print("=" * 92)
        print("BBF RSA Accumulator — streaming build")
        print("=" * 92)
        print(f"Encoding:     {opts.encoding}")
        print(f"Depth:        {opts.depth}")
        print(f"Primes:       {opts.prime_bits} bits")
        print(f"Trapdoor:     {opts.trapdoor_bits} bits")
        print(f"RSA modulus:  {opts.rsa_bits} bits")
        print(f"Workers:      {opts.workers}")
        print(f"Input:        {opts.input or '<stdin>'} (must be sorted)")
        print("=" * 92)
        print("")

    alphabet = get_alphabet(opts.encoding)

    def _notify():
        if not opts.quiet:
            print("\n⚠️  WARNING: '0x' (Ethereum-style) prefix detected!", flush=True)
            print("   Recommended: restart with --encoding hex", flush=True)
            print("   Press Enter to continue with base58, or q to exit:", end='', flush=True)
            try:
                resp = input()
                if resp.lower() == 'q':
                    print("\nAborted by user.", flush=True)
                    sys.exit(1)
            except (EOFError, KeyboardInterrupt):
                print("\nContinuing (interrupted input treated as 'continue').", flush=True)

    table = ProgressTable(enabled=not opts.quiet, total_addresses=opts.total_addresses)
    handle = open(opts.input) if opts.input else sys.stdin
    records = {}
    total_addresses = 0
    interrupted = False

    try:
        if opts.workers <= 1:
            for pattern, buf in iter_pattern_runs(handle, opts.prefixes, opts.depth,
                                                  alphabet, _notify):
                addrs = dedup_run(buf)
                if not addrs:
                    continue
                rec = process_chunk((pattern, addrs, s, g, n, opts.prime_bits))
                records[pattern] = rec
                total_addresses += rec['address_count']
                table.row(pattern, rec['address_count'], rec['proc_seconds'])
                del addrs, buf
                gc.collect()
        else:
            inflight_limit = max(opts.workers * 2, opts.workers + 1)
            inflight = {}

            with ProcessPoolExecutor(max_workers=opts.workers) as pool:
                runs = iter_pattern_runs(handle, opts.prefixes, opts.depth, alphabet, _notify)
                exhausted = False

                while not exhausted or inflight:
                    while not exhausted and len(inflight) < inflight_limit:
                        try:
                            pattern, buf = next(runs)
                        except StopIteration:
                            exhausted = True
                            break
                        addrs = dedup_run(buf)
                        if not addrs:
                            continue
                        fut = pool.submit(
                            process_chunk, (pattern, addrs, s, g, n, opts.prime_bits)
                        )
                        inflight[fut] = pattern
                        del addrs, buf

                    if not inflight:
                        continue

                    done, _ = wait(set(inflight), return_when=FIRST_COMPLETED)
                    for fut in done:
                        pat = inflight.pop(fut)
                        try:
                            rec = fut.result()
                        except Exception as exc:
                            print(f"[ERROR] chunk {pat}: {exc}", file=sys.stderr, flush=True)
                            continue
                        records[rec['pattern']] = rec
                        total_addresses += rec['address_count']
                        table.row(rec['pattern'], rec['address_count'], rec['proc_seconds'])

                    if len(records) % 64 == 0:
                        gc.collect()

    except KeyboardInterrupt:
        interrupted = True
        print("\n[INTERRUPTED] Flushing completed chunks...", file=sys.stderr, flush=True)
    finally:
        if opts.input:
            handle.close()

    ordered = [records[p] for p in sorted(records)]
    meta_path, chunk_path = write_outputs(opts.output, ordered, s, g, n, opts, total_addresses)

    table.footer()
    if not opts.quiet:
        print(f"Metadata:  {meta_path}")
        print(f"Chunks:    {chunk_path}")
        if interrupted:
            print("[NOTE] Partial build — rerun `update` to extend.", file=sys.stderr)

    return 0 if not interrupted else 130


# ==============================================================================
# UPDATE (delta extension, non-destructive)
# ==============================================================================

def cmd_update(opts):
    ctx = load_context(opts.file)
    s, g, n = ctx['s'], ctx['g'], ctx['n']
    alphabet = ctx['alphabet']

    if not opts.quiet:
        print("=" * 92)
        print("BBF RSA Accumulator — incremental update")
        print("=" * 92)
        print(f"Source:       {opts.file}")
        print(f"Existing:     {ctx['meta'].get('address_count', '?'):,} addresses, "
              f"{len(ctx['chunks']):,} chunks")
        print(f"New input:    {opts.input or '<stdin>'} (must be sorted)")
        print(f"Output:       {opts.output}")
        print("=" * 92)
        print("")

    table = ProgressTable(enabled=not opts.quiet)
    handle = open(opts.input) if opts.input else sys.stdin

    added = 0
    dupes = 0
    new_chunks = 0
    touched = set()

    try:
        for pattern, buf in iter_pattern_runs(handle, ctx['prefixes'], ctx['depth'], alphabet):
            addrs = dedup_run(buf)
            if not addrs:
                continue

            rec = ctx['by_pattern'].get(pattern)
            if rec is None:
                fresh = process_chunk((pattern, addrs, s, g, n, ctx['prime_bits']))
                ctx['by_pattern'][pattern] = fresh
                ctx['chunks'].append(fresh)
                new_chunks += 1
                added += fresh['address_count']
                table.row(pattern, fresh['address_count'], fresh['proc_seconds'])
                continue

            P_old = b64d(rec['chunk_product'])
            A_old = b64d(rec['chunk_accumulator'])

            delta_terms = []
            for addr in addrs:
                x = addr_to_prime(addr, ctx['prime_bits'])
                term = s + x
                if P_old % term == 0:
                    dupes += 1
                    continue
                delta_terms.append(term)

            if not delta_terms:
                continue

            t0 = time.perf_counter()
            delta = prod_tree(delta_terms)
            P_new = P_old * delta
            A_new = pow(A_old, delta, n)
            proc = time.perf_counter() - t0

            rec['chunk_product'] = b64e(P_new)
            rec['chunk_accumulator'] = b64e(A_new)
            rec['address_count'] += len(delta_terms)
            added += len(delta_terms)
            touched.add(pattern)
            table.row(pattern, len(delta_terms), proc)

    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Writing partial update...", file=sys.stderr, flush=True)
    finally:
        if opts.input:
            handle.close()

    total = sum(c['address_count'] for c in ctx['chunks'])
    ordered = sorted(ctx['chunks'], key=lambda c: c['pattern'])

    class _Opts:
        pass

    o = _Opts()
    o.encoding = ctx['encoding']
    o.depth = ctx['depth']
    o.prefixes = ctx['prefixes']
    o.prime_bits = ctx['prime_bits']
    o.trapdoor_bits = ctx['meta'].get('trapdoor_bits', TRAPDOOR_BITS_DEFAULT)
    o.rsa_bits = ctx['meta'].get('rsa_bits', RSA_BITS_DEFAULT)

    meta_path, chunk_path = write_outputs(opts.output, ordered, s, g, n, o, total)

    table.footer()
    if not opts.quiet:
        print(f"Added:      {added:,} addresses")
        print(f"Duplicates: {dupes:,} skipped")
        print(f"New chunks: {new_chunks:,}")
        print(f"Extended:   {len(touched):,}")
        print(f"Total:      {total:,} addresses across {len(ordered):,} chunks")
        print(f"Metadata:   {meta_path}")
        print(f"Chunks:     {chunk_path}")

    return 0


# ==============================================================================
# VERIFY
# ==============================================================================

def verify_one(ctx, address, prove=False):
    t0 = time.perf_counter()

    def done(found, reason):
        return found, (time.perf_counter() - t0) * 1_000_000, reason

    _, _, pattern = get_chunk_pattern(
        address, ctx['prefixes'], ctx['depth'], ctx['alphabet'])
    if pattern is None:
        return done(False, "no prefix match")

    rec = ctx['by_pattern'].get(pattern)
    if rec is None:
        return done(False, "no chunk")

    x = addr_to_prime(address, ctx['prime_bits'])
    term = ctx['s'] + x

    P = b64d(rec['chunk_product'])
    if P % term != 0:
        return done(False, "not divisible")

    if prove:
        A = b64d(rec['chunk_accumulator'])
        witness = pow(ctx['g'], P // term, ctx['n'])
        if pow(witness, term, ctx['n']) != A:
            return done(False, "witness mismatch")

    return done(True, "member")


def cmd_verify(opts):
    ctx = load_context(opts.file)
    found, us, reason = verify_one(ctx, opts.address, prove=opts.prove)
    verdict = "MEMBER" if found else "NOT MEMBER"
    print(f"{verdict}\t{opts.address}\t({reason}, {us:.1f}us)")
    return 0 if found else 1


def cmd_verify_batch(opts):
    ctx = load_context(opts.file)

    if opts.debug:
        print(f"[DEBUG] {len(ctx['chunks']):,} chunks, "
              f"{ctx['meta'].get('address_count', '?'):,} addresses, "
              f"prime_bits={ctx['prime_bits']}", file=sys.stderr, flush=True)

    seen = set()
    total = matches = 0
    t_start = time.perf_counter()

    for lineno, line in enumerate(sys.stdin, 1):
        line = line.strip()
        if not line:
            continue
        addr = line.split()[0]
        if len(addr) < MIN_ADDR_LEN or addr in seen:
            continue
        seen.add(addr)
        total += 1

        found, us, reason = verify_one(ctx, addr, prove=opts.prove)

        if found:
            matches += 1
            print(addr, flush=True)
            if opts.debug:
                print(f"[DEBUG] line {lineno}: {addr[:24]}… FOUND ({us:.1f}us)",
                      file=sys.stderr, flush=True)
        else:
            if opts.show_nonmembers:
                print(f"# NONMEMBER {addr} ({reason})", file=sys.stderr, flush=True)
            if opts.debug:
                print(f"[DEBUG] line {lineno}: {addr[:24]}… miss ({reason}, {us:.1f}us)",
                      file=sys.stderr, flush=True)

        if opts.debug and total % 10000 == 0:
            el = time.perf_counter() - t_start
            print(f"[DEBUG] {total:,} checked, {matches:,} matched, {el:.1f}s "
                  f"({total/max(el,1e-9):,.0f}/s)", file=sys.stderr, flush=True)

    if opts.debug:
        el = time.perf_counter() - t_start
        print(f"[DEBUG] done: {total:,} checked, {matches:,} matched, {el:.1f}s "
              f"({total/max(el,1e-9):,.0f}/s)", file=sys.stderr, flush=True)

    return 0


# ==============================================================================
# CLI
# ==============================================================================

def build_parser():
    p = argparse.ArgumentParser(
        prog='acc.py',
        description='BBF RSA accumulator — streaming build, update, verify.')
    sub = p.add_subparsers(dest='cmd')

    def common_out(sp):
        sp.add_argument('-o', '--output', required=True, help='Output stem (.json appended)')
        sp.add_argument('-q', '--quiet', action='store_true', help='Suppress progress table')

    b = sub.add_parser('build', help='Build a new accumulator (sorted input)')
    b.add_argument('-i', '--input', help='Sorted input file (default: stdin)')
    common_out(b)
    b.add_argument('-w', '--workers', type=int, default=1, help='Worker processes')
    b.add_argument('--prime-bits', type=int, default=PRIME_BITS_DEFAULT)
    b.add_argument('--trapdoor-bits', type=int, default=TRAPDOOR_BITS_DEFAULT)
    b.add_argument('--rsa-bits', type=int, default=RSA_BITS_DEFAULT)
    b.add_argument('--depth', type=int, default=DEPTH_DEFAULT)
    b.add_argument('--encoding', default='base58', choices=['base58', 'hex'])
    b.add_argument('--prefixes', nargs='+', default=DEFAULT_PREFIXES_BTC)
    b.add_argument('--total-addresses', type=int, default=None,
                   help='Known total, for informational purposes only')

    u = sub.add_parser('update', help='Extend an existing accumulator (sorted input)')
    u.add_argument('-f', '--file', required=True, help='Existing accumulator .json')
    u.add_argument('-i', '--input', help='Sorted new-address file (default: stdin)')
    common_out(u)

    v = sub.add_parser('verify', help='Verify a single address')
    v.add_argument('-f', '--file', required=True)
    v.add_argument('-a', '--address', required=True)
    v.add_argument('--prove', action='store_true', help='Full witness verification (slow)')

    vb = sub.add_parser('verify-batch', help='Filter addresses from stdin to stdout')
    vb.add_argument('-f', '--file', required=True)
    vb.add_argument('--prove', action='store_true', help='Full witness verification (slow)')
    vb.add_argument('--debug', action='store_true', help='Timing and counters to stderr')
    vb.add_argument('--show-nonmembers', action='store_true',
                    help='Emit misses to stderr as comments')

    return p


def main():
    known = {'build', 'update', 'verify', 'verify-batch'}
    argv = sys.argv[1:]

    # Backwards compatibility: bare invocation implies `build`
    if not argv or (argv[0] not in known and argv[0] not in ('-h', '--help')):
        argv = ['build'] + argv

    parser = build_parser()
    opts = parser.parse_args(argv)

    if not opts.cmd:
        parser.print_help()
        return 2

    handlers = {
        'build': cmd_build,
        'update': cmd_update,
        'verify': cmd_verify,
        'verify-batch': cmd_verify_batch,
    }
    return handlers[opts.cmd](opts)


if __name__ == '__main__':
    sys.exit(main())