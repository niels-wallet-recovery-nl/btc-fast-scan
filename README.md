

# btc-addr-accum-scan (BBF Edition)
A fast Bitcoin/Ethereum address scanner using **BBF Polynomial RSA Accumulators** with **58² positional routing**. Compresses millions of addresses into ~300 MB while enabling individual address lookups with constant-time proofs (~16 ms per check). No blockchain download, no API rate limits.

---

## Scripts

- **`0_sort_addresses.py`** — Sort and route addresses to chunks
- **`1_RSA_BBF_accumulator.py`** — Build BBF polynomial accumulator
- **`2_RSA_BBF_verify.py`** — Filter addresses, print those in accumulator to STDOUT
- **`3_get_balance.py`** — Optional check balance for address found in the RSA accumulator

---

## Quick Start

### Build accumulator

```bash
python3 0_sort_addresses.py -i addresses.txt > sorted_addresses.txt
python3 1_RSA_BBF_accumulator.py -i sorted_addresses.txt -o bitcoin_accumulator.json -w 16 --depth 2
```

Options: `--depth 2` = 58² = 3,364 routing chunks (default), `-w` sets worker threads. Use `--skip-proof-store` for smaller output. HIGHLY RECOMMENDED!

### Verify addresses

```bash
cat check_addresses.txt | python3 2_RSA_BBF_verify.py -f bitcoin_accumulator.json -w 16 > verified.txt
```

### Get balances (optional)

```bash
cat verified.txt | python3 3_get_balance.py > results.tsv
```

---

## Architecture

**Build Phase:**

- Load addresses → Route to 3,364 chunks (58²) by prefix + character
- Each chunk: P_chunk(s) = ∏(s + x_i) [~15 KB per chunk]
- Super accumulator: g^(∏P_chunk) mod N [384 bytes]
- Store: accumulator + trapdoor s + chunk products

**Verification Phase:**

- Address → chunk_id (deterministic)
- Load chunk product (~15 KB)
- Compute proof: P_chunk / (s + x)
- Verify: proof^(s+x) == accumulator

---

## Input Format

One address per line, optional tab-separated value:

```
bc1ql49ydapnjafl5t2cp9zqpjwe6pdgmxy98859v2	0.001
3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6
eth:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
```

**Supported prefixes**: Legacy `1`, P2SH `3`, Bech32 `bc1q`, Bech32m `bc1p`, Ethereum `0x` or `eth:`

---

## Chunk Routing (58² = 3,364 Chunks)

| Prefix | Routing Keys |
| --- | --- |
| Legacy `1...` | Char[0] + Char[1] (base58) |
| P2SH `3...` | Char[0] + Char[1] (base58) |
| Bech32 `bc1q...` | Char[0-3] + Char[5] (mixed) |
| Bech32m `bc1p...` | Char[0-3] + Char[5] (mixed) |
| Ethereum `0x...` | 0x + Char[4] (hex) |

**Result**: ~15K addresses per chunk for 50M total addresses.

---

## Performance (50M Addresses, 16 cores)

| Metric | Build | Verify |
| --- | --- | --- |
| **Time** | 30-60 min | 16 ms/address |
| **Throughput** | 15K-25K/sec | 1K/sec (1 core) |
| **Parallel** | 16 workers | 16 workers |
| **Memory per check** | 8-12 GB | 15 KB |

---

## Storage Requirements

| Component | Size |
| --- | --- |
| **Accumulator (root)** | 384 bytes |
| **Trapdoor s** | 32 bytes |
| **Chunk products (3,364)** | ~100 MB |
| **Total** | **~100 MB** |

### Compression Ratios

| Scenario | Original | With BBF | Ratio |
| --- | --- | --- | --- |
| Address strings (50M) | 1.75 GB | ~100 MB | 18:1 |
| Full proof list | 19 GB | ~100 MB | 190:1 |

---

## Security Considerations

**WARNING**: The accumulator JSON includes the RSA trapdoor `s`. Anyone with it can forge proofs. This tool assumes **trust in the generator**.

| Aspect | Status |
| --- | --- |
| **Trapdoor exposure** | Keep `s` confidential (encrypted at rest) |
| **RSA key strength** | 256-512 bits (testing), 2048+ bits (production) |
| **Soundness** | Based on Strong RSA assumption |

For production use: consider Rust crates (mikelodder7/accumulator-rs, cambrian/accumulator).

---

## Troubleshooting

### Chunk backup not found

```bash
ls -la bitcoin_accumulator.json* # Should show both files
```

### Out of memory during build

```bash
python3 1_RSA_BBF_accumulator.py -i addresses.txt -o prod.json --max-ram-gb 12 -w 16
```

### Verification too slow

```bash
cat addresses.txt | python3 2_RSA_BBF_verify.py -f prod.json -w 32
```

---

## References

1. Boneh et al. (BBF 2018): [Batching Techniques for Accumulators](https://eprint.iacr.org/2018/1188)
2. EPrint 2024/505: [RSA-Based Dynamic Accumulator without Hashing into Primes](https://eprint.iacr.org/2024/505)
3. mikelodder7/accumulator-rs: https://github.com/mikelodder7/accumulator-rs
4. ParityTech stateless-blockchain: https://github.com/paritytech/stateless-blockchain

---

## License & Disclaimer

Apache 2.0. Provided as-is, use at your own risk. No responsibility for financial losses or misuse. Independent security review recommended before production use.
```
