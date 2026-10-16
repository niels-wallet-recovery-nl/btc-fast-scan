#!/usr/bin/env python3
"""
Get BTC/ETH balance and tx_count for verified addresses via public APIs.

Reads addresses from STDIN (one per line), outputs TSV to STDOUT:
    address<TAB>chain<TAB>tx_count<TAB>balance

USAGE:
    python verify.py accumulator.json < verified.txt | python 3_get_balance.py > results.tsv

Providers (fallback chain):
    Bitcoin: Blockstream → Mempool → Blockchair → Blockcypher
    Ethereum: Blockchair → Blockcypher
"""

import time
import requests
import sys
from typing import Tuple

def _get(url: str, timeout: int = 12) -> dict:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()

# ---------- Bitcoin Providers ----------
def esplora_btc(url_tpl: str, addr: str) -> Tuple[int, int]:
    j = _get(url_tpl.format(addr))
    tx = j["chain_stats"]["tx_count"] + j["mempool_stats"]["tx_count"]
    bal = j["chain_stats"]["funded_txo_sum"] - j["chain_stats"]["spent_txo_sum"]
    return tx, bal

def blockchair_btc(url_tpl: str, addr: str) -> Tuple[int, int]:
    data = _get(url_tpl.format(addr))["data"][addr]
    return len(data.get("transactions", [])), int(data["address"]["balance"])

def blockcypher_btc(url_tpl: str, addr: str) -> Tuple[int, int]:
    j = _get(url_tpl.format(addr))
    return int(j.get("n_tx", 0)), int(j["final_balance"])

BTC_PROVIDERS = [
    ("blockstream", "https://blockstream.info/api/address/{}", esplora_btc, 0.1),
    ("mempool",     "https://mempool.space/api/address/{}",     esplora_btc, 0.15),
    ("blockchair",  "https://api.blockchair.com/bitcoin/dashboards/address/{}", blockchair_btc, 0.3),
    ("blockcypher", "https://api.blockcypher.com/v1/btc/main/addrs/{}/balance", blockcypher_btc, 0.6),
]

# ---------- Ethereum Providers ----------
def blockchair_eth(url_tpl: str, addr: str) -> Tuple[int, int]:
    j = _get(url_tpl.format(addr))
    d = j["data"][addr]["address"]
    return int(d["transaction_count"]), int(d["balance"])  # balance in wei

def blockcypher_eth(url_tpl: str, addr: str) -> Tuple[int, int]:
    j = _get(url_tpl.format(addr))
    return int(j.get("n_tx", 0)), int(j["balance"])

ETH_PROVIDERS = [
    ("blockchair",   "https://api.blockchair.com/ethereum/dashboards/address/{}", blockchair_eth, 0.3),
    ("blockcypher",  "https://api.blockcypher.com/v1/eth/main/addrs/{}/balance", blockcypher_eth, 0.6),
]

def check_balance(address: str, providers: list) -> Tuple[str, int, int]:
    """Try all providers, return (chain, tx_count, balance) or ('err', -1, -1)."""
    for name, url_tpl, fn, delay in providers:
        try:
            tx, bal = fn(url_tpl, address)
            time.sleep(delay)
            return ('BTC', tx, bal) if 'btc' in url_tpl.lower() else ('ETH', tx, bal)
        except Exception:
            continue
    return ('err', -1, -1)

def main():
    for line in sys.stdin:
        addr = line.strip().split('\t')[0].strip()
        if not addr or addr.startswith('#'):
            continue
        
        if addr.startswith('0x'):
            chain, tx, bal = check_balance(addr, ETH_PROVIDERS)
            divisor = 1e18  # wei to ETH
        else:
            chain, tx, bal = check_balance(addr, BTC_PROVIDERS)
            divisor = 1e8   # satoshi to BTC
        
        if chain == 'err':
            print(f"{addr}\t{chain}\t{tx}\t{bal}", file=sys.stderr)
        else:
            # Output: address, chain, tx_count, balance (human-readable)
            print(f"{addr}\t{chain}\t{tx}\t{bal/divisor:.8f}")
        
        time.sleep(0.1)  # Rate limit protection

if __name__ == '__main__':
    main()