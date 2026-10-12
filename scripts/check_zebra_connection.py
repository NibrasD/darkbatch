#!/usr/bin/env python3
"""
DarkBatch — Zebra Testnet Connection Checker
============================================
Checks connectivity to a local or remote zebrad instance on Zcash Testnet.

Usage:
  python scripts/check_zebra_connection.py [rpc_url]
"""

import json
import os
import sys
import urllib.request

DEFAULT_URL = os.environ.get("ZCASH_TESTNET_RPC_URL", "http://127.0.0.1:18232")


def rpc_call(url: str, method: str, params: list) -> dict:
    payload = json.dumps({"jsonrpc": "1.0", "id": "darkbatch-check", "method": method, "params": params})
    req = urllib.request.Request(
        url,
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    print(f"\n[*] Probing Zebra RPC endpoint: {url}")

    try:
        # 1. getblockcount
        count_res = rpc_call(url, "getblockcount", [])
        height = count_res.get("result", 0)
        print(f"[+] Connected to Zebra node!")
        print(f"[+] Current Block Height: {height:,}")

        # 2. getblockchaininfo
        info_res = rpc_call(url, "getblockchaininfo", [])
        res = info_res.get("result", {})
        chain = res.get("chain", "unknown")
        print(f"[+] Network Chain: {chain}")

        nu6_active = height >= 4_134_000
        nu7_active = height >= 4_465_026
        print(f"[+] NU6.3 Activated (Height >= 4,134,000): {'YES (Ironwood active)' if nu6_active else 'NO'}")
        print(f"[+] NU7 Activated (Height >= 4,465,026): {'YES' if nu7_active else 'NO'}")

        print("\n[SUCCESS] Zebra node is reachable and ready for DarkBatch Testnet transactions.\n")
    except Exception as exc:
        print(f"[-] Could not connect to Zebra at {url}: {exc}")
        print("\nEnsure zebrad is running on Testnet, for example:")
        print("  docker run -d --name zebrad -p 18232:18232 -v ${PWD}/zebrad.toml:/etc/zebrad.toml zfnd/zebra:latest start -c /etc/zebrad.toml")
        print("or start zebrad locally with: zebrad start -c zebrad.toml\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
