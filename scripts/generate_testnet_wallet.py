#!/usr/bin/env python3
"""
DarkBatch — Authentic Zcash Testnet Wallet Generator
====================================================
Generates a real Zcash Testnet Unified Address (UA) and Orchard/Ironwood keys
using the official darkbatch_crypto Rust engine (librustzcash / orchard crate).

Output files (saved to ./wallets/):
  - participant_testnet_key.json  (PRIVATE: contains sk_hex for signing settlement)
  - wallet_public_info.json       (PUBLIC: contains Unified Address and FVK)

Usage:
  python scripts/generate_testnet_wallet.py [--name participant_1]
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
CRYPTO_BIN = ROOT_DIR / "darkbatch_crypto" / "target" / "release" / "darkbatch_crypto"
if sys.platform == "win32":
    CRYPTO_BIN = CRYPTO_BIN.with_suffix(".exe")


def run_crypto_cmd(cmd: str, payload_dict: dict) -> dict:
    if not CRYPTO_BIN.exists():
        raise RuntimeError(
            f"Binary not found at {CRYPTO_BIN}. Build it using:\n"
            "cargo build --release --manifest-path darkbatch_crypto/Cargo.toml"
        )
    payload_json = json.dumps(payload_dict)
    res = subprocess.run(
        [str(CRYPTO_BIN), cmd],
        input=payload_json.encode("utf-8"),
        capture_output=True,
    )
    if res.returncode != 0:
        err = res.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"darkbatch_crypto {cmd} failed (code {res.returncode}): {err}")
    stdout_str = res.stdout.decode("utf-8", errors="replace").strip()
    return json.loads(stdout_str)


def generate_wallet(wallet_name: str = "participant_1") -> dict:
    # 1. Generate 32 bytes cryptographically secure random spending key
    sk_bytes = secrets.token_bytes(32)
    sk_hex = sk_bytes.hex()

    # 2. Derive Testnet Unified Address and raw Ironwood receiver via official Rust library
    addr_res = run_crypto_cmd("derive-ironwood-address-stdin", {
        "network": "testnet",
        "spending_key_hex": sk_hex,
        "address_index": 0,
        "scope": "external",
    })

    # 3. Export Full Viewing Key (FVK) and Incoming Viewing Key (IVK)
    fvk_res = run_crypto_cmd("export-ironwood-fvk-stdin", {
        "network": "testnet",
        "spending_key_hex": sk_hex,
    })

    wallet_data = {
        "wallet_name": wallet_name,
        "network": "testnet",
        "unified_address": addr_res["unified_address"],
        "raw_ironwood_receiver_hex": addr_res["raw_ironwood_receiver_hex"],
        "full_viewing_key_hex": fvk_res["full_viewing_key_hex"],
        "incoming_viewing_key_hex": fvk_res["incoming_viewing_key_hex"],
        "sk_hex": sk_hex,
    }

    # 4. Save to files
    wallets_dir = ROOT_DIR / "wallets"
    wallets_dir.mkdir(parents=True, exist_ok=True)

    priv_file = wallets_dir / f"{wallet_name}_key.json"
    pub_file = wallets_dir / f"{wallet_name}_public.json"

    with open(priv_file, "w", encoding="utf-8") as f:
        json.dump(wallet_data, f, indent=2)

    public_data = {k: v for k, v in wallet_data.items() if k != "sk_hex"}
    with open(pub_file, "w", encoding="utf-8") as f:
        json.dump(public_data, f, indent=2)

    # Restrict permissions on private key file
    try:
        os.chmod(priv_file, 0o600)
    except Exception:
        pass

    return wallet_data


def main():
    parser = argparse.ArgumentParser(description="Generate real Zcash Testnet Unified Address and keys")
    parser.add_argument("--name", default="participant_1", help="Wallet name / identifier")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("      DarkBatch — Real Zcash Testnet Wallet Generation")
    print("=" * 70)

    wallet = generate_wallet(args.name)

    print(f"\n[+] Wallet successfully generated for: {args.name}")
    print(f"[+] Network: Zcash Testnet (NU6.3 / NU7 / Ironwood compatible)")
    print(f"\n[!] OFFICIAL TESTNET UNIFIED ADDRESS (UA):")
    print(f"    {wallet['unified_address']}")
    print(f"\n[+] Raw Ironwood Receiver (43 bytes hex):")
    print(f"    {wallet['raw_ironwood_receiver_hex']}")
    print(f"[+] Full Viewing Key (96 bytes hex):")
    print(f"    {wallet['full_viewing_key_hex']}")
    print(f"\n[+] Private Key File (DO NOT SHARE):")
    print(f"    wallets/{args.name}_key.json")
    print(f"[+] Public Info File:")
    print(f"    wallets/{args.name}_public.json")

    print("\n" + "=" * 70)
    print("   NEXT STEPS TO GET REAL TESTNET ZEC (TAZ):")
    print("=" * 70)
    print("1. Copy your Unified Address above:")
    print(f"   {wallet['unified_address']}")
    print("\n2. Request test funds (TAZ) from an official faucet:")
    print("   - https://fauzec.com/")
    print("   - https://zcashfaucet.jinolabs.xyz/")
    print("\n3. Once funded, use this key file with DarkBatch settlement:")
    print(f"   python scripts/run_real_settlement.py <epoch_id> wallets/{args.name}_key.json")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
