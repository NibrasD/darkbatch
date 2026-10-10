"""Locally submit an official-PCZT-extracted V6 transaction to Zebra Testnet."""
import argparse
import json
import time
from pathlib import Path

from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transaction_hex_file", help="File containing raw Transaction V6 hex")
    parser.add_argument("--wait-for-confirmation", type=int, default=0,
                        help="Maximum seconds to poll for a mined block (0 means report broadcast only)")
    parser.add_argument("--poll-interval", type=float, default=3.0,
                        help="Seconds between status checks when waiting")
    args = parser.parse_args()
    if args.wait_for_confirmation < 0 or args.poll_interval <= 0:
        parser.error("wait timeout must be non-negative and poll interval must be positive")

    try:
        raw_hex = Path(args.transaction_hex_file).read_text(encoding="utf-8")
        adapter = TestnetSettlementAdapter(allow_simulation=False)
        record = adapter.broadcast_raw_transaction(raw_hex)
        print(json.dumps(record, indent=2))
        if args.wait_for_confirmation == 0:
            return 0

        deadline = time.monotonic() + args.wait_for_confirmation
        while time.monotonic() < deadline:
            latest = adapter.get_transaction(record["txid"]) or record
            print(json.dumps(latest, indent=2))
            if latest.get("status") == "CONFIRMED":
                return 0
            time.sleep(min(args.poll_interval, max(0.0, deadline - time.monotonic())))
        print(json.dumps({
            "status": "CONFIRMATION_TIMEOUT",
            "txid": record["txid"],
            "last_known_status": record.get("status"),
            "epoch_settled": False,
            "message": "No confirmed block was observed before timeout; this tool does not mark the FBA epoch settled."
        }, indent=2))
        return 2
    except Exception as exc:
        print(json.dumps({"status": "BROADCAST_FAILED", "error": str(exc), "simulation_used": False}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
