"""
Local CLI for collaborative Ironwood PCZT construction.

This module is for trusted local wallet machines, not the public coordinator.
It never accepts spending keys on the command line, writes sensitive artifacts with
owner-only permissions, and never broadcasts until the official decoder validates
the exact serialized transaction and its txid.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

from darkbatch.settlement.ironwood_transaction_client import _default_binary_path
from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter


PCZT_MAX_BYTES = 2 * 1024 * 1024


def _run_rust(command: str, request: Mapping[str, Any], timeout_seconds: int = 1800) -> dict[str, Any]:
    binary = _default_binary_path()
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        raise RuntimeError(
            f"Rust engine not found/executable: {binary}. Build it with "
            "cargo build --manifest-path darkbatch_crypto/Cargo.toml --release"
        )
    payload = json.dumps(request, ensure_ascii=True, separators=(",", ":"))
    try:
        completed = subprocess.run(
            [binary, command],
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Rust operation {command} timed out; no broadcast was attempted.") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not start the Rust engine for {command}: {exc}") from exc
    if completed.returncode != 0:
        # Rust diagnostics are designed not to echo the request or secret input.
        detail = completed.stderr.strip() or f"Rust engine exited with code {completed.returncode}."
        raise RuntimeError(f"{command} failed closed: {detail}")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Rust engine returned malformed JSON for {command}.") from exc
    if not isinstance(result, dict):
        raise RuntimeError(f"Rust engine returned an invalid response for {command}.")
    return result


def _read_json(path: str | Path) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            result = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read valid JSON from {path}: {exc}") from exc
    if not isinstance(result, dict):
        raise RuntimeError(f"{path} must contain a JSON object.")
    return result


def _write_private_json(path: str | Path, value: Mapping[str, Any]) -> None:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    # O_EXCL prevents silently overwriting the unsigned/reviewed PCZT or another artifact.
    try:
        fd = os.open(str(target), flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"Refusing to overwrite existing file: {target}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(target, 0o600)
        except OSError:
            # Windows ACLs do not map POSIX modes exactly; file is still created exclusively.
            pass
    except Exception:
        try:
            target.unlink(missing_ok=True)
        finally:
            raise


def _pczt_hex_from_file(path: str | Path) -> str:
    data = _read_json(path)
    value = str(data.get("pczt_hex", "")).strip()
    if not value or len(value) % 2 or len(value) // 2 > PCZT_MAX_BYTES or not re.fullmatch(r"[0-9a-fA-F]+", value):
        raise RuntimeError("Input file must contain a valid, size-limited pczt_hex field.")
    return value.lower()


def command_export_fvk(args: argparse.Namespace) -> int:
    key = getpass.getpass("Raw Ironwood-protocol SpendingKey (hex; input hidden): ").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key):
        raise RuntimeError("SpendingKey must be exactly 32 bytes encoded as 64 hex characters.")
    result = _run_rust("export-ironwood-fvk-stdin", {
        "network": "testnet",
        "spending_key_hex": key.lower(),
    })
    if result.get("status") != "LOCAL_FVK_EXPORTED":
        raise RuntimeError("Rust engine returned an unexpected FVK-export status.")
    _write_private_json(args.out, result)
    print(f"Saved sensitive Full Viewing Key to {Path(args.out).resolve()} (owner-only file).")
    print(f"Testnet Unified Address: {result.get('unified_address', '')}")
    print("WARNING: the Full Viewing Key reveals wallet history. Do not send it to the public coordinator.")
    return 0


def command_create(args: argparse.Namespace) -> int:
    request = _read_json(args.request)
    result = _run_rust("create-ironwood-pczt-stdin", request)
    if result.get("status") != "PCZT_READY_FOR_REVIEW_AND_PARTICIPANT_SIGNATURES":
        raise RuntimeError("Official builder did not return an unsigned PCZT ready for review.")
    pczt_hex = str(result.get("pczt_hex", ""))
    if not pczt_hex or len(pczt_hex) % 2 or len(pczt_hex) // 2 > PCZT_MAX_BYTES:
        raise RuntimeError("Official builder returned invalid or oversized PCZT bytes.")
    _write_private_json(args.out, result)
    print(json.dumps({
        "status": result["status"],
        "network": result.get("network"),
        "transaction_version": result.get("transaction_version"),
        "consensus_branch_id": result.get("consensus_branch_id"),
        "input_value_zat": result.get("input_value_zat"),
        "output_value_zat": result.get("output_value_zat"),
        "fee_zat": result.get("fee_zat"),
        "input_action_indices": result.get("input_action_indices"),
        "sighash_hex": result.get("sighash_hex"),
        "pczt_file": str(Path(args.out).resolve()),
        "broadcast": False,
    }, indent=2))
    print("Review the outputs, values, change, fee, and sighash before any participant signs.")
    return 0


def command_inspect(args: argparse.Namespace) -> int:
    result = _run_rust("inspect-ironwood-pczt-stdin", {"pczt_hex": _pczt_hex_from_file(args.pczt)})
    print(json.dumps(result, indent=2))
    return 0


def command_sign(args: argparse.Namespace) -> int:
    pczt_hex = _pczt_hex_from_file(args.pczt)
    key = getpass.getpass("Your raw Ironwood SpendingKey (hex; input hidden): ").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key):
        raise RuntimeError("SpendingKey must be exactly 32 bytes encoded as 64 hex characters.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.nullifier):
        raise RuntimeError("--nullifier must be a 32-byte nullifier encoded as 64 hex characters.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.sighash):
        raise RuntimeError("--sighash must be the 32-byte digest explicitly reviewed by the participant.")
    result = _run_rust("sign-ironwood-pczt-stdin", {
        "pczt_hex": pczt_hex,
        "spending_key_hex": key.lower(),
        "nullifier_hex": args.nullifier.lower(),
        "expected_sighash_hex": args.sighash.lower(),
    })
    if result.get("status") != "PARTICIPANT_SIGNATURE_ADDED" or result.get("broadcast") is not False:
        raise RuntimeError("Signer returned an unexpected result; refusing to save it.")
    _write_private_json(args.out, result)
    print(json.dumps({
        "status": result["status"],
        "signed_nullifier_hex": result.get("signed_nullifier_hex"),
        "action_index": result.get("action_index"),
        "sighash_hex": result.get("sighash_hex"),
        "pczt_file": str(Path(args.out).resolve()),
        "broadcast": False,
    }, indent=2))
    print("Only your selected input was signed. Send the signed PCZT through the intended secure participant channel.")
    return 0


def command_finalize(args: argparse.Namespace) -> int:
    request = _read_json(args.request)
    result = _run_rust("finalize-ironwood-pczt-stdin", request, timeout_seconds=args.timeout)
    if result.get("status") != "BUILT_NOT_BROADCAST" or result.get("broadcast") is not False:
        raise RuntimeError("Finalizer did not return an explicitly non-broadcast transaction.")
    raw_hex = str(result.get("raw_tx_hex", ""))
    if not raw_hex or len(raw_hex) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", raw_hex):
        raise RuntimeError("Finalizer returned malformed raw transaction hex.")
    if int(result.get("raw_tx_bytes_len", -1)) != len(raw_hex) // 2:
        raise RuntimeError("Finalizer's serialized byte length does not match its raw transaction.")
    _write_private_json(args.out, result)
    print(json.dumps({k: result.get(k) for k in (
        "status", "network", "consensus_ready", "transaction_version",
        "version_group_id", "txid", "raw_tx_bytes_len", "input_count",
        "broadcast", "confirmed"
    )}, indent=2))
    print("Transaction is built, not broadcast. Independently review it before broadcasting.")
    return 0


def command_broadcast(args: argparse.Namespace) -> int:
    transaction = _read_json(args.tx_file)
    raw_hex = str(transaction.get("raw_tx_hex", "")).strip()
    txid = str(transaction.get("txid", "")).strip()
    if not raw_hex or not txid:
        raise RuntimeError("Transaction file must contain raw_tx_hex and txid.")
    adapter = TestnetSettlementAdapter()
    receipt = adapter.broadcast_raw_transaction(raw_hex, txid)
    print(json.dumps(receipt, indent=2))
    return 0 if receipt.get("broadcast") and receipt.get("txid_matches") else 2


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Local-only collaborative Zcash Ironwood PCZT workflow (Testnet)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    fvk = sub.add_parser("export-fvk", help="Export sensitive FVK to a protected local file.")
    fvk.add_argument("--out", required=True)
    fvk.set_defaults(func=command_export_fvk)

    create = sub.add_parser("create", help="Build an unsigned Ironwood PCZT from validated note data.")
    create.add_argument("--request", required=True, help="Private local JSON request with notes/FVKs/outputs.")
    create.add_argument("--out", required=True, help="New output path; existing files are never overwritten.")
    create.set_defaults(func=command_create)

    inspect = sub.add_parser("inspect", help="Inspect a PCZT's output/action manifest and sighash.")
    inspect.add_argument("--pczt", required=True)
    inspect.set_defaults(func=command_inspect)

    sign = sub.add_parser("sign", help="Sign only your input after verifying its details and sighash.")
    sign.add_argument("--pczt", required=True)
    sign.add_argument("--nullifier", required=True)
    sign.add_argument("--sighash", required=True, help="Must match the sighash that the participant reviewed.")
    sign.add_argument("--out", required=True, help="New signed PCZT output path.")
    sign.set_defaults(func=command_sign)

    finalize = sub.add_parser("finalize", help="Attach live witnesses, prove and extract the same PCZT.")
    finalize.add_argument("--request", required=True, help="Local JSON including signed PCZT, anchor, and all witnesses.")
    finalize.add_argument("--out", required=True)
    finalize.add_argument("--timeout", type=int, default=1800)
    finalize.set_defaults(func=command_finalize)

    broadcast = sub.add_parser("broadcast", help="Broadcast a finalized raw tx through a configured Zebra Testnet RPC.")
    broadcast.add_argument("--tx-file", required=True)
    broadcast.set_defaults(func=command_broadcast)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_cli())
