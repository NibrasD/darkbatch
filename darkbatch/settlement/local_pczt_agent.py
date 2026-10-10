"""
Trusted local PCZT settlement agent for DarkBatch.

This process intentionally runs beside a synced Zcash Testnet wallet. It reads real
Ironwood note openings and spending keys from local files, builds and signs a PCZT with
the repository's official librustzcash-backed CLI, creates the Halo 2 proof, extracts
the canonical V6 transaction, then sends ONLY raw transaction bytes and non-secret
accounting reports to the coordinator.

It never uploads the wallet inventory, notes, FVKs, Merkle paths, PCZT, or spending keys.
A synced wallet/provider must produce wallet_inventory.json; demo balances are rejected.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
from pathlib import Path
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, Iterable, List, Tuple


NU6_3_HEIGHT = 4_134_000
NU7_HEIGHT = 4_465_026
NU6_3_BRANCH = "0x37a5165b"
NU7_BRANCH = "0x77190ad9"
INVENTORY_SCHEMA = "darkbatch.ironwood-wallet-inventory.v1"
PLAN_SCHEMA = "darkbatch.fba-local-pczt-plan.v1"


class AgentError(RuntimeError):
    pass


def _validated_api_base(value: str) -> str:
    normalized = value.rstrip("/")
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise AgentError("API base must be a valid HTTP(S) URL")
    if parsed.scheme != "https" and host not in {"127.0.0.1", "localhost", "::1"}:
        raise AgentError("settlement token cannot be sent over remote plain HTTP; use HTTPS")
    return normalized


def _json_http(url: str, *, method: str = "GET", token: str | None = None,
               body: Dict[str, Any] | None = None, timeout: float = 15.0) -> Dict[str, Any]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-DarkBatch-Settlement-Token"] = token
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:800]
        raise AgentError(f"Coordinator returned HTTP {exc.code}: {detail}") from exc
    except Exception as exc:
        raise AgentError(f"Coordinator request failed: {exc}") from exc
    if not isinstance(result, dict):
        raise AgentError("Coordinator returned a non-object JSON response")
    return result


def _run_cli(binary: Path, args: List[str], *, cwd: Path, timeout: int = 900) -> str:
    if not binary.is_file():
        raise AgentError(f"Rust CLI binary was not found: {binary}")
    try:
        proc = subprocess.run(
            [str(binary), *args],
            cwd=str(cwd),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise AgentError(f"Rust command timed out after {timeout}s: {args[0]}") from exc
    if proc.returncode != 0:
        # Commands never print private keys, but avoid dumping arbitrary stdout. Rust errors
        # are returned without the input JSON or contents of a spending-key file.
        detail = (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()
        raise AgentError(f"Rust command {args[0]} failed: {detail[-1600:]}")
    return proc.stdout.strip()


def _write_private_json(path: Path, value: Dict[str, Any]) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows ACLs do not map to POSIX chmod; directory protection still applies.
        pass


def _private_workdir(path: Path) -> None:
    if path.exists():
        if not path.is_dir():
            raise AgentError(f"private workdir is not a directory: {path}")
        if any(path.iterdir()):
            raise AgentError(
                f"private workdir must be empty to avoid mixing old signatures/PCZTs with a new epoch: {path}"
            )
    else:
        path.mkdir(parents=True, exist_ok=False)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return float(text)
        except ValueError:
            pass
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return dt.datetime.fromisoformat(text).timestamp()
        except ValueError as exc:
            raise AgentError("inventory captured_at must be Unix time or ISO-8601 UTC") from exc
    raise AgentError("inventory is missing captured_at timestamp")


def _require_hex(value: Any, size: int, field: str) -> str:
    if not isinstance(value, str):
        raise AgentError(f"{field} must be hex text")
    normalized = "".join(value.split()).lower()
    if len(normalized) != size * 2 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise AgentError(f"{field} must be exactly {size} bytes of hex")
    return normalized


def _validate_inventory(snapshot: Dict[str, Any], server_status: Dict[str, Any], max_age: int,
                        max_tip_lag: int) -> Tuple[int, str, Dict[str, Any]]:
    if snapshot.get("schema") != INVENTORY_SCHEMA:
        raise AgentError(f"wallet inventory schema must be {INVENTORY_SCHEMA}")
    source = str(snapshot.get("source", "")).strip().lower()
    if not source or any(bad in source for bad in ("mock", "demo", "fake", "simul", "fixture")):
        raise AgentError("inventory source must identify a real synced wallet provider, not a mock/demo")
    if str(snapshot.get("network", "")).lower() not in {"zcash testnet", "testnet"}:
        raise AgentError("wallet inventory must be from Zcash Testnet")
    if str(snapshot.get("sync_status", "")).upper() != "SYNCED":
        raise AgentError("wallet provider is not SYNCED")
    if _timestamp(snapshot.get("captured_at")) < time.time() - max_age:
        raise AgentError(f"wallet inventory is stale; refresh it within {max_age} seconds")
    current_info = server_status.get("remote_chain_info")
    if not server_status.get("live_rpc_connected") or not isinstance(current_info, dict):
        raise AgentError("coordinator cannot verify its live activated Zebra Testnet RPC")
    try:
        current_height = int(current_info["blocks"])
        inventory_height = int(snapshot["tip_height"])
        anchor_height = int(snapshot["anchor_height"])
    except (KeyError, TypeError, ValueError):
        raise AgentError("inventory must include numeric tip_height and anchor_height")
    if inventory_height > current_height:
        raise AgentError("wallet inventory claims a tip above the coordinator's live Zebra tip")
    if current_height - inventory_height > max_tip_lag:
        raise AgentError(
            f"wallet inventory tip is {current_height - inventory_height} blocks behind Zebra; "
            "rescan before selecting spendable notes"
        )
    if not NU6_3_HEIGHT <= anchor_height <= inventory_height:
        raise AgentError("inventory anchor_height is outside the synchronized Testnet range")
    anchor_hex = _require_hex(snapshot.get("ironwood_anchor_hex"), 32, "ironwood_anchor_hex")
    wallets = snapshot.get("wallets")
    if not isinstance(wallets, dict) or not wallets:
        raise AgentError("inventory wallets must be a non-empty object keyed by the exact shielded address")
    return current_height + 1, anchor_hex, wallets


def _note_id(note: Dict[str, Any]) -> Tuple[str, int]:
    txid = str(note.get("txid", "")).lower()
    index = note.get("output_index")
    if len(txid) != 64 or any(ch not in "0123456789abcdef" for ch in txid):
        raise AgentError("each spendable note must include a real 64-hex txid")
    try:
        index = int(index)
    except (TypeError, ValueError):
        raise AgentError("each spendable note must include numeric output_index")
    return txid, index


def _validated_candidates(wallet: Dict[str, Any], label: str) -> List[Dict[str, Any]]:
    notes = wallet.get("spendable_notes")
    if not isinstance(notes, list):
        raise AgentError(f"wallet entry {label!r} has no spendable_notes list")
    result: List[Dict[str, Any]] = []
    for idx, note in enumerate(notes):
        if not isinstance(note, dict):
            continue
        if note.get("unspent") is not True or note.get("locked") is True or note.get("spent") is True:
            continue
        try:
            if str(note.get("pool", "")).lower() != "ironwood":
                continue
            if int(note.get("confirmations", 0)) < 1:
                continue
            amount = int(note["value_zat"])
            if amount <= 0:
                continue
            _require_hex(note.get("raw_address_hex"), 43, f"{label}.spendable_notes[{idx}].raw_address_hex")
            _require_hex(note.get("rho_hex"), 32, f"{label}.spendable_notes[{idx}].rho_hex")
            _require_hex(note.get("rseed_hex"), 32, f"{label}.spendable_notes[{idx}].rseed_hex")
            path = note.get("merkle_path_hex")
            if not isinstance(path, list) or len(path) != 32:
                continue
            path = [_require_hex(node, 32, f"{label}.spendable_notes[{idx}].merkle_path_hex") for node in path]
            position = int(note["merkle_position"])
            txid_out = _note_id(note)
        except (KeyError, TypeError, ValueError, AgentError):
            continue
        item = dict(note)
        item["_id"] = txid_out
        item["_value"] = amount
        item["_path"] = path
        item["_position"] = position
        result.append(item)
    # Largest-first minimizes action count. Rust performs the authoritative anchor-root check.
    return sorted(result, key=lambda note: (-note["_value"], note["_id"]))


def _make_memo(kind: str, epoch_id: int, intent_id: str, amount_zat: int,
               price_usd: float, status: str) -> str:
    memo = {
        "protocol": "DarkBatch",
        "type": kind,
        "epoch": epoch_id,
        "order": intent_id,
        "filled_zat": amount_zat,
        "price_usd": round(price_usd, 4),
        "quote_status": status,
    }
    encoded = json.dumps(memo, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(encoded) > 512:
        raise AgentError("generated private receipt memo exceeds Zcash's 512-byte memo limit")
    return encoded.hex()


def _solver_fee_zat(value: Any) -> int:
    if isinstance(value, bool):
        raise AgentError("solver_fee_zec must be a finite, non-negative decimal amount")
    try:
        fee = Decimal(str(0 if value is None else value)) * Decimal(100_000_000)
    except (InvalidOperation, ValueError):
        raise AgentError("solver_fee_zec must be a finite, non-negative decimal amount")
    if not fee.is_finite() or fee < 0:
        raise AgentError("solver_fee_zec must be a finite, non-negative decimal amount")
    return int(fee.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _allocate_pro_rata(total: int, weights: List[int]) -> List[int]:
    if total < 0 or any(weight < 0 for weight in weights):
        raise AgentError("pro-rata allocation amounts must be non-negative integers")
    if not weights:
        if total == 0:
            return []
        raise AgentError("cannot allocate a non-zero solver fee without seller owners")
    if total == 0:
        return [0 for _ in weights]
    weight_total = sum(weights)
    if weight_total <= 0:
        raise AgentError("cannot allocate a solver fee across zero seller fills")
    shares, remainders = [], []
    assigned = 0
    for index, weight in enumerate(weights):
        base, remainder = divmod(total * weight, weight_total)
        shares.append(base)
        remainders.append((index, remainder))
        assigned += base
    remaining = total - assigned
    remainders.sort(key=lambda item: (-item[1], item[0]))
    if remaining > len(remainders):
        raise AgentError("pro-rata solver fee remainder exceeded seller count")
    for index, _ in remainders[:remaining]:
        shares[index] += 1
    return shares


def _build_request(plan: Dict[str, Any], wallets: Dict[str, Any], anchor_hex: str,
                   target_height: int, solver_fee_receiver: Any = None) -> Tuple[Dict[str, Any], List[Tuple[Dict[str, Any], Path]]]:
    buys = plan.get("buy_fills")
    sells = plan.get("sell_fills")
    if not isinstance(buys, list) or not isinstance(sells, list) or not buys or not sells:
        raise AgentError("FBA plan does not contain positive buy and sell fills")
    total_buys = sum(int(fill["filled_zat"]) for fill in buys)
    total_sells = sum(int(fill["filled_zat"]) for fill in sells)
    if total_buys <= 0 or total_buys != total_sells:
        raise AgentError(f"FBA is not exactly balanced in integer zatoshi: buy={total_buys}, sell={total_sells}")

    # Group sell-side participants by canonical FullViewingKey, since one shielded wallet may
    # submit fills using multiple diversified addresses.
    owner_map: Dict[str, Dict[str, Any]] = {}
    for fill in sells:
        address = str(fill["shielded_address"])
        wallet = wallets.get(address)
        if not isinstance(wallet, dict):
            raise AgentError(f"no local wallet inventory entry matches seller address {address!r}")
        fvk = _require_hex(wallet.get("fvk_hex"), 96, f"wallets[{address}].fvk_hex")
        key_file_text = str(wallet.get("spending_key_file", "")).strip()
        if not key_file_text:
            raise AgentError(f"wallet entry for seller {address!r} must point to a local spending_key_file")
        key_file = Path(key_file_text).expanduser().resolve()
        if not key_file.is_file():
            raise AgentError(f"local spending key file for seller {address!r} was not found")
        change_address = _require_hex(wallet.get("change_address_raw_hex"), 43, f"wallets[{address}].change_address_raw_hex")
        bucket = owner_map.setdefault(fvk, {
            "fvk_hex": fvk,
            "change_address_raw_hex": change_address,
            "spending_key_file": key_file,
            "seller_fill_zat": 0,
            "addresses": [],
            "candidates": {},
        })
        if bucket["change_address_raw_hex"] != change_address:
            raise AgentError("the same FullViewingKey maps to conflicting change addresses in inventory")
        if bucket["spending_key_file"] != key_file:
            raise AgentError("the same FullViewingKey maps to conflicting spending key files in inventory")
        bucket["seller_fill_zat"] += int(fill["filled_zat"])
        bucket["addresses"].append(address)
        for note in _validated_candidates(wallet, address):
            note_id = note["_id"]
            prior = bucket["candidates"].get(note_id)
            if prior and prior["_value"] != note["_value"]:
                raise AgentError("the same note outpoint is reported with conflicting values")
            bucket["candidates"][note_id] = note

    if len(owner_map) == 0:
        raise AgentError("no sellers available for ZEC-side funding")
    owners = sorted(owner_map.values(), key=lambda owner: owner["fvk_hex"])
    solver_fee_zat = _solver_fee_zat(plan.get("solver_fee_zec", 0))
    if solver_fee_zat > total_sells:
        raise AgentError("solver fee in ZEC exceeds the matched seller ZEC fills")
    fee_shares = _allocate_pro_rata(
        solver_fee_zat, [int(owner["seller_fill_zat"]) for owner in owners]
    )
    for owner, share in zip(owners, fee_shares):
        owner["solver_fee_share_zat"] = share
    solver_fee_output_index = None
    fee_receiver_hex = ""
    fee_memo = ""
    if solver_fee_zat:
        if isinstance(solver_fee_receiver, str):
            solver_fee_receiver = {"address_raw_hex": solver_fee_receiver}
        if not isinstance(solver_fee_receiver, dict):
            raise AgentError(
                "non-zero solver fee requires a top-level solver_fee_receiver in the private wallet inventory"
            )
        fee_receiver_hex = _require_hex(
            solver_fee_receiver.get("address_raw_hex"), 43, "solver_fee_receiver.address_raw_hex"
        )
        fee_memo = solver_fee_receiver.get("memo_hex", "")
        if not isinstance(fee_memo, str):
            raise AgentError("solver_fee_receiver.memo_hex must be hexadecimal text")
        if fee_memo:
            try:
                if len(bytes.fromhex(fee_memo)) > 512:
                    raise AgentError("solver fee memo exceeds 512 bytes")
            except ValueError as exc:
                raise AgentError("solver_fee_receiver.memo_hex is invalid hex") from exc
    for owner in owners:
        owner["candidates"] = sorted(owner["candidates"].values(),
                                     key=lambda note: (-note["_value"], note["_id"]))
        if not owner["candidates"]:
            raise AgentError(
                f"seller wallet {owner['addresses'][0]!r} has no confirmed, unlocked Ironwood notes "
                "in the supplied synchronized inventory"
            )

    outputs = []
    for fill in buys:
        address = str(fill["shielded_address"])
        wallet = wallets.get(address)
        if not isinstance(wallet, dict):
            raise AgentError(f"no local wallet inventory entry matches buyer address {address!r}")
        outputs.append({
            "address_raw_hex": _require_hex(wallet.get("address_raw_hex"), 43, f"wallets[{address}].address_raw_hex"),
            "value_zat": int(fill["filled_zat"]),
            "memo_hex": _make_memo(
                "BUY_RECEIPT", int(plan["epoch_id"]), str(fill["intent_id"]),
                int(fill["filled_zat"]), float(fill["clearing_price_usd"]), "NOT_SETTLED",
            ),
        })

    if solver_fee_zat:
        solver_fee_output_index = len(outputs)
        outputs.append({
            "address_raw_hex": fee_receiver_hex,
            "value_zat": solver_fee_zat,
            "memo_hex": fee_memo or _make_memo(
                "SOLVER_FEE", int(plan["epoch_id"]), "solver",
                solver_fee_zat, float(plan["clearing_price_usd"]), "NOT_SETTLED",
            ),
        })

    change_outputs = []
    for owner in owners:
        receipt_total = owner["seller_fill_zat"]
        change_outputs.append({
            "fvk_hex": owner["fvk_hex"],
            "address_raw_hex": owner["change_address_raw_hex"],
            "value_zat": None,
            "seller_fill_zat": receipt_total + owner["solver_fee_share_zat"],
            "memo_hex": _make_memo(
                "SELL_RECEIPT", int(plan["epoch_id"]), ",".join(owner["addresses"])[:64],
                receipt_total, float(plan["clearing_price_usd"]), "NOT_SETTLED",
            ),
        })

    spend_rows: List[Tuple[Dict[str, Any], Path]] = []
    for owner in owners:
        owner["selected"] = []
        owner["selected_value"] = 0
        spend_rows.append((owner, owner["spending_key_file"]))
    # Select real on-chain candidate notes per seller. The Rust builder will check every Merkle
    # path against the supplied current anchor and will do the authoritative ZIP-317 fee check.
    for owner in owners:
        reserve = max(25_000, 5_000 * (len(outputs) + len(owners) + 2))
        for candidate in owner["candidates"]:
            if owner["selected_value"] >= owner["seller_fill_zat"] + owner["solver_fee_share_zat"] + reserve:
                break
            owner["selected"].append(candidate)
            owner["selected_value"] += candidate["_value"]
        if owner["selected_value"] < owner["seller_fill_zat"] + owner["solver_fee_share_zat"] + 10_000:
            raise AgentError(
                f"seller {owner['addresses'][0]!r} does not have enough confirmed notes above their sell fill plus solver-fee share "
                "to cover change and the network fee"
            )

    inputs = []
    for owner in owners:
        for note in owner["selected"]:
            inputs.append({
                "fvk_hex": owner["fvk_hex"],
                "raw_address_hex": note["raw_address_hex"].lower(),
                "value_zat": note["_value"],
                "rho_hex": note["rho_hex"].lower(),
                "rseed_hex": note["rseed_hex"].lower(),
                "merkle_position": note["_position"],
                "merkle_path_hex": note["_path"],
            })
    # One nullifier/outpoint must never be proposed twice, even if inventory entries were
    # duplicated across diversified receiver addresses.
    outpoints = [note["_id"] for owner in owners for note in owner["selected"]]
    if len(outpoints) != len(set(outpoints)):
        raise AgentError("selected Notes contain duplicate transaction outpoints across seller wallets")
    request = {
        "target_height": target_height,
        "ironwood_anchor_hex": anchor_hex,
        "inputs": inputs,
        "outputs": outputs,
        "solver_fee_output_zat": solver_fee_zat,
        "solver_fee_output_index": solver_fee_output_index,
        "solver_fee_output_address_raw_hex": fee_receiver_hex if solver_fee_zat else "",
        "change_outputs": change_outputs,
        "change_fvk_hex": "",
        "change_address_raw_hex": "",
    }
    # Return signing owner mapping in precisely the same order as request inputs/action indexes.
    signing_rows: List[Tuple[Dict[str, Any], Path]] = []
    for owner in owners:
        for _ in owner["selected"]:
            signing_rows.append((owner, owner["spending_key_file"]))
    return request, signing_rows


def _selected_inputs_and_signers(
    owners: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Tuple[Dict[str, Any], Path]]]:
    """Rebuild inputs and signing order from each owner's selected real Notes."""
    inputs: List[Dict[str, Any]] = []
    signing_rows: List[Tuple[Dict[str, Any], Path]] = []
    for owner in owners.values():
        for note in owner["selected"]:
            inputs.append({
                "fvk_hex": owner["fvk_hex"],
                "raw_address_hex": note["raw_address_hex"].lower(),
                "value_zat": note["_value"],
                "rho_hex": note["rho_hex"].lower(),
                "rseed_hex": note["rseed_hex"].lower(),
                "merkle_position": note["_position"],
                "merkle_path_hex": note["_path"],
            })
            signing_rows.append((owner, owner["spending_key_file"]))
    return inputs, signing_rows


def _run_full_pczt(binary: Path, workdir: Path, request: Dict[str, Any],
                   signing_rows: List[Tuple[Dict[str, Any], Path]]) -> Tuple[Dict[str, Any], str]:
    request_path = workdir / "private-fba-build.json"
    unsigned_pczt = workdir / "unsigned.pczt"
    build_report_path = workdir / "build-report.json"

    # Increase input selection only when the official builder indicates a genuine fee/funding
    # shortfall; invalid notes and bad Merkle paths must stop rather than be silently skipped.
    # Keep this iterative: recursive retries can exceed Python's recursion limit for wallets
    # with many small notes, and must rebuild action-index/signing order after every added input.
    owner_lookup = {owner["fvk_hex"]: owner for owner, _ in signing_rows}
    maximum_rounds = sum(len(owner["candidates"]) for owner in owner_lookup.values()) + 1
    last_error = ""
    build_report: Dict[str, Any] | None = None
    for _attempt in range(maximum_rounds):
        request["inputs"], signing_rows = _selected_inputs_and_signers(owner_lookup)
        for path in (unsigned_pczt, build_report_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        _write_private_json(request_path, request)
        try:
            _run_cli(binary, ["build-fba-pczt-local", str(request_path), str(unsigned_pczt), str(build_report_path)],
                     cwd=workdir)
            build_report = json.loads(build_report_path.read_text(encoding="utf-8"))
            break
        except AgentError as exc:
            last_error = str(exc)
            retryable = any(message in last_error.lower() for message in (
                "insufficient input", "cannot cover their allocated network fee",
                "no positive change after seller fill", "change output would be zero",
            ))
            if not retryable:
                raise
            advanced = False
            for owner in owner_lookup.values():
                selected_ids = {note["_id"] for note in owner["selected"]}
                next_note = next((note for note in owner["candidates"] if note["_id"] not in selected_ids), None)
                if next_note is not None:
                    owner["selected"].append(next_note)
                    owner["selected_value"] += next_note["_value"]
                    advanced = True
                    break
            if not advanced:
                raise AgentError(f"available notes cannot fund the actual protocol fee/change: {last_error}") from exc
    if build_report is None:
        raise AgentError(f"could not build PCZT after exhausting candidate notes: {last_error}")

    if build_report.get("status") != "FBA_PCZT_READY_FOR_LOCAL_PARTICIPANT_SIGNATURES":
        raise AgentError("Rust builder returned an unexpected FBA PCZT status")
    output_total = sum(int(o["value_zat"]) for o in request["outputs"])
    buyer_total = output_total - int(request["solver_fee_output_zat"])
    if int(build_report.get("recipient_total_zat", -1)) != output_total:
        raise AgentError("PCZT builder report does not match buyer plus solver-fee output totals")
    if int(build_report.get("buyer_output_total_zat", -1)) != buyer_total:
        raise AgentError("PCZT builder report does not match buyer-only output totals")
    if int(build_report.get("solver_fee_output_zat", -1)) != int(request["solver_fee_output_zat"]):
        raise AgentError("PCZT builder report does not match the configured solver fee output")
    if str(build_report.get("solver_fee_output_address_raw_hex", "")).lower() != str(request["solver_fee_output_address_raw_hex"]).lower():
        raise AgentError("PCZT builder report does not match the configured solver-fee receiver")
    if int(build_report.get("seller_fill_total_zat", -1)) != sum(int(c["seller_fill_zat"]) for c in request["change_outputs"]):
        raise AgentError("PCZT builder report does not match seller fill totals")

    action_indexes = build_report.get("ironwood_spend_action_indexes", [])
    if not isinstance(action_indexes, list) or len(action_indexes) != len(signing_rows):
        raise AgentError("PCZT builder spend/action index count does not match the selected real Notes")
    if not action_indexes:
        raise AgentError("PCZT contains no real spend actions to authorize")

    # IMPORTANT: each participant signs an independent view derived from the same original
    # unsigned PCZT. sign-pczt-local now redacts the participant's signed copy, so chaining
    # one participant's output into the next signer would drop the witness/opening fields
    # needed by other signers. Keep the full original private and combine all contributions
    # against it after every local signature has been generated.
    signed_contributions: List[Path] = []
    for index, ((owner, key_path), action_index) in enumerate(zip(signing_rows, action_indexes)):
        redacted_path = workdir / f"participant-{index:04d}-redacted.pczt"
        signed_path = workdir / f"participant-{index:04d}-signed-redacted.pczt"
        _run_cli(
            binary,
            ["redact-pczt-local", str(unsigned_pczt), str(int(action_index)), str(redacted_path)],
            cwd=workdir,
        )
        _run_cli(
            binary,
            ["sign-pczt-local", str(redacted_path), str(key_path), str(int(action_index)), str(signed_path)],
            cwd=workdir,
        )
        signed_contributions.append(signed_path)

    combined_pczt = workdir / "combined.pczt"
    _run_cli(
        binary,
        ["combine-pczts-local", str(combined_pczt), str(unsigned_pczt),
         *[str(path) for path in signed_contributions]],
        cwd=workdir,
    )

    tx_hex_path = workdir / "raw-transaction.hex"
    proof_report_path = workdir / "proof-report.json"
    _run_cli(binary, ["prove-extract-pczt-local", str(combined_pczt), str(tx_hex_path), str(proof_report_path)],
             cwd=workdir, timeout=1800)
    proof_report = json.loads(proof_report_path.read_text(encoding="utf-8"))
    raw_tx_hex = tx_hex_path.read_text(encoding="ascii").strip()
    if proof_report.get("status") != "PROOF_GENERATED_AND_TRANSACTION_EXTRACTED":
        raise AgentError("official prover/extractor did not report successful extraction")
    if proof_report.get("network_confirmed") is not False or proof_report.get("broadcast_ready") is not True:
        raise AgentError("proof report contains inconsistent transaction readiness fields")
    return {"build_report": build_report, "proof_report": proof_report}, raw_tx_hex


def _settle_usdc_after_zec_confirmation(
    api_base: str,
    epoch_id: int,
    quote_batch_id: str,
    txid: str,
    plan_path: Path,
    token: str,
    minimum_zec_confirmations: int,
    evm_wait_seconds: int,
) -> Dict[str, Any]:
    """Explicitly attest confirmed ZEC, release the funded USDC escrow, then finalize the API epoch."""
    if not os.getenv("DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY", "").strip():
        raise AgentError("--settle-usdc requires DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY in the local environment")
    if minimum_zec_confirmations < 1 or evm_wait_seconds < 1:
        raise AgentError("USDC release requires at least one ZEC confirmation and a positive EVM wait timeout")
    if not plan_path.is_file():
        raise AgentError(f"private FBA plan is missing for USDC release: {plan_path}")

    env = os.environ.copy()
    # quote_oracle reads this same secret name; the token remains in process environment,
    # never in command-line arguments or the public coordinator payload.
    env["DARKBATCH_SETTLEMENT_TOKEN"] = token
    command = [
        sys.executable, "-m", "darkbatch.settlement.quote_oracle",
        "--api-base", api_base,
        "--epoch-id", str(epoch_id),
        "--quote-batch-id", quote_batch_id,
        "--zec-txid", txid,
        "--plan-json", str(plan_path),
        "--minimum-zec-confirmations", str(minimum_zec_confirmations),
        "--wait-seconds", str(evm_wait_seconds),
        "--submit", "--release-usdc",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(Path(__file__).resolve().parents[2]),
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=(2 * evm_wait_seconds) + 45,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AgentError(
            f"USDC oracle subprocess did not complete cleanly; inspect the on-chain escrow before retrying: {exc}"
        ) from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or f"exit code {completed.returncode}").strip()
        raise AgentError(
            "USDC oracle/release failed or its final state is uncertain; inspect the escrow before retrying: "
            + detail[-1200:]
        )
    try:
        oracle = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AgentError(
            "USDC oracle returned invalid JSON after an EVM submission may have occurred; inspect the escrow before retrying"
        ) from exc
    if not isinstance(oracle, dict):
        raise AgentError("USDC oracle returned a non-object response; inspect escrow state before retrying")

    # Keep the non-secret oracle receipts locally so a later finalization-only recovery can
    # reuse the exact release transaction hash instead of submitting a second release.
    oracle_artifact = plan_path.parent / "usdc-oracle-result.json"
    previous_oracle: Dict[str, Any] = {}
    if oracle_artifact.is_file():
        try:
            loaded_previous = json.loads(oracle_artifact.read_text(encoding="utf-8"))
            if isinstance(loaded_previous, dict):
                previous_oracle = loaded_previous
        except (OSError, json.JSONDecodeError):
            previous_oracle = {}
    _write_private_json(oracle_artifact, oracle)
    result: Dict[str, Any] = {"oracle": oracle, "epoch_settled": False}
    if oracle.get("status") != "USDC_RELEASED":
        result["status"] = str(oracle.get("status") or "USDC_RELEASE_PENDING")
        result["message"] = (
            "ZEC is confirmed, but the oracle did not verify a completed USDC release. "
            "Inspect the escrow state before retrying."
        )
        return result

    release = oracle.get("release_transaction")
    release_txid = str(release.get("transaction_hash", "")).strip() if isinstance(release, dict) else ""
    if not release_txid:
        saved_oracle = previous_oracle
        saved_zec = saved_oracle.get("zec") if isinstance(saved_oracle, dict) else None
        saved_batch = str(saved_oracle.get("batch_id", "")).lower().removeprefix("0x") if isinstance(saved_oracle, dict) else ""
        saved_epoch = saved_oracle.get("epoch_id") if isinstance(saved_oracle, dict) else None
        saved_txid = str(saved_zec.get("txid", "")).lower() if isinstance(saved_zec, dict) else ""
        saved_release = saved_oracle.get("release_transaction") if isinstance(saved_oracle, dict) else None
        if (
            saved_oracle.get("status") == "USDC_RELEASED"
            and saved_epoch == epoch_id
            and saved_batch == quote_batch_id.lower().removeprefix("0x")
            and saved_txid == txid.lower().removeprefix("0x")
            and isinstance(saved_release, dict)
        ):
            release_txid = str(saved_release.get("transaction_hash", "")).strip()
    if not release_txid:
        result["status"] = "USDC_RELEASED_FINALIZATION_PENDING"
        result["message"] = "Oracle reports USDC released but no matching local EVM release transaction hash is available."
        return result

    try:
        finalized = _json_http(
            api_base.rstrip("/") + "/api/v1/settlement/quote-finalize",
            method="POST",
            token=token,
            body={
                "epoch_id": epoch_id,
                "quote_batch_id": quote_batch_id,
                "zec_txid": txid,
                "quote_release_txid": release_txid,
            },
            timeout=20.0,
        )
    except AgentError as exc:
        result.update({
            "status": "USDC_RELEASED_FINALIZATION_PENDING",
            "release_txid": release_txid,
            "finalization_error": str(exc),
            "message": "USDC release was confirmed by the oracle, but coordinator finalization failed. Retry quote-finalize after inspecting the API state.",
        })
        return result

    if finalized.get("status") != "CLEARED" or finalized.get("epoch_settled") is not True:
        result.update({
            "status": "USDC_RELEASED_FINALIZATION_PENDING",
            "release_txid": release_txid,
            "finalization": finalized,
            "message": "USDC release was reported, but the coordinator did not confirm the epoch as CLEARED.",
        })
        return result

    result.update({
        "status": "CLEARED",
        "epoch_settled": True,
        "quote_txid": finalized.get("quote_txid") or release_txid,
        "finalization": finalized,
    })
    return result


def finalize_usdc_existing(
    api_base: str,
    epoch_id: int,
    workdir: Path,
    token: str,
    quote_batch_id: str,
    minimum_zec_confirmations: int = 2,
    evm_wait_seconds: int = 120,
) -> Dict[str, Any]:
    """Resume only the USDC release/finalization for a previously broadcast transaction."""
    api_base = _validated_api_base(api_base)
    if not quote_batch_id:
        raise AgentError("--finalize-usdc-existing requires --quote-batch-id")
    if minimum_zec_confirmations < 1 or evm_wait_seconds < 1:
        raise AgentError("minimum ZEC confirmations and EVM wait timeout must be positive")
    if not os.getenv("DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY", "").strip():
        raise AgentError("--finalize-usdc-existing requires DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY in the local environment")

    plan_path = workdir / "fba-plan.json"
    proof_path = workdir / "proof-report.json"
    for path in (plan_path, proof_path):
        if not path.is_file():
            raise AgentError(f"USDC recovery artifact is missing: {path}")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    if plan.get("schema") != PLAN_SCHEMA or int(plan.get("epoch_id", -1)) != epoch_id:
        raise AgentError("saved FBA plan does not match the requested epoch")
    if proof.get("status") != "PROOF_GENERATED_AND_TRANSACTION_EXTRACTED" or proof.get("network") != "Zcash Testnet":
        raise AgentError("saved proof report is not a verified Testnet V6 extraction report")
    txid = str(proof.get("txid", "")).strip().lower()
    if len(txid) != 64 or any(ch not in "0123456789abcdef" for ch in txid):
        raise AgentError("saved proof report has an invalid ZEC TXID")

    latest = _json_http(
        api_base.rstrip("/") + f"/api/v1/settlement/tx/{txid}",
        token=token,
        timeout=10.0,
    )
    confirmations = int(latest.get("confirmations", 0))
    if latest.get("status") != "CONFIRMED" or confirmations < minimum_zec_confirmations:
        return {
            "status": "ZEC_CONFIRMATIONS_PENDING",
            "epoch_id": epoch_id,
            "txid": txid,
            "confirmations": confirmations,
            "minimum_zec_confirmations": minimum_zec_confirmations,
            "epoch_settled": False,
            "message": "USDC was not submitted: the coordinator has not observed the required real ZEC confirmations.",
        }

    result = _settle_usdc_after_zec_confirmation(
        api_base, epoch_id, quote_batch_id, txid, plan_path, token,
        minimum_zec_confirmations, evm_wait_seconds,
    )
    return {
        **result,
        "epoch_id": epoch_id,
        "txid": txid,
        "confirmations": confirmations,
        "workdir": str(workdir),
    }


def run_agent(api_base: str, epoch_id: int, inventory_path: Path, binary: Path,
              workdir: Path, token: str, max_age: int, max_tip_lag: int,
              broadcast: bool, quote_batch_id: str | None = None,
              wait_for_confirmation: int = 0, poll_interval: float = 3.0,
              settle_usdc: bool = False, minimum_zec_confirmations: int = 2,
              evm_wait_seconds: int = 120) -> Dict[str, Any]:
    api_base = _validated_api_base(api_base)
    if wait_for_confirmation < 0 or poll_interval <= 0:
        raise AgentError("confirmation timeout must be non-negative and poll interval must be positive")
    if settle_usdc:
        if not broadcast:
            raise AgentError("--settle-usdc requires --broadcast")
        if not quote_batch_id:
            raise AgentError("--settle-usdc requires a fully funded --quote-batch-id")
        if wait_for_confirmation <= 0:
            raise AgentError("--settle-usdc requires --wait-for-confirmation > 0")
        if minimum_zec_confirmations < 1 or evm_wait_seconds < 1:
            raise AgentError("minimum ZEC confirmations and EVM wait timeout must be positive")
        if not os.getenv("DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY", "").strip():
            raise AgentError("--settle-usdc requires DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY in the local environment")
    _private_workdir(workdir)
    snapshot = json.loads(inventory_path.read_text(encoding="utf-8"))
    server_status = _json_http(api_base.rstrip("/") + "/api/v1/settlement/testnet-status")
    target_height, anchor_hex, wallets = _validate_inventory(snapshot, server_status, max_age, max_tip_lag)
    plan = _json_http(
        api_base.rstrip("/") + f"/api/v1/settlement/local-plan/{epoch_id}",
        token=token,
    )
    if plan.get("schema") != PLAN_SCHEMA or int(plan.get("epoch_id", -1)) != epoch_id:
        raise AgentError("API did not return the expected private FBA PCZT plan")
    if plan.get("status") != "LOCAL_PCZT_REQUIRED":
        raise AgentError(f"epoch is not ready for local PCZT: {plan.get('status')}")
    if broadcast and not quote_batch_id:
        raise AgentError("--broadcast requires --quote-batch-id for a pre-funded USDC escrow batch")
    if broadcast and plan.get("quote_escrow_ready") is not True:
        raise AgentError("the signed quote plan is incomplete; cannot broadcast ZEC without exact USDC obligations")
    if broadcast:
        # Read-only on-chain USDC check before the expensive local Halo 2 proving stage.
        preflight = _json_http(
            api_base.rstrip("/") + "/api/v1/settlement/quote-preflight",
            method="POST",
            token=token,
            body={"epoch_id": epoch_id, "quote_batch_id": quote_batch_id},
        )
        if preflight.get("status") != "USDC_LOCKED":
            raise AgentError("USDC quote escrow did not report a fully funded batch")
        if str(preflight.get("quote_plan_hash", "")).lower() != str(plan.get("quote_plan_hash", "")).lower():
            raise AgentError("funded USDC escrow commitment does not match this FBA plan")

    # Keep the canonical plan as a private artifact for later safe submission/resume.
    # Write it only after any escrow preflight succeeds, so an unfunded batch can retry cleanly.
    plan_artifact = workdir / "fba-plan.json"
    _write_private_json(plan_artifact, plan)
    request, signing_rows = _build_request(
        plan, wallets, anchor_hex, target_height, snapshot.get("solver_fee_receiver")
    )
    reports, raw_tx_hex = _run_full_pczt(binary, workdir, request, signing_rows)
    build_report, proof_report = reports["build_report"], reports["proof_report"]
    if int(build_report.get("target_height", -1)) != target_height:
        raise AgentError("Rust build report target height does not match current Testnet tip")
    expected_branch = NU7_BRANCH if target_height >= NU7_HEIGHT else NU6_3_BRANCH
    if str(build_report.get("consensus_branch_id", "")).lower() != expected_branch:
        raise AgentError(f"PCZT builder branch report does not match target height; expected {expected_branch}")
    if str(proof_report.get("consensus_branch_id", "")).lower() != expected_branch:
        raise AgentError(f"Extracted transaction branch does not match target height; expected {expected_branch}")
    if len(raw_tx_hex) // 2 != int(proof_report.get("raw_transaction_bytes", -1)):
        raise AgentError("raw transaction length does not match official proof/extraction report")

    result: Dict[str, Any] = {
        "status": "BUILT_AND_PROVED_LOCALLY",
        "epoch_id": epoch_id,
        "transaction_id": proof_report.get("txid"),
        "target_height": target_height,
        "branch": expected_branch,
        "input_notes": len(request["inputs"]),
        "recipient_outputs": len(request["outputs"]),
        "network_fee_zat": int(build_report["fee_zat"]),
        "change_zat": int(build_report["change_zat"]),
        "quote_leg_status": "NOT_SETTLED",
        "workdir": str(workdir),
        "broadcast": False,
    }
    # By default the agent stops before an irreversible network action. --broadcast requests
    # Testnet submission; it still does not settle the cross-asset quote leg.
    if not broadcast:
        return result
    submit_body = {
        "epoch_id": epoch_id,
        "quote_batch_id": quote_batch_id,
        "txid": proof_report["txid"],
        "raw_tx_hex": raw_tx_hex,
        "build_report": build_report,
        "proof_report": proof_report,
    }
    response = _json_http(
        api_base.rstrip("/") + "/api/v1/settlement/raw-v6",
        method="POST",
        token=token,
        body=submit_body,
        timeout=30.0,
    )
    result["broadcast"] = response
    result["status"] = response.get("status", "BROADCAST_SUBMITTED")
    result["broadcast_requested"] = True
    if result["status"] == "BROADCAST_TXID_MISMATCH":
        result["message"] = "The node-reported transaction ID did not match the local extraction report; the FBA epoch was not associated or settled."
        return result
    if wait_for_confirmation > 0 and result.get("transaction_id"):
        required_confirmations = minimum_zec_confirmations if settle_usdc else 1
        deadline = time.monotonic() + wait_for_confirmation
        last_seen: Dict[str, Any] | None = None
        while time.monotonic() < deadline:
            latest = _json_http(
                api_base.rstrip("/") + f"/api/v1/settlement/tx/{result['transaction_id']}",
                token=token,
                timeout=5.0,
            )
            last_seen = latest
            if latest.get("status") == "CONFIRMED" and int(latest.get("confirmations", 0)) >= required_confirmations:
                result["transaction_status"] = "CONFIRMED"
                result["confirmations"] = latest.get("confirmations")
                result["block_hash"] = latest.get("block_hash")
                result["quote_leg_status"] = latest.get("quote_leg_status", "NOT_SETTLED")
                if settle_usdc:
                    try:
                        usdc = _settle_usdc_after_zec_confirmation(
                            api_base, epoch_id, str(quote_batch_id), str(result["transaction_id"]),
                            plan_artifact, token, minimum_zec_confirmations, evm_wait_seconds,
                        )
                    except AgentError as exc:
                        usdc = {
                            "status": "USDC_RELEASE_PENDING",
                            "epoch_settled": False,
                            "error": str(exc),
                            "message": "ZEC is confirmed; USDC release/finalization needs recovery. Inspect on-chain state before retrying.",
                        }
                    result["usdc_settlement"] = usdc
                    if usdc.get("epoch_settled") is True and usdc.get("status") == "CLEARED":
                        result["status"] = "CLEARED"
                        result["epoch_settled"] = True
                        result["quote_leg_status"] = "SETTLED"
                        result["quote_txid"] = usdc.get("quote_txid")
                        result["message"] = "ZEC confirmation, USDC release, and coordinator epoch finalization were all verified."
                    else:
                        result["status"] = "ZEC_CONFIRMED_USDC_RELEASE_PENDING"
                        result["epoch_settled"] = False
                        result["quote_leg_status"] = "RELEASE_PENDING"
                        result["message"] = str(usdc.get("message") or "ZEC is confirmed; USDC release and epoch finalization remain pending.")
                else:
                    result["status"] = "ZEC_CONFIRMED_QUOTE_RELEASE_PENDING"
                    result["message"] = "ZEC is confirmed on Testnet; USDC release and final epoch settlement remain separate."
                break
            time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))
        else:
            result["status"] = "BROADCAST_PENDING_CONFIRMATION"
            if last_seen and last_seen.get("status") == "CONFIRMED":
                result["confirmations"] = last_seen.get("confirmations")
                result["message"] = f"ZEC has some confirmations, but {required_confirmations} were required before proceeding."
            else:
                result["message"] = "No required block confirmation was observed before timeout; the FBA epoch remains unsettled."
    return result


def submit_existing(api_base: str, epoch_id: int, workdir: Path, token: str,
                   quote_batch_id: str | None, wait_for_confirmation: int = 0,
                   poll_interval: float = 3.0, settle_usdc: bool = False,
                   minimum_zec_confirmations: int = 2,
                   evm_wait_seconds: int = 120) -> Dict[str, Any]:
    """Submit a previously proven local V6 transaction without rebuilding/re-signing it."""
    if not quote_batch_id:
        raise AgentError("--submit-existing requires --quote-batch-id for the fully funded USDC batch")
    api_base = _validated_api_base(api_base)
    if wait_for_confirmation < 0 or poll_interval <= 0:
        raise AgentError("confirmation timeout must be non-negative and poll interval must be positive")
    if settle_usdc:
        if wait_for_confirmation <= 0:
            raise AgentError("--settle-usdc requires --wait-for-confirmation > 0")
        if minimum_zec_confirmations < 1 or evm_wait_seconds < 1:
            raise AgentError("minimum ZEC confirmations and EVM wait timeout must be positive")
        if not os.getenv("DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY", "").strip():
            raise AgentError("--settle-usdc requires DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY in the local environment")

    plan_path = workdir / "fba-plan.json"
    build_path = workdir / "build-report.json"
    proof_path = workdir / "proof-report.json"
    raw_path = workdir / "raw-transaction.hex"
    for path in (plan_path, build_path, proof_path, raw_path):
        if not path.is_file():
            raise AgentError(f"cannot submit existing transaction; required private artifact is missing: {path}")

    original_plan = json.loads(plan_path.read_text(encoding="utf-8"))
    build_report = json.loads(build_path.read_text(encoding="utf-8"))
    proof_report = json.loads(proof_path.read_text(encoding="utf-8"))
    raw_tx_hex = "".join(raw_path.read_text(encoding="ascii").split()).lower()
    if original_plan.get("schema") != PLAN_SCHEMA or int(original_plan.get("epoch_id", -1)) != epoch_id:
        raise AgentError("private FBA plan does not match the requested epoch")
    if proof_report.get("status") != "PROOF_GENERATED_AND_TRANSACTION_EXTRACTED":
        raise AgentError("private proof report does not confirm official PCZT proof/extraction")
    if proof_report.get("network") != "Zcash Testnet" or proof_report.get("transaction_version") != 6:
        raise AgentError("extracted transaction report is not for Testnet V6")
    if not raw_tx_hex or len(raw_tx_hex) % 2 or any(c not in "0123456789abcdef" for c in raw_tx_hex):
        raise AgentError("saved raw transaction is not valid even-length hex")
    if len(raw_tx_hex) // 2 != int(proof_report.get("raw_transaction_bytes", -1)):
        raise AgentError("saved raw transaction length does not match the official extraction report")
    reported_txid = str(proof_report.get("txid", "")).strip().lower()
    if not reported_txid:
        raise AgentError("official proof report does not contain a transaction ID")

    # Refresh the canonical plan and ensure the batch has not changed after the transaction was
    # constructed. This prevents an old local raw transaction being attached to a newer FBA epoch.
    current_plan = _json_http(
        api_base.rstrip("/") + f"/api/v1/settlement/local-plan/{epoch_id}",
        token=token,
    )
    if current_plan.get("status") != "LOCAL_PCZT_REQUIRED":
        raise AgentError("coordinator no longer has an active local PCZT plan for this epoch")
    if str(current_plan.get("quote_plan_hash", "")).lower() != str(original_plan.get("quote_plan_hash", "")).lower():
        raise AgentError("current FBA quote commitment differs from the saved private plan")
    if original_plan.get("quote_escrow_ready") is not True:
        raise AgentError("saved FBA plan was not ready for a complete quote commitment")

    preflight = _json_http(
        api_base.rstrip("/") + "/api/v1/settlement/quote-preflight",
        method="POST",
        token=token,
        body={"epoch_id": epoch_id, "quote_batch_id": quote_batch_id},
    )
    if preflight.get("status") != "USDC_LOCKED":
        raise AgentError("USDC escrow is not fully funded; raw transaction was not submitted")
    if str(preflight.get("quote_plan_hash", "")).lower() != str(original_plan["quote_plan_hash"]).lower():
        raise AgentError("on-chain USDC escrow is committed to a different FBA plan")

    try:
        target_height = int(build_report["target_height"])
        expiry_height = int(build_report["expiry_height"])
        current_status = _json_http(api_base.rstrip("/") + "/api/v1/settlement/testnet-status")
        if current_status.get("live_rpc_connected") is not True:
            raise AgentError("coordinator cannot verify live Zebra Testnet; raw transaction was not submitted")
        chain_info = current_status.get("remote_chain_info")
        if not isinstance(chain_info, dict):
            raise AgentError("live Zebra status omitted chain info")
        current_height = int(chain_info["blocks"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AgentError(f"could not validate live Testnet height or transaction expiry: {exc}") from exc

    expected_branch = NU7_BRANCH if target_height >= NU7_HEIGHT else NU6_3_BRANCH
    if str(build_report.get("consensus_branch_id", "")).lower() != expected_branch:
        raise AgentError(f"saved PCZT build branch does not match target height; expected {expected_branch}")
    if str(proof_report.get("consensus_branch_id", "")).lower() != expected_branch:
        raise AgentError(f"saved transaction branch does not match target height; expected {expected_branch}")
    if current_height >= expiry_height:
        raise AgentError(
            f"transaction expiry height {expiry_height} has passed at live tip {current_height}; rebuild from fresh notes/witnesses"
        )

    response = _json_http(
        api_base.rstrip("/") + "/api/v1/settlement/raw-v6",
        method="POST",
        token=token,
        body={
            "epoch_id": epoch_id,
            "quote_batch_id": quote_batch_id,
            "txid": reported_txid,
            "raw_tx_hex": raw_tx_hex,
            "build_report": build_report,
            "proof_report": proof_report,
        },
        timeout=30.0,
    )
    transaction = response.get("transaction") if isinstance(response.get("transaction"), dict) else {}
    result: Dict[str, Any] = {
        "status": response.get("status"),
        "epoch_id": epoch_id,
        "txid": transaction.get("txid") or reported_txid,
        "extracted_txid": reported_txid,
        "transaction_status": transaction.get("status"),
        "epoch_settled": response.get("epoch_settled", False),
        "quote_leg_status": response.get("quote_leg_status", "NOT_SETTLED"),
        "workdir": str(workdir),
        "broadcast": True,
        "message": response.get("message", "ZEC broadcast result recorded; confirmation and USDC release remain separate steps."),
    }
    if result["status"] == "BROADCAST_TXID_MISMATCH":
        result["message"] = "The node-reported transaction ID did not match the local extraction report; the FBA epoch was not associated or settled."
        return result
    if wait_for_confirmation > 0:
        required_confirmations = minimum_zec_confirmations if settle_usdc else 1
        deadline = time.monotonic() + wait_for_confirmation
        last_seen: Dict[str, Any] | None = None
        while time.monotonic() < deadline:
            latest = _json_http(
                api_base.rstrip("/") + f"/api/v1/settlement/tx/{result['txid']}",
                token=token,
                timeout=5.0,
            )
            last_seen = latest
            if latest.get("status") == "CONFIRMED" and int(latest.get("confirmations", 0)) >= required_confirmations:
                result["transaction_status"] = "CONFIRMED"
                result["confirmations"] = latest.get("confirmations")
                result["block_hash"] = latest.get("block_hash")
                result["epoch_settled"] = False
                result["quote_leg_status"] = latest.get("quote_leg_status", "NOT_SETTLED")
                if settle_usdc:
                    try:
                        usdc = _settle_usdc_after_zec_confirmation(
                            api_base, epoch_id, str(quote_batch_id), str(result["txid"]),
                            plan_path, token, minimum_zec_confirmations, evm_wait_seconds,
                        )
                    except AgentError as exc:
                        usdc = {
                            "status": "USDC_RELEASE_PENDING",
                            "epoch_settled": False,
                            "error": str(exc),
                            "message": "ZEC is confirmed; USDC release/finalization needs recovery. Inspect on-chain state before retrying.",
                        }
                    result["usdc_settlement"] = usdc
                    if usdc.get("epoch_settled") is True and usdc.get("status") == "CLEARED":
                        result["status"] = "CLEARED"
                        result["epoch_settled"] = True
                        result["quote_leg_status"] = "SETTLED"
                        result["quote_txid"] = usdc.get("quote_txid")
                        result["message"] = "ZEC confirmation, USDC release, and coordinator epoch finalization were all verified."
                    else:
                        result["status"] = "ZEC_CONFIRMED_USDC_RELEASE_PENDING"
                        result["epoch_settled"] = False
                        result["quote_leg_status"] = "RELEASE_PENDING"
                        result["message"] = str(usdc.get("message") or "ZEC is confirmed; USDC release and epoch finalization remain pending.")
                else:
                    result["status"] = "ZEC_CONFIRMED_QUOTE_RELEASE_PENDING"
                    result["message"] = (
                        "ZEC is confirmed on Testnet. USDC payout/release is still pending and the FBA epoch is not fully settled."
                    )
                break
            time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))
        else:
            result["status"] = "BROADCAST_PENDING_CONFIRMATION"
            if last_seen and last_seen.get("status") == "CONFIRMED":
                result["confirmations"] = last_seen.get("confirmations")
                result["message"] = f"ZEC has some confirmations, but {required_confirmations} were required before proceeding."
            else:
                result["message"] = "No required block confirmation was observed before timeout; the FBA epoch remains unsettled."
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build/sign/prove a real V6 Ironwood PCZT locally from a synchronized wallet inventory."
    )
    parser.add_argument("--api-base", default=os.getenv("DARKBATCH_API_BASE", "http://127.0.0.1:8000"))
    parser.add_argument("--epoch-id", required=True, type=int)
    parser.add_argument("--wallet-inventory", type=Path,
                        help="Private JSON inventory from a real synced Zcash Testnet wallet/provider; required unless --submit-existing")
    parser.add_argument("--submit-existing", action="store_true",
                        help="Submit the already-proven raw transaction in --workdir without rescanning/rebuilding")
    parser.add_argument("--finalize-usdc-existing", action="store_true",
                        help="Resume only the USDC oracle/release/finalization for a previously broadcast ZEC transaction; never rebroadcasts ZEC")
    parser.add_argument("--rust-binary", type=Path,
                        default=Path(os.getenv("DARKBATCH_CRYPTO_BIN", "darkbatch_crypto/target/release/darkbatch_crypto")))
    parser.add_argument("--workdir", required=True, type=Path,
                        help="Private work directory; contains PCZT and note-opening artifacts")
    parser.add_argument("--token-env", default="DARKBATCH_SETTLEMENT_TOKEN",
                        help="Environment variable holding the coordinator's local settlement token")
    parser.add_argument("--max-inventory-age", type=int, default=300)
    parser.add_argument("--max-tip-lag", type=int, default=12)
    parser.add_argument("--quote-batch-id", default=os.getenv("DARKBATCH_USDC_BATCH_ID"),
                        help="Pre-funded on-chain USDC escrow batch ID (bytes32 hex)")
    parser.add_argument("--broadcast", action="store_true",
                        help="Submit the newly proven raw V6 transaction only after API verifies funded USDC escrow")
    parser.add_argument("--wait-for-confirmation", type=int, default=0,
                        help="When broadcasting/submitting existing, poll real Testnet status for this many seconds")
    parser.add_argument("--settle-usdc", action="store_true",
                        help="After the required real ZEC confirmations, explicitly submit the EVM oracle attestation and USDC release, then finalize the epoch API state")
    parser.add_argument("--minimum-zec-confirmations", type=int, default=2,
                        help="Minimum Zebra confirmations required before --settle-usdc can submit EVM transactions")
    parser.add_argument("--evm-wait-seconds", type=int, default=120,
                        help="Wait limit for each EVM attestation/release receipt when --settle-usdc is enabled")
    parser.add_argument("--poll-interval", type=float, default=3.0)
    args = parser.parse_args()
    token = os.getenv(args.token_env, "").strip()
    if not token:
        print(f"ERROR: environment variable {args.token_env} is empty", file=sys.stderr)
        return 2
    try:
        if args.wait_for_confirmation < 0 or args.poll_interval <= 0:
            raise AgentError("confirmation timeout must be non-negative and poll interval must be positive")
        api_base = args.api_base.rstrip("/")
        if args.finalize_usdc_existing:
            if args.submit_existing or args.broadcast or args.wallet_inventory is not None or args.settle_usdc:
                raise AgentError("--finalize-usdc-existing must be used alone; it never builds or broadcasts a ZEC transaction")
            result = finalize_usdc_existing(
                api_base, args.epoch_id, args.workdir.resolve(), token,
                args.quote_batch_id, args.minimum_zec_confirmations, args.evm_wait_seconds,
            )
        elif args.submit_existing:
            result = submit_existing(
                api_base, args.epoch_id, args.workdir.resolve(), token,
                args.quote_batch_id, args.wait_for_confirmation, args.poll_interval,
                args.settle_usdc, args.minimum_zec_confirmations, args.evm_wait_seconds,
            )
        else:
            if args.wallet_inventory is None:
                raise AgentError("--wallet-inventory is required unless --submit-existing or --finalize-usdc-existing is used")
            result = run_agent(
                api_base, args.epoch_id, args.wallet_inventory, args.rust_binary.resolve(),
                args.workdir.resolve(), token, args.max_inventory_age, args.max_tip_lag, args.broadcast,
                args.quote_batch_id, args.wait_for_confirmation, args.poll_interval,
                args.settle_usdc, args.minimum_zec_confirmations, args.evm_wait_seconds,
            )
        print(json.dumps(result, indent=2))
        return 0
    except (AgentError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
