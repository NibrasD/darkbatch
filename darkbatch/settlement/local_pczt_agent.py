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
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


NU6_3_HEIGHT = 4_134_000
NU7_HEIGHT = 4_465_026
NU6_3_BRANCH = "0x37a5165b"
NU7_BRANCH = "0x77190ad9"
INVENTORY_SCHEMA = "darkbatch.ironwood-wallet-inventory.v1"
PLAN_SCHEMA = "darkbatch.fba-local-pczt-plan.v1"


class AgentError(RuntimeError):
    pass


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


def _build_request(plan: Dict[str, Any], wallets: Dict[str, Any], anchor_hex: str,
                   target_height: int) -> Tuple[Dict[str, Any], List[Tuple[Dict[str, Any], Path]]]:
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

    change_outputs = []
    for owner in owners:
        receipt_total = owner["seller_fill_zat"]
        change_outputs.append({
            "fvk_hex": owner["fvk_hex"],
            "address_raw_hex": owner["change_address_raw_hex"],
            "value_zat": None,
            "seller_fill_zat": receipt_total,
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
            if owner["selected_value"] >= owner["seller_fill_zat"] + reserve:
                break
            owner["selected"].append(candidate)
            owner["selected_value"] += candidate["_value"]
        if owner["selected_value"] < owner["seller_fill_zat"] + 10_000:
            raise AgentError(
                f"seller {owner['addresses'][0]!r} does not have enough confirmed notes above their sell fill "
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


def _run_full_pczt(binary: Path, workdir: Path, request: Dict[str, Any],
                   signing_rows: List[Tuple[Dict[str, Any], Path]]) -> Tuple[Dict[str, Any], str]:
    request_path = workdir / "private-fba-build.json"
    unsigned_pczt = workdir / "unsigned.pczt"
    build_report_path = workdir / "build-report.json"
    _write_private_json(request_path, request)

    # Increase input selection only when the official builder indicates a genuine fee/funding
    # shortfall; invalid notes and bad Merkle paths must stop rather than be silently skipped.
    owner_lookup = {owner["fvk_hex"]: owner for owner, _ in signing_rows}
    all_signing_rows = list(signing_rows)
    tried_counts = tuple(len(owner["selected"]) for owner in owner_lookup.values())
    maximum_rounds = sum(len(owner["candidates"]) for owner in owner_lookup.values()) + 1
    last_error = ""
    for _attempt in range(maximum_rounds):
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
                    # Rebuild inputs and signing-order mapping together; never keep stale indexes.
                    return _retry_with_more_notes(binary, workdir, request, owner_lookup, signing_rows, next_note)
                    advanced = True
            if not advanced:
                raise AgentError(f"available notes cannot fund the actual protocol fee/change: {last_error}") from exc
    else:
        raise AgentError(f"could not build PCZT after exhausting candidate notes: {last_error}")

    if build_report.get("status") != "FBA_PCZT_READY_FOR_LOCAL_PARTICIPANT_SIGNATURES":
        raise AgentError("Rust builder returned an unexpected FBA PCZT status")
    if int(build_report.get("recipient_total_zat", -1)) != sum(int(o["value_zat"]) for o in request["outputs"]):
        raise AgentError("PCZT builder report does not match buyer output totals")
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


def _retry_with_more_notes(binary: Path, workdir: Path, request: Dict[str, Any],
                           owners: Dict[str, Dict[str, Any]],
                           original_rows: List[Tuple[Dict[str, Any], Path]],
                           added_note: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    # Rebuild input records and key assignment from each owner's authoritative selected-note list.
    inputs = []
    signing_rows = []
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
    request["inputs"] = inputs
    return _run_full_pczt(binary, workdir, request, signing_rows)


def run_agent(api_base: str, epoch_id: int, inventory_path: Path, binary: Path,
              workdir: Path, token: str, max_age: int, max_tip_lag: int,
              broadcast: bool, quote_batch_id: str | None = None) -> Dict[str, Any]:
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
    # Keep the canonical plan as a private artifact for the escrow registrar. Never publish
    # it publicly: it includes participant addresses, fills, and individual quote amounts.
    plan_artifact = workdir / "fba-plan.json"
    _write_private_json(plan_artifact, plan)
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

    request, signing_rows = _build_request(plan, wallets, anchor_hex, target_height)
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
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build/sign/prove a real V6 Ironwood PCZT locally from a synchronized wallet inventory."
    )
    parser.add_argument("--api-base", default=os.getenv("DARKBATCH_API_BASE", "http://127.0.0.1:8000"))
    parser.add_argument("--epoch-id", required=True, type=int)
    parser.add_argument("--wallet-inventory", required=True, type=Path,
                        help="Private JSON inventory from a real synced Zcash Testnet wallet/provider")
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
                        help="Submit the proven raw V6 transaction only after API verifies fully funded USDC escrow")
    args = parser.parse_args()
    token = os.getenv(args.token_env, "").strip()
    if not token:
        print(f"ERROR: environment variable {args.token_env} is empty", file=sys.stderr)
        return 2
    try:
        result = run_agent(
            args.api_base, args.epoch_id, args.wallet_inventory, args.rust_binary.resolve(),
            args.workdir.resolve(), token, args.max_inventory_age, args.max_tip_lag, args.broadcast,
            args.quote_batch_id,
        )
        print(json.dumps(result, indent=2))
        return 0
    except (AgentError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
