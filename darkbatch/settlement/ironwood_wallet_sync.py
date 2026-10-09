"""
Local Ironwood Testnet wallet scanner and transaction workflow.

Run this module locally, near the wallet and Zebra RPC. The spending key is entered
with a hidden prompt and passed only to the Rust process through stdin. It is never
sent to the public coordinator or persisted in the wallet-state JSON.

IMPORTANT:
- Initialize at a height before the notes you want to discover.
- The initial treestate checkpoint does not reveal old notes by itself. Notes received
  before that checkpoint need a valid witness imported from a real wallet.
- This scanner records genuine V3 notes and witnesses. The FBA coordinator still does
  not have non-custodial multi-party signing integrated, so a match is not settlement.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence

from darkbatch.settlement.ironwood_transaction_client import (
    BuiltIronwoodTransaction,
    _default_binary_path,
    build_ironwood_transaction,
)
from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter

ACTIVATION_HEIGHT = 4_134_000
STATE_SCHEMA_VERSION = 1


class ZebraRpc:
    def __init__(
        self,
        url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 10.0,
    ):
        self.url = (url or os.getenv("ZCASH_TESTNET_RPC_URL") or "").strip()
        self.username = username if username is not None else os.getenv("ZCASH_TESTNET_RPC_USER", "")
        self.password = password if password is not None else os.getenv("ZCASH_TESTNET_RPC_PASS", "")
        self.timeout = timeout
        if not self.url:
            raise RuntimeError("Set ZCASH_TESTNET_RPC_URL to your own Zebra Testnet JSON-RPC endpoint.")

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        payload = {"jsonrpc": "1.0", "id": "darkbatch-local-wallet", "method": method, "params": params or []}
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self.username and self.password:
            import base64
            token = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
            request.add_header("Authorization", f"Basic {token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                parsed = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"Zebra RPC {method} could not be reached: {exc}") from exc
        if parsed.get("error"):
            raise RuntimeError(f"Zebra RPC {method} failed: {parsed['error']}")
        if "result" not in parsed:
            raise RuntimeError(f"Zebra RPC {method} returned no result.")
        return parsed["result"]

    def testnet_info(self) -> dict[str, Any]:
        info = self.call("getblockchaininfo")
        chain = str(info.get("chain", "")).lower()
        if chain != "test" and "testnet" not in chain:
            raise RuntimeError(f"Refusing wallet sync: RPC endpoint reports non-Testnet chain {chain!r}.")
        height = int(info.get("blocks", -1))
        if height < ACTIVATION_HEIGHT:
            raise RuntimeError(
                f"Node tip {height} is below Ironwood Testnet activation {ACTIVATION_HEIGHT}."
            )
        return info

    def block_hash(self, height: int) -> str:
        result = self.call("getblockhash", [int(height)])
        if not isinstance(result, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", result):
            raise RuntimeError(f"getblockhash({height}) returned an invalid block hash.")
        return result.lower()

    def treestate(self, block_hash: str) -> dict[str, Any]:
        state = self.call("z_gettreestate", [block_hash])
        if not isinstance(state, dict):
            raise RuntimeError("z_gettreestate returned an unexpected response.")
        if str(state.get("hash", "")).lower() != block_hash.lower():
            raise RuntimeError("z_gettreestate hash does not match the requested canonical block.")
        height = int(state.get("height", -1))
        pool = state.get("ironwood")
        commitments = pool.get("commitments") if isinstance(pool, dict) else None
        final_state = commitments.get("finalState") if isinstance(commitments, dict) else None
        if not isinstance(final_state, str) or not final_state:
            raise RuntimeError(
                "Zebra returned no Ironwood finalState. Use a NU6.3-capable Zebra node "
                "and a post-activation canonical block."
            )
        _validate_hex(final_state, "ironwood.commitments.finalState")
        return {"height": height, "hash": block_hash.lower(), "final_state_hex": final_state.lower()}

    def raw_block_hex(self, block_hash: str) -> str:
        result = self.call("getblock", [block_hash, 0])
        if isinstance(result, str):
            raw_hex = result
        elif isinstance(result, dict):
            raw_hex = result.get("hex", "")
        else:
            raw_hex = ""
        _validate_hex(raw_hex, f"raw block {block_hash}")
        return raw_hex.lower()


def _validate_hex(value: str, label: str) -> None:
    if not isinstance(value, str) or not value or len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", value):
        raise RuntimeError(f"{label} must be non-empty even-length hexadecimal.")


def _atomic_save(path: str | Path, payload: Mapping[str, Any]) -> None:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".tmp", dir=str(destination.parent))
    try:
        try:
            os.chmod(temp_name, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_name, destination)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _load_state(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser()
    with source.open("r", encoding="utf-8") as file:
        state = json.load(file)
    if state.get("schema_version") != STATE_SCHEMA_VERSION or state.get("pool") != "ironwood":
        raise RuntimeError("Unsupported wallet state file. Reinitialize using this version of the scanner.")
    if state.get("network") != "testnet":
        raise RuntimeError("This local wallet state is not a Testnet Ironwood state.")
    _validate_hex(state.get("tree_state_hex", ""), "tree_state_hex")
    state.setdefault("tracked_notes", [])
    return state


def derive_testnet_ironwood_address(
    spending_key_hex: str,
    *,
    address_index: int = 0,
    binary_path: str | None = None,
) -> dict[str, Any]:
    """
    Derive a canonical Testnet Unified Address locally from a raw 32-byte
    Orchard-protocol SpendingKey. This is not a BIP39 phrase or ZIP32 account seed.
    """
    key = spending_key_hex.strip()
    _validate_hex(key, "spending_key_hex")
    if len(key) != 64:
        raise RuntimeError("This initial address tool requires a raw 32-byte Orchard-protocol SpendingKey.")
    if address_index < 0:
        raise RuntimeError("address_index cannot be negative.")
    binary = binary_path or _default_binary_path()
    if not os.path.isfile(binary):
        raise RuntimeError(
            f"DarkBatch Rust engine not found at {binary}; build darkbatch_crypto before address derivation."
        )
    payload = json.dumps({
        "network": "testnet",
        "spending_key_hex": key,
        "address_index": int(address_index),
    }, separators=(",", ":"))
    try:
        completed = subprocess.run(
            [binary, "derive-ironwood-address-stdin"],
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Local Ironwood address derivation failed: {exc}") from exc
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Rust address derivation failed.")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Rust address derivation returned malformed JSON.") from exc
    if result.get("status") != "DERIVED_TESTNET_ADDRESS" or result.get("network") != "testnet":
        raise RuntimeError("Rust address tool returned an unexpected result.")
    _validate_hex(result.get("raw_ironwood_receiver_hex", ""), "raw_ironwood_receiver_hex")
    if len(result["raw_ironwood_receiver_hex"]) != 86:
        raise RuntimeError("Rust address tool returned an invalid 43-byte receiver.")
    if not isinstance(result.get("unified_address"), str) or not result["unified_address"]:
        raise RuntimeError("Rust address tool returned no Unified Address.")
    return result


def _derive_tree_root(tree_state_hex: str, binary_path: str | None = None) -> str:
    """Derive the root through the same official Merkle implementation as the scanner."""
    binary = binary_path or _default_binary_path()
    if not os.path.isfile(binary):
        raise RuntimeError(
            f"DarkBatch Rust engine not found at {binary}; build darkbatch_crypto before wallet sync."
        )
    request = json.dumps({"tree_state_hex": tree_state_hex}, separators=(",", ":"))
    try:
        completed = subprocess.run(
            [binary, "ironwood-tree-root-stdin"],
            input=request,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not derive the official Ironwood tree root: {exc}") from exc
    if completed.returncode != 0:
        raise RuntimeError(
            "Official Ironwood tree root derivation failed: "
            + (completed.stderr.strip() or f"exit status {completed.returncode}")
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Rust root helper returned malformed JSON.") from exc
    root = str(result.get("tree_root_hex", "")).lower()
    if result.get("status") != "TREE_ROOT" or not re.fullmatch(r"[0-9a-f]{64}", root):
        raise RuntimeError("Rust root helper returned an invalid anchor.")
    return root


def initialize_wallet_scan(
    state_path: str | Path,
    *,
    start_height: int | None = None,
    rpc: ZebraRpc | None = None,
    overwrite: bool = False,
    binary_path: str | None = None,
) -> dict[str, Any]:
    rpc = rpc or ZebraRpc()
    if Path(state_path).expanduser().exists() and not overwrite:
        raise RuntimeError(f"State file already exists: {state_path}. Refusing to overwrite it.")
    info = rpc.testnet_info()
    tip = int(info["blocks"])
    height = tip if start_height is None else int(start_height)
    if height < ACTIVATION_HEIGHT or height > tip:
        raise RuntimeError(f"Start height must be between {ACTIVATION_HEIGHT} and current tip {tip}.")
    block_hash = rpc.block_hash(height)
    treestate = rpc.treestate(block_hash)
    if treestate["height"] != height:
        raise RuntimeError("z_gettreestate height does not match the chosen checkpoint.")
    state = {
        "schema_version": STATE_SCHEMA_VERSION,
        "network": "testnet",
        "pool": "ironwood",
        "checkpoint_height": height,
        "checkpoint_hash": block_hash,
        "height": height,
        "block_hash": block_hash,
        "tree_state_hex": treestate["final_state_hex"],
        "tree_root_hex": _derive_tree_root(treestate["final_state_hex"], binary_path),
        "tracked_notes": [],
        "notes": [
            "This checkpoint only enables discovery of wallet notes created in blocks after this height.",
            "Older notes need current Merkle witnesses imported from a trusted Ironwood-capable wallet.",
            "This file contains note seeds and witnesses but never stores the wallet spending key.",
        ],
    }
    _atomic_save(state_path, state)
    return state


def _scan_block_with_rust(
    binary_path: str,
    *,
    request: Mapping[str, Any],
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    if not os.path.isfile(binary_path):
        raise RuntimeError(
            f"DarkBatch Rust engine not found at {binary_path}; build it with "
            "'cargo build --manifest-path darkbatch_crypto/Cargo.toml --release'."
        )
    payload = json.dumps(request, separators=(",", ":"), ensure_ascii=True)
    try:
        completed = subprocess.run(
            [binary_path, "scan-ironwood-block-stdin"],
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Local Ironwood block scanner could not complete: {exc}") from exc
    if completed.returncode != 0:
        reason = completed.stderr.strip() or f"Rust scanner exited with status {completed.returncode}."
        raise RuntimeError(f"Ironwood block scan refused: {reason}")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Rust scanner returned malformed JSON; state was not updated.") from exc
    if not isinstance(result, dict) or result.get("status") != "SCANNED_BLOCK":
        raise RuntimeError("Rust scanner returned an unexpected result; state was not updated.")
    return result


def sync_wallet_scan(
    state_path: str | Path,
    spending_key_hex: str,
    *,
    rpc: ZebraRpc | None = None,
    binary_path: str | None = None,
    max_blocks: int | None = None,
) -> dict[str, Any]:
    state = _load_state(state_path)
    rpc = rpc or ZebraRpc()
    info = rpc.testnet_info()
    tip = int(info["blocks"])
    saved_height = int(state["height"])
    if saved_height > tip:
        raise RuntimeError("Saved wallet scan height is ahead of the node tip. Refusing to guess after a reorg.")
    canonical_saved_hash = rpc.block_hash(saved_height)
    if canonical_saved_hash != str(state["block_hash"]).lower():
        raise RuntimeError(
            "Saved wallet checkpoint is not on the node's current canonical chain. "
            "Do not reuse its witnesses: restore a matching backup or reinitialize and rescan."
        )
    canonical_saved_tree = rpc.treestate(canonical_saved_hash)
    if canonical_saved_tree["final_state_hex"] != str(state["tree_state_hex"]).lower():
        raise RuntimeError(
            "Saved Ironwood tree differs from Zebra at the saved block. Refusing to spend with stale witnesses."
        )
    canonical_root = _derive_tree_root(state["tree_state_hex"], binary_path)
    saved_root = state.get("tree_root_hex")
    if saved_root and str(saved_root).lower() != canonical_root:
        raise RuntimeError("Saved Ironwood anchor disagrees with its serialized tree; refusing stale witnesses.")
    state["tree_root_hex"] = canonical_root

    key = spending_key_hex.strip()
    _validate_hex(key, "spending_key_hex")
    if len(key) != 64:
        raise RuntimeError("spending_key_hex must encode exactly 32 bytes.")
    binary = binary_path or _default_binary_path()
    upper_height = tip if max_blocks is None else min(tip, saved_height + max(0, int(max_blocks)))
    new_notes = 0
    spent_notes = 0
    scanned_blocks = 0

    for height in range(saved_height + 1, upper_height + 1):
        block_hash = rpc.block_hash(height)
        raw_block = rpc.raw_block_hex(block_hash)
        post_tree = rpc.treestate(block_hash)
        prev_hash = rpc.block_hash(height - 1)
        if post_tree["height"] != height:
            raise RuntimeError(f"z_gettreestate returned a different height for block {height}.")

        result = _scan_block_with_rust(
            binary,
            request={
                "network": "testnet",
                "expected_height": height,
                "expected_block_hash": block_hash,
                "expected_prev_block_hash": prev_hash,
                "raw_block_hex": raw_block,
                "expected_final_state_hex": state["tree_state_hex"],
                "tree_state_hex": state["tree_state_hex"],
                "spending_key_hex": key,
                "tracked_notes": state["tracked_notes"],
            },
        )
        if int(result.get("height", -1)) != height or result.get("block_hash") != block_hash:
            raise RuntimeError("Rust scanner block identity does not match the canonical Zebra response.")
        if str(result.get("prev_block_hash", "")).lower() != prev_hash:
            raise RuntimeError("Rust scanner parent identity does not match the canonical Zebra response.")
        # Zebra serializes the canonical CommitmentTree as finalState. Byte equality
        # proves the local scanner appended exactly the same Ironwood commitments.
        if str(result.get("tree_state_hex", "")).lower() != post_tree["final_state_hex"]:
            raise RuntimeError(
                f"Local Ironwood tree diverged from Zebra at height {height}; wallet state was not advanced."
            )

        state["height"] = height
        state["block_hash"] = block_hash
        state["tree_state_hex"] = result["tree_state_hex"].lower()
        state["tree_root_hex"] = str(result["tree_root_hex"]).lower()
        state["tracked_notes"] = result.get("tracked_notes", [])
        _atomic_save(state_path, state)
        new_notes += len(result.get("new_note_ids", []))
        spent_notes += len(result.get("spent_note_ids", []))
        scanned_blocks += 1

    state["last_sync"] = {
        "scanned_blocks": scanned_blocks,
        "new_notes": new_notes,
        "spent_notes": spent_notes,
        "node_tip_height": tip,
        "caught_up": int(state["height"]) == tip,
    }
    _atomic_save(state_path, state)
    return state


def list_wallet_notes(state_path: str | Path) -> list[dict[str, Any]]:
    state = _load_state(state_path)
    return [
        {
            "note_id": note["note_id"],
            "status": note["status"],
            "value_zat": note["value_zat"],
            "received_height": note["received_height"],
            "txid": note["txid"],
            "witness_root_hex": note.get("witness_root_hex"),
            "witness_ready": bool(note.get("witness_state_hex")) if note.get("status") == "UNSPENT" else False,
        }
        for note in state.get("tracked_notes", [])
    ]


def build_transaction_from_notes(
    state_path: str | Path,
    spending_key_hex: str,
    note_ids: Sequence[str],
    outputs: Sequence[Mapping[str, Any]],
    *,
    rpc: ZebraRpc | None = None,
    binary_path: str | None = None,
) -> BuiltIronwoodTransaction:
    """Build a real Testnet send from tracked wallet notes. Does not broadcast."""
    if not note_ids:
        raise RuntimeError("Select at least one tracked note to spend.")
    if not outputs:
        raise RuntimeError("At least one real Ironwood recipient output is required.")
    state = _load_state(state_path)
    rpc = rpc or ZebraRpc()
    info = rpc.testnet_info()
    tip = int(info["blocks"])
    if int(state["height"]) != tip:
        raise RuntimeError(
            f"Wallet state is at {state['height']} but node tip is {tip}. Run wallet sync before building."
        )
    if rpc.block_hash(tip) != state["block_hash"]:
        raise RuntimeError("Saved wallet tip is no longer canonical; refusing to build.")
    live_tree = rpc.treestate(state["block_hash"])
    if live_tree["final_state_hex"] != state["tree_state_hex"]:
        raise RuntimeError("Wallet tree checkpoint differs from Zebra. Refusing to spend.")
    live_root = _derive_tree_root(state["tree_state_hex"], binary_path)
    if state.get("tree_root_hex") and str(state["tree_root_hex"]).lower() != live_root:
        raise RuntimeError("Stored Ironwood anchor differs from the canonical tree state. Refusing to spend.")
    state["tree_root_hex"] = live_root

    by_id = {note["note_id"]: note for note in state.get("tracked_notes", [])}
    selected: list[dict[str, Any]] = []
    for note_id in note_ids:
        note = by_id.get(note_id)
        if note is None:
            raise RuntimeError(f"Unknown note ID: {note_id}")
        if note.get("status") != "UNSPENT" or not note.get("witness_state_hex"):
            raise RuntimeError(f"Note {note_id} is not currently spendable.")
        if len(note.get("witness_auth_path_hex", [])) != 32 or note.get("witness_position") is None:
            raise RuntimeError(f"Note {note_id} has no current 32-node Merkle witness.")
        selected.append(note)

    anchors = {str(note.get("witness_root_hex", "")).lower() for note in selected}
    if len(anchors) != 1 or not next(iter(anchors)):
        raise RuntimeError("Selected notes do not share the same canonical Ironwood anchor.")
    anchor = next(iter(anchors))
    if anchor != live_root:
        raise RuntimeError("Selected note witnesses are not anchored at the current canonical tree root.")
    if live_tree["final_state_hex"] != state["tree_state_hex"]:
        raise RuntimeError("Tree state changed; run sync before rebuilding.")

    key = spending_key_hex.strip()
    _validate_hex(key, "spending_key_hex")
    if len(key) != 64:
        raise RuntimeError("spending_key_hex must encode exactly 32 bytes.")
    request_spends = []
    for note in selected:
        request_spends.append({
            "spending_key_hex": key,
            "note_address_raw_hex": note["raw_address_hex"],
            "value_zat": int(note["value_zat"]),
            "rho_hex": note["rho_hex"],
            "rseed_hex": note["rseed_hex"],
            "witness_position": int(note["witness_position"]),
            "witness_auth_path_hex": note["witness_auth_path_hex"],
        })

    request_outputs = []
    for index, output in enumerate(outputs):
        address_hex = str(output.get("recipient_address_raw_hex", ""))
        _validate_hex(address_hex, f"outputs[{index}].recipient_address_raw_hex")
        if len(address_hex) != 86:
            raise RuntimeError(f"outputs[{index}] recipient must be a raw 43-byte Ironwood address.")
        value = int(output.get("value_zat", 0))
        if value <= 0:
            raise RuntimeError(f"outputs[{index}] value_zat must be positive.")
        memo_hex = str(output.get("memo_hex", ""))
        if memo_hex:
            _validate_hex(memo_hex, f"outputs[{index}].memo_hex")
            if len(memo_hex) > 1024:
                raise RuntimeError(f"outputs[{index}].memo_hex exceeds 512 bytes.")
        request_outputs.append({
            "recipient_address_raw_hex": address_hex.lower(),
            "value_zat": value,
            "memo_hex": memo_hex.lower(),
            "ovk_hex": output.get("ovk_hex"),
        })

    return build_ironwood_transaction(
        {
            "network": "testnet",
            "target_height": tip + 1,
            "ironwood_anchor_hex": anchor,
            "spends": request_spends,
            "outputs": request_outputs,
        },
        binary_path=binary_path,
    )


def broadcast_built_transaction(transaction: BuiltIronwoodTransaction, *, rpc: ZebraRpc | None = None) -> dict[str, Any]:
    """Broadcast a locally built, officially serialized v6 transaction; report pending, never assume mined."""
    rpc = rpc or ZebraRpc()
    adapter = TestnetSettlementAdapter(rpc_url=rpc.url, rpc_user=rpc.username, rpc_password=rpc.password)
    return adapter.broadcast_raw_transaction(transaction.raw_tx_hex, transaction.txid)


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Local Zebra Testnet Ironwood wallet sync/build tools.")
    sub = parser.add_subparsers(dest="command", required=True)

    address = sub.add_parser("address", help="Derive a standard Testnet Unified Address from a raw Orchard-protocol spending key.")
    address.add_argument("--index", type=int, default=0)

    init = sub.add_parser("init", help="Checkpoint the Ironwood tree at a canonical Testnet height.")
    init.add_argument("--state", required=True)
    init.add_argument("--height", type=int, default=None)
    init.add_argument("--overwrite", action="store_true")

    sync = sub.add_parser("sync", help="Scan blocks after a saved checkpoint and discover incoming V3 notes.")
    sync.add_argument("--state", required=True)
    sync.add_argument("--max-blocks", type=int, default=None)

    show = sub.add_parser("notes", help="List notes learned by this local scanner.")
    show.add_argument("--state", required=True)

    build = sub.add_parser("build", help="Build, but do not broadcast, a transaction from selected notes.")
    build.add_argument("--state", required=True)
    build.add_argument("--notes", required=True, help="Comma-separated note IDs from the notes command.")
    build.add_argument("--outputs-json", required=True, help="JSON file: an array of raw recipient address/value/memo objects.")
    build.add_argument("--out", required=True, help="Write built raw transaction receipt here (no spending keys).")

    broadcast = sub.add_parser("broadcast", help="Broadcast a previously built raw transaction using live Zebra RPC.")
    broadcast.add_argument("--tx-file", required=True)

    args = parser.parse_args()
    try:
        if args.command == "address":
            key = getpass.getpass("Raw 32-byte Orchard-protocol SpendingKey hex (hidden; never saved): ").strip()
            result = derive_testnet_ironwood_address(key, address_index=args.index)
            print(json.dumps({
                "status": result["status"],
                "network": result["network"],
                "address_index": result["address_index"],
                "unified_address": result["unified_address"],
                "raw_ironwood_receiver_hex": result["raw_ironwood_receiver_hex"],
                "note": result["note"],
            }, indent=2))
            return 0
        if args.command == "init":
            state = initialize_wallet_scan(args.state, start_height=args.height, overwrite=args.overwrite)
            print(json.dumps({"status": "INITIALIZED", "height": state["height"], "block_hash": state["block_hash"], "state_path": str(Path(args.state).expanduser().resolve())}, indent=2))
            return 0
        if args.command == "sync":
            key = getpass.getpass("Ironwood wallet spending key (hex, hidden; never saved): ").strip()
            state = sync_wallet_scan(args.state, key, max_blocks=args.max_blocks)
            print(json.dumps({"status": "SYNCED", "height": state["height"], "block_hash": state["block_hash"], "last_sync": state.get("last_sync")}, indent=2))
            return 0
        if args.command == "notes":
            print(json.dumps(list_wallet_notes(args.state), indent=2))
            return 0
        if args.command == "build":
            key = getpass.getpass("Ironwood wallet spending key (hex, hidden; never saved): ").strip()
            with open(args.outputs_json, "r", encoding="utf-8") as file:
                outputs = json.load(file)
            if not isinstance(outputs, list):
                raise RuntimeError("--outputs-json must contain a JSON array.")
            selected_ids = [part.strip() for part in args.notes.split(",") if part.strip()]
            transaction = build_transaction_from_notes(args.state, key, selected_ids, outputs)
            receipt = {
                "status": "BUILT_NOT_BROADCAST",
                "txid": transaction.txid,
                "raw_tx_hex": transaction.raw_tx_hex,
                "raw_tx_bytes_len": transaction.raw_tx_bytes_len,
                "target_height": transaction.target_height,
                "consensus_branch_id": f"0x{transaction.consensus_branch_id:08x}",
                "version_group_id": f"0x{transaction.version_group_id:08x}",
                "network": transaction.network,
                "broadcast": False,
            }
            _atomic_save(args.out, receipt)
            print(json.dumps({"status": receipt["status"], "txid": transaction.txid, "raw_tx_bytes_len": transaction.raw_tx_bytes_len, "saved_to": str(Path(args.out).expanduser().resolve())}, indent=2))
            return 0
        if args.command == "broadcast":
            with open(args.tx_file, "r", encoding="utf-8") as file:
                receipt = json.load(file)
            raw_tx_hex = receipt.get("raw_tx_hex", "")
            expected_txid = receipt.get("txid", "")
            if not raw_tx_hex or not expected_txid:
                raise RuntimeError("Transaction file has no raw_tx_hex / txid.")
            rpc = ZebraRpc()
            adapter = TestnetSettlementAdapter(rpc_url=rpc.url, rpc_user=rpc.username, rpc_password=rpc.password)
            result = adapter.broadcast_raw_transaction(raw_tx_hex, expected_txid)
            print(json.dumps(result, indent=2))
            return 0 if result.get("broadcast") else 2
    except Exception as exc:
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli())
