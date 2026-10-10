"""
DarkBatch prototype coordinator API server.
SQLite/WebSocket order handling is not independently privacy-audited; real settlement remains guarded.
"""

import asyncio
from contextlib import asynccontextmanager
import os
import secrets
import time
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from darkbatch.core.repo import (
    list_wallets,
    get_wallet,
    save_intent,
    get_pending_intents,
    mark_intents_settled,
    get_active_epoch_id,
    record_epoch_clear,
    record_epoch_zec_pending,
    record_epoch_zec_confirmed,
    get_epoch_history,
    update_wallet_balance
)
from darkbatch.core.wallet import ShieldedWallet
from darkbatch.core.intent import SwapOrderIntent, OrderDirection, create_intent
from darkbatch.node.simulator import ZcashNodeSimulator
from darkbatch.solver.engine import AutonomousSolverDaemon
from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter, LIVE_SETTLEMENT_IMPLEMENTED

NODE = ZcashNodeSimulator()
TESTNET_ADAPTER = TestnetSettlementAdapter(NODE)
# The API must use the strict adapter. Direct simulator settlement is only used by unit tests.
SOLVER = AutonomousSolverDaemon(NODE, settlement_adapter=TESTNET_ADAPTER)

class IntentSubmitRequest(BaseModel):
    direction: OrderDirection
    zec_amount: float
    limit_price_usd: float
    shielded_address: str

class RawV6SettlementRequest(BaseModel):
    epoch_id: int
    txid: str
    raw_tx_hex: str
    build_report: Dict[str, Any]
    proof_report: Dict[str, Any]

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()
EPOCH_DURATION_SECONDS = 30
epoch_start_time = time.time()

@asynccontextmanager
async def lifespan(app: FastAPI):
    async def epoch_ticker():
        global epoch_start_time
        while True:
            await asyncio.sleep(1)
            elapsed = time.time() - epoch_start_time
            remaining = max(0.0, EPOCH_DURATION_SECONDS - elapsed)
            epoch_id = get_active_epoch_id()
            pending = get_pending_intents()
            await manager.broadcast({
                "type": "TICK",
                "epoch_id": epoch_id,
                "seconds_remaining": round(remaining, 1),
                "sealed_count": len(pending)
            })
            if remaining <= 0.0:
                if pending:
                    # The public coordinator never injects mock wallet keys into settlement.
                    # A real PCZT is prepared by the trusted local settlement agent.
                    res = SOLVER.run_epoch_settlement(epoch_id, pending)
                    if res.get("status") in {"SETTLED_AND_MINED", "CONFIRMED"}:
                        record_epoch_clear(
                            epoch_id=epoch_id,
                            clearing_price_usd=res["clearing_price_usd"],
                            total_cleared_zec=res["cleared_zec"],
                            total_cleared_usd=res["cleared_usd"],
                            tx_id=res["tx_id"],
                            block_hash=res["block_hash"]
                        )
                        mark_intents_settled([i.intent_id for i in pending])
                    await manager.broadcast({
                        "type": "EPOCH_CLEARED",
                        "epoch_id": epoch_id,
                        "result": res
                    })
                epoch_start_time = time.time()

    ticker_task = asyncio.create_task(epoch_ticker())
    yield
    ticker_task.cancel()

app = FastAPI(
    title="DarkBatch Protocol API",
    description="Confidential Intent-Based Batch Auction & RFQ for Shielded Zcash (Ironwood Era)",
    version="3.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws/feed")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/api/v1/health")
def get_health():
    elapsed = time.time() - epoch_start_time
    remaining = max(0.0, EPOCH_DURATION_SECONDS - elapsed)
    epoch_id = get_active_epoch_id()
    pending = get_pending_intents()
    return {
        "status": "ONLINE",
        "network": "DarkBatch FBA coordinator (live settlement guarded)",
        "protocol_version": "ZIP-228 / ZIP-229 v6",
        "current_epoch": epoch_id,
        "seconds_until_clear": round(remaining, 1),
        "sealed_intent_count": len(pending),
        "total_blocks_mined": len(NODE.blocks),
        "ironwood_anchor": NODE.current_anchor()
    }

@app.get("/api/v1/wallets")
def get_all_wallets():
    return {"wallets": list_wallets()}

@app.post("/api/v1/intent")
async def submit_intent(req: IntentSubmitRequest):
    intent = create_intent(
        direction=req.direction,
        zec_amount=req.zec_amount,
        limit_price_usd=req.limit_price_usd,
        shielded_address=req.shielded_address
    )
    epoch_id = get_active_epoch_id()
    save_intent(intent, epoch_id)

    # Public WebSocket feed omits order terms; the complete confidentiality properties of this prototype have not been independently audited.
    await manager.broadcast({
        "type": "NEW_SEALED_INTENT",
        "intent_id": intent.intent_id,
        "commitment": intent.value_commitment[:24] + "...",
        "epoch_id": epoch_id
    })

    return {
        "status": "SEALED_AND_COMMITTED",
        "intent_id": intent.intent_id,
        "epoch": epoch_id,
        "commitment": intent.value_commitment,
        "bsk_share_hex": hex(intent.bsk_share)[:18] + "...",
        "expiry_height": intent.expiry_height
    }

@app.get("/api/v1/epoch/current")
def get_current_epoch():
    """
    CONFIDENTIAL MEMPOOL: Returns ONLY sealed order commitments.
    Prices, amounts, directions, and user addresses are strictly shielded!
    """
    elapsed = time.time() - epoch_start_time
    remaining = max(0.0, EPOCH_DURATION_SECONDS - elapsed)
    epoch_id = get_active_epoch_id()
    pending = get_pending_intents()

    sealed_orders = [
        {
            "id": i.intent_id[:16] + "...",
            "value_commitment": i.value_commitment,
            "status": "SEALED_COMMITMENT",
            "expiry_height": i.expiry_height,
            "timestamp": i.created_at_timestamp
        }
        for i in pending
    ]

    return {
        "epoch_id": epoch_id,
        "seconds_remaining": round(remaining, 1),
        "sealed_orders_count": len(sealed_orders),
        "sealed_orders": sealed_orders,
        "confidentiality_status": "UNAUDITED_PROTOTYPE",
        "privacy_guarantee": False
    }

@app.post("/api/v1/epoch/clear")
async def clear_current_epoch():
    global epoch_start_time
    epoch_id = get_active_epoch_id()
    pending = get_pending_intents()

    if not pending:
        return {"status": "EMPTY", "message": "No pending orders to clear."}

    # Keep matching independent from the demonstration-wallet IVKs. Fills remain in
    # process memory and are accessible only via the token-protected local agent endpoint.
    res = SOLVER.run_epoch_settlement(epoch_id, pending)

    if res.get("status") in {"SETTLED_AND_MINED", "CONFIRMED"}:
        # Only confirmed on-chain settlement may update the durable epoch and order state.
        price = res.get("clearing_price_usd", res.get("proposed_clearing_price_usd"))
        cleared_zec = res.get("cleared_zec", res.get("proposed_volume_zec"))
        cleared_usd = res.get("cleared_usd", res.get("proposed_volume_usd"))
        if price is None or cleared_zec is None or cleared_usd is None or not res.get("tx_id") or not res.get("block_hash"):
            raise HTTPException(status_code=502, detail="Settlement adapter returned CONFIRMED without complete transaction details")
        record_epoch_clear(
            epoch_id=epoch_id,
            clearing_price_usd=price,
            total_cleared_zec=cleared_zec,
            total_cleared_usd=cleared_usd,
            tx_id=res["tx_id"],
            block_hash=res["block_hash"]
        )
        mark_intents_settled([i.intent_id for i in pending])

    # Cool-down timer only. The epoch is not recorded/advanced unless actual confirmation is verified.
    epoch_start_time = time.time()

    await manager.broadcast({
        "type": "EPOCH_SETTLEMENT_RESULT",
        "epoch_id": epoch_id,
        "result": res
    })

    if res.get("status") == "SETTLEMENT_BLOCKED":
        return JSONResponse(status_code=503, content={
            "status": "SETTLEMENT_BLOCKED",
            "cleared_epoch": epoch_id,
            "result": res
        })

    return {
        "status": res.get("status", "SETTLEMENT_PENDING"),
        "cleared_epoch": epoch_id,
        "settled": res.get("status") in {"SETTLED_AND_MINED", "CONFIRMED"},
        "result": res
    }

@app.get("/api/v1/epoch/history")
def get_history():
    return {"history": get_epoch_history()}

@app.get("/api/v1/node/blocks")
def get_node_blocks():
    return {
        "network": "LOCAL_SIMULATION_ONLY",
        "warning": "These blocks are generated by the DarkBatch simulator and are not Zcash Testnet blocks.",
        "blocks": [
        {
            "height": b.height,
            "hash": b.hash,
            "prev_hash": b.prev_hash,
            "timestamp": b.timestamp,
            "anchor_root": b.anchor_root,
            "tx_count": b.tx_count,
            "transactions": b.transactions
        } for b in NODE.blocks
        ]
    }

@app.post("/api/v1/wallet/decrypt-memo")
def decrypt_memo_endpoint(req: dict):
    alias = req.get("alias")
    memo_hex = req.get("memo_hex", "").strip()
    epk_hex = req.get("epk_hex", "").strip()
    wallet = get_wallet(alias)
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")

    try:
        from darkbatch.core.crypto import decrypt_orchard_note, decrypt_512_memo, derive_shared_key
        memo_bytes = bytes.fromhex(memo_hex)

        # 1. Authentic Orchard Note Plaintext decryption (580 bytes encCiphertext)
        if len(memo_bytes) == 580:
            epk_bytes = bytes.fromhex(epk_hex) if epk_hex else None
            if not epk_bytes:
                for b in NODE.blocks:
                    for t in b.transactions:
                        for ag in t.get("action_groups", []):
                            for act in ag.get("actions", []):
                                if act.get("memo_hex") == memo_hex and "epk" in act:
                                    epk_bytes = bytes.fromhex(act["epk"])
                                    break
            if not epk_bytes:
                epk_bytes = bytes(32)

            val, memo_512 = decrypt_orchard_note(memo_bytes, wallet.ivk, epk_bytes)
            memo_text = memo_512.rstrip(b"\x00").decode("utf-8")
            return {
                "status": "SUCCESS",
                "decryption_method": "Zcash Protocol § 5.4.3.4 (Incoming Viewing Key)",
                "value_zat": val,
                "receipt": json.loads(memo_text)
            }

        # 2. Legacy / 512-byte raw memo fallback
        shared_key = derive_shared_key(wallet.ivk)
        plaintext = decrypt_512_memo(memo_bytes, shared_key)
        return {"status": "SUCCESS", "receipt": json.loads(plaintext.decode("utf-8"))}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

@app.post("/api/v1/demo/seed")
async def seed_demo():
    epoch_id = get_active_epoch_id()
    wallets = list_wallets()
    if not wallets:
        return {"status": "NO_WALLETS"}

    w_alice = wallets[0]["unified_address"]
    w_bob = wallets[1]["unified_address"] if len(wallets) > 1 else w_alice
    w_whale = wallets[2]["unified_address"] if len(wallets) > 2 else w_alice
    w_maker = wallets[3]["unified_address"] if len(wallets) > 3 else w_bob

    orders = [
        (OrderDirection.BUY_ZEC, 20.0, 43.60, w_bob),
        (OrderDirection.BUY_ZEC, 35.0, 42.90, w_whale),
        (OrderDirection.BUY_ZEC, 15.0, 41.80, w_alice),
        (OrderDirection.SELL_ZEC, 25.0, 41.50, w_maker),
        (OrderDirection.SELL_ZEC, 20.0, 42.30, w_alice),
        (OrderDirection.SELL_ZEC, 25.0, 44.00, w_whale),
    ]

    for direction, zec, price, addr in orders:
        intent = create_intent(direction, zec, price, addr)
        save_intent(intent, epoch_id)

    await manager.broadcast({"type": "SEEDED", "epoch_id": epoch_id})

    return {
        "status": "SEEDED",
        "orders_added": len(orders),
        "total_zec_volume": sum(o[1] for o in orders)
    }

@app.get("/api/v1/settlement/testnet-status")
def get_testnet_status():
    chain_info = TESTNET_ADAPTER.get_live_chain_info()
    live_rpc = TESTNET_ADAPTER.is_live_rpc_available()
    bundle_builder_is_live_safe = bool(LIVE_SETTLEMENT_IMPLEMENTED and getattr(SOLVER.bundle_builder, "live_broadcast_safe", False))
    return {
        "status": "LIVE_TESTNET_RPC_READY" if live_rpc else "RPC_UNAVAILABLE",
        "network": "Zcash Testnet" if live_rpc else None,
        "protocol_version": "ZIP-229 Transaction v6 (0xD884B698)",
        "consensus_branch_id": "0x37A5165B",
        "validator_implementation": "Zebra RPC" if live_rpc else None,
        "testnet_activation_height": 4134000,
        "live_rpc_connected": live_rpc,
        "rpc_endpoint": TESTNET_ADAPTER.rpc_url if live_rpc else None,
        "fba_live_broadcast_enabled": bool(live_rpc and bundle_builder_is_live_safe),
        "testnet_nu7_activation_height": 4465026,
        "testnet_nu7_consensus_branch_id": "0x77190AD9",
        "local_pczt_agent_required": True,
        "local_raw_v6_submission_available": True,
        "quote_leg_settlement_implemented": False,
        "live_broadcast_block_reason": None if bundle_builder_is_live_safe else (
            "Legacy assembler is not certified for live broadcast; valid participant spend inputs, "
            "cooperative PCZT authorization, and matching Halo 2 proofs are not implemented."
        ),
        "remote_chain_info": chain_info,
        "local_simulation_enabled": TESTNET_ADAPTER.allow_simulation,
        "total_tracked_transactions": len(TESTNET_ADAPTER.broadcast_history)
    }


def _require_local_settlement_token(token: Optional[str]) -> None:
    configured = os.getenv("DARKBATCH_SETTLEMENT_TOKEN", "").strip()
    if not configured:
        raise HTTPException(
            status_code=503,
            detail="The trusted local PCZT agent is not configured; set DARKBATCH_SETTLEMENT_TOKEN on the coordinator.",
        )
    if not token or not secrets.compare_digest(token, configured):
        raise HTTPException(status_code=401, detail="Invalid local settlement token")


@app.get("/api/v1/settlement/local-plan/{epoch_id}")
def get_local_pczt_plan(
    epoch_id: int,
    x_darkbatch_settlement_token: Optional[str] = Header(default=None),
):
    """Private order-level data for the trusted local PCZT process only."""
    _require_local_settlement_token(x_darkbatch_settlement_token)
    plan = SOLVER.local_settlement_plans.get(epoch_id)
    if not plan:
        pending = get_pending_intents(epoch_id)
        if not pending:
            raise HTTPException(status_code=404, detail="No pending intents or in-memory FBA plan for this epoch")
        result = SOLVER.run_epoch_settlement(epoch_id, pending)
        if result.get("status") != "LOCAL_PCZT_REQUIRED":
            raise HTTPException(status_code=409, detail=f"Epoch is not awaiting local PCZT: {result.get('status')}")
        plan = SOLVER.local_settlement_plans.get(epoch_id)
    if not plan:
        raise HTTPException(status_code=503, detail="Local FBA plan was not retained")
    if plan.get("status") != "LOCAL_PCZT_REQUIRED":
        raise HTTPException(status_code=409, detail="Epoch plan is not awaiting local PCZT")
    # Do not log or broadcast this response: it contains participant addresses and trade amounts.
    return plan


@app.post("/api/v1/settlement/raw-v6")
def submit_local_pczt_transaction(
    req: RawV6SettlementRequest,
    x_darkbatch_settlement_token: Optional[str] = Header(default=None),
):
    """Accept only an extracted official V6 transaction from the trusted local agent."""
    _require_local_settlement_token(x_darkbatch_settlement_token)
    plan = SOLVER.local_settlement_plans.get(req.epoch_id)
    if not plan or plan.get("status") != "LOCAL_PCZT_REQUIRED":
        raise HTTPException(status_code=409, detail="No outstanding local PCZT plan exists for this epoch")
    if req.epoch_id != get_active_epoch_id():
        raise HTTPException(status_code=409, detail="Epoch is no longer active for settlement")
    if req.proof_report.get("status") != "PROOF_GENERATED_AND_TRANSACTION_EXTRACTED":
        raise HTTPException(status_code=422, detail="Local proof report does not confirm official PCZT proof and transaction extraction")
    if req.proof_report.get("network") != "Zcash Testnet" or req.proof_report.get("transaction_version") != 6:
        raise HTTPException(status_code=422, detail="Only official V6 transactions built for Zcash Testnet are accepted")
    try:
        target_height = int(req.build_report.get("target_height", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Build report target_height is missing or invalid")
    if target_height < 4_134_000:
        raise HTTPException(status_code=422, detail="PCZT target height predates Testnet NU6.3 activation")
    expected_branch = "0x77190ad9" if target_height >= 4_465_026 else "0x37a5165b"
    reported_branch = str(req.proof_report.get("consensus_branch_id", "")).lower()
    built_branch = str(req.build_report.get("consensus_branch_id", "")).lower()
    if reported_branch != expected_branch or built_branch != expected_branch:
        raise HTTPException(
            status_code=422,
            detail=f"PCZT reports must match Testnet consensus branch {expected_branch} for target height {target_height}",
        )
    if req.proof_report.get("network_confirmed") is not False or req.proof_report.get("broadcast_ready") is not True:
        raise HTTPException(status_code=422, detail="Proof report readiness/confirmation fields are inconsistent")
    reported_txid = str(req.proof_report.get("txid", "")).lower()
    if not reported_txid or reported_txid != req.txid.strip().lower():
        raise HTTPException(status_code=422, detail="Submitted TXID does not match the official transaction-extraction report")

    raw_hex = "".join(req.raw_tx_hex.split()).lower()
    if not raw_hex or len(raw_hex) % 2 or any(ch not in "0123456789abcdef" for ch in raw_hex):
        raise HTTPException(status_code=422, detail="Raw transaction must be non-empty even-length hex")
    raw_len = len(raw_hex) // 2
    if raw_len != req.proof_report.get("raw_transaction_bytes"):
        raise HTTPException(status_code=422, detail="Raw transaction byte length does not match the extraction report")

    buy_fills = plan.get("buy_fills", [])
    sell_fills = plan.get("sell_fills", [])
    total_buys = sum(int(fill.get("filled_zat", 0)) for fill in buy_fills)
    total_sells = sum(int(fill.get("filled_zat", 0)) for fill in sell_fills)
    if total_buys <= 0 or total_buys != total_sells:
        raise HTTPException(status_code=409, detail="FBA buy/sell fill totals are not balanced")
    build = req.build_report
    if build.get("status") != "FBA_PCZT_READY_FOR_LOCAL_PARTICIPANT_SIGNATURES":
        raise HTTPException(status_code=422, detail="Build report is not from the FBA PCZT builder")
    if build.get("network") != "Zcash Testnet" or build.get("broadcast_ready") is not False:
        raise HTTPException(status_code=422, detail="Build report network or staged-build fields are invalid")
    try:
        input_total = int(build["input_total_zat"])
        recipient_total = int(build["recipient_total_zat"])
        fee_zat = int(build["fee_zat"])
        change_zat = int(build["change_zat"])
        seller_fill_total = int(build["seller_fill_total_zat"])
        input_count = int(build["input_count"])
        recipient_count = int(build["recipient_output_count"])
        change_count = int(build["change_output_count"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Build report is missing numeric transaction-balance fields")
    if (
        recipient_total != total_buys
        or seller_fill_total != total_sells
        or recipient_count != len(buy_fills)
        or input_count < len({str(fill.get("shielded_address", "")) for fill in sell_fills})
        or change_count <= 0
        or fee_zat <= 0
        or change_zat <= 0
        or input_total != recipient_total + fee_zat + change_zat
    ):
        raise HTTPException(status_code=422, detail="Build report does not balance against the FBA fill plan")
    # Broadcast only raw transaction bytes plus non-secret target/branch metadata. Never send
    # PCZT data, note openings or keys to Zebra.
    try:
        record = TESTNET_ADAPTER.broadcast_raw_transaction(raw_hex, metadata={
            "target_height": target_height,
            "consensus_branch_id": expected_branch,
        })
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Zebra Testnet rejected or could not accept the transaction: {exc}")
    actual_txid = str(record.get("txid", "")).lower()
    if actual_txid != reported_txid:
        record["association_status"] = "TXID_MISMATCH_NOT_ASSOCIATED_WITH_EPOCH"
        return {
            "status": "BROADCAST_TXID_MISMATCH",
            "transaction": record,
            "epoch_settled": False,
            "quote_leg_status": "NOT_SETTLED",
        }

    metadata = {
        "epoch_id": req.epoch_id,
        "clearing_price_usd": plan["clearing_price_usd"],
        "total_cleared_zec": plan["total_cleared_zec"],
        "total_cleared_usd": plan["total_cleared_usd"],
        "intent_ids": plan["intent_ids"],
        "build_report_input_total_zat": input_total,
        "build_report_recipient_total_zat": recipient_total,
        "build_report_fee_zat": fee_zat,
        "build_report_change_zat": change_zat,
        "build_report_input_count": input_count,
        "build_report_recipient_output_count": recipient_count,
    }
    record.update(metadata)
    record["quote_leg_status"] = "NOT_SETTLED"
    record["epoch_settled"] = False
    record["association_status"] = "ASSOCIATED_WITH_FBA_EPOCH"
    try:
        record_epoch_zec_pending(
            epoch_id=req.epoch_id,
            clearing_price_usd=float(plan["clearing_price_usd"]),
            total_cleared_zec=float(plan["total_cleared_zec"]),
            total_cleared_usd=float(plan["total_cleared_usd"]),
            tx_id=actual_txid,
            intent_ids=list(plan["intent_ids"]),
        )
    except Exception as exc:
        # The network broadcast already happened; keep its TXID tracked and return an explicit
        # reconciliation warning instead of pretending the broadcast never happened.
        record["association_status"] = "BROADCAST_BUT_DB_RECONCILIATION_REQUIRED"
        record["db_error"] = str(exc)
        return {
            "status": "BROADCAST_REQUIRES_RECONCILIATION",
            "transaction": record,
            "epoch_settled": False,
            "quote_leg_status": "NOT_SETTLED",
        }
    SOLVER.local_settlement_plans.pop(req.epoch_id, None)
    return {
        "status": "BROADCAST_PENDING_CONFIRMATION",
        "transaction": record,
        "epoch_settled": False,
        "quote_leg_status": "NOT_SETTLED",
        "message": "ZEC leg broadcast. Await a real Testnet block confirmation; USDC/quote settlement is still not implemented.",
    }


@app.get("/api/v1/settlement/tx/{txid}")
def get_testnet_tx(txid: str):
    tx = TESTNET_ADAPTER.get_transaction(txid)
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction is not tracked by the live settlement adapter")
    if tx.get("status") == "CONFIRMED" and tx.get("epoch_id") is not None and tx.get("block_hash"):
        try:
            record_epoch_zec_confirmed(
                epoch_id=int(tx["epoch_id"]),
                tx_id=str(tx["txid"]),
                block_hash=str(tx["block_hash"]),
            )
            tx["epoch_status"] = "ZEC_CONFIRMED_QUOTE_PENDING"
            tx["quote_leg_status"] = "NOT_SETTLED"
            tx["epoch_settled"] = False
            tx["note"] = "ZEC transaction is confirmed on Testnet. The USDC/quote leg is not integrated and the FBA trade is not fully settled."
        except Exception as exc:
            tx["epoch_finalization_error"] = str(exc)
    return tx

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "..", "web", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()
