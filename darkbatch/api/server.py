"""
DarkBatch prototype coordinator API server.
SQLite/WebSocket order handling is not independently privacy-audited; real settlement remains guarded.
"""

import asyncio
from contextlib import asynccontextmanager
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import os
import re
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
    record_epoch_quote_settled,
    get_epoch_history,
    get_epoch_by_txid,
    get_epoch_by_id,
    update_wallet_balance
)
from darkbatch.core.wallet import ShieldedWallet
from darkbatch.core.intent import SwapOrderIntent, OrderDirection, create_intent
from darkbatch.node.simulator import ZcashNodeSimulator
from darkbatch.solver.engine import AutonomousSolverDaemon
from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter, LIVE_SETTLEMENT_IMPLEMENTED
from darkbatch.settlement.quote_escrow import (
    QuoteEscrowError,
    quote_plan_hash,
    quote_escrow_data_hash,
    _abi_word_uint,
    _keccak256_hex,
    verify_funded_quote_batch,
    verify_released_quote_batch_by_hash,
)

NODE = ZcashNodeSimulator()
TESTNET_ADAPTER = TestnetSettlementAdapter(NODE)
# The API must use the strict adapter. Direct simulator settlement is only used by unit tests.
SOLVER = AutonomousSolverDaemon(NODE, settlement_adapter=TESTNET_ADAPTER)

class IntentSubmitRequest(BaseModel):
    direction: OrderDirection
    zec_amount: float
    limit_price_usd: float
    shielded_address: str
    # Required to complete a real USDC quote leg; optional for matching-only demos.
    quote_address: Optional[str] = None

class RawV6SettlementRequest(BaseModel):
    epoch_id: int
    quote_batch_id: str
    txid: str
    raw_tx_hex: str
    build_report: Dict[str, Any]
    proof_report: Dict[str, Any]


class QuoteFinalizeRequest(BaseModel):
    epoch_id: int
    zec_txid: str
    quote_batch_id: str
    quote_release_txid: str

class QuotePreflightRequest(BaseModel):
    epoch_id: int
    quote_batch_id: str


class QuoteRefundPreflightRequest(BaseModel):
    epoch_id: int
    quote_batch_id: str

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
    quote_address = (req.quote_address or "").strip()
    if quote_address and not re.fullmatch(r"0x[0-9a-fA-F]{40}", quote_address):
        raise HTTPException(status_code=422, detail="quote_address must be a valid 20-byte EVM address (0x + 40 hex characters)")
    intent = create_intent(
        direction=req.direction,
        zec_amount=req.zec_amount,
        limit_price_usd=req.limit_price_usd,
        shielded_address=req.shielded_address,
        quote_address=quote_address or None,
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
    try:
        tip_height = int(chain_info.get("blocks", -1)) if isinstance(chain_info, dict) else -1
    except (TypeError, ValueError):
        tip_height = -1
    branch_id = (
        "0x77190ad9" if tip_height >= 4_465_026
        else "0x37a5165b" if tip_height >= 4_134_000
        else None
    )
    return {
        "status": "LIVE_TESTNET_RPC_READY" if live_rpc else "RPC_UNAVAILABLE",
        "network": "Zcash Testnet" if live_rpc else None,
        "protocol_version": "ZIP-229 Transaction v6 (0xD884B698)",
        "consensus_branch_id": branch_id,
        "current_testnet_tip_height": tip_height if tip_height >= 0 else None,
        "validator_implementation": "Zebra RPC" if live_rpc else None,
        "testnet_activation_height": 4134000,
        "live_rpc_connected": live_rpc,
        "rpc_endpoint": TESTNET_ADAPTER.rpc_url if live_rpc else None,
        "fba_live_broadcast_enabled": bool(live_rpc and bundle_builder_is_live_safe),
        "testnet_nu7_activation_height": 4465026,
        "testnet_nu7_consensus_branch_id": "0x77190ad9",
        "local_ironwood_wallet_scanner_available": True,
        "local_spendable_note_selection_available": True,
        "local_pczt_agent_required": True,
        "local_pczt_cli_available": True,
        "participant_pczt_redaction_available": True,
        "local_raw_v6_submission_available": True,
        "automatic_spendable_note_selection_available": False,
        "automatic_fba_to_pczt_handoff_available": False,
        "quote_escrow_verification_supported": True,
        "quote_escrow_configured": all(os.getenv(name, "").strip() for name in (
            "DARKBATCH_QUOTE_RPC_URL", "DARKBATCH_QUOTE_CHAIN_ID",
            "DARKBATCH_QUOTE_DEPLOYMENT_BLOCK",
            "DARKBATCH_USDC_TOKEN_ADDRESS", "DARKBATCH_USDC_ESCROW_ADDRESS",
        )),
        "local_opt_in_quote_leg_settlement_available": True,
        "automatic_quote_leg_settlement_available": False,
        "live_broadcast_block_reason": (
            "The legacy FBA assembler is intentionally blocked from live broadcast. The trusted local workflow "
            "can scan real Ironwood notes, select spendable notes, build/sign/prove/extract an official PCZT, "
            "broadcast the extracted V6 transaction, and optionally release USDC after Zebra confirmation. "
            "These local steps are not invoked automatically by the API; a synced wallet, current witnesses, "
            "a funded matching escrow batch, and explicit operator action are required."
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
    # Quote addresses are part of each order signature. Hash only the canonical, non-secret quote
    # plan. If a participant has no EVM address, the plan may be previewed but cannot broadcast.
    response = dict(plan)
    try:
        response["quote_plan_hash"] = quote_plan_hash(plan)
        response["quote_escrow_ready"] = True
        response["quote_escrow_reason"] = None
    except QuoteEscrowError as exc:
        response["quote_plan_hash"] = None
        response["quote_escrow_ready"] = False
        response["quote_escrow_reason"] = str(exc)
    # Do not log or broadcast this response: it contains participant addresses and trade amounts.
    return response


@app.post("/api/v1/settlement/quote-preflight")
def preflight_quote_batch(
    req: QuotePreflightRequest,
    x_darkbatch_settlement_token: Optional[str] = Header(default=None),
):
    """Verify the exact USDC escrow batch before spending time generating the Ironwood proof."""
    _require_local_settlement_token(x_darkbatch_settlement_token)
    if req.epoch_id != get_active_epoch_id():
        raise HTTPException(status_code=409, detail="Epoch is no longer active for settlement")
    plan = SOLVER.local_settlement_plans.get(req.epoch_id)
    if not plan or plan.get("status") != "LOCAL_PCZT_REQUIRED":
        raise HTTPException(status_code=409, detail="No pending local PCZT plan exists for this epoch")
    try:
        quote_lock = verify_funded_quote_batch(req.quote_batch_id, plan)
    except QuoteEscrowError as exc:
        raise HTTPException(status_code=409, detail=f"USDC escrow preflight failed: {exc}")
    return {
        "status": "USDC_LOCKED",
        "epoch_id": req.epoch_id,
        "quote_batch_id": req.quote_batch_id,
        "quote_plan_hash": quote_plan_hash(plan),
        "quote_escrow_data_hash": quote_lock["escrow_data_hash"],
        "quote_total_micro": int(plan["quote_total_micro"]),
        "chain_id": int(quote_lock["chain_id"]),
        "deadline": int(quote_lock["deadline"]),
        "funding_event_block": int(quote_lock["funding_event_block"]),
        "funding_event_confirmations": int(quote_lock["funding_event_confirmations"]),
        "minimum_evm_confirmations": int(quote_lock["minimum_evm_confirmations"]),
        "note": "Read-only check only. This route does not send or release USDC."
    }


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
        buyer_output_total = int(build["buyer_output_total_zat"])
        recipient_total = int(build["recipient_total_zat"])
        solver_fee_output_zat = int(build["solver_fee_output_zat"])
        solver_fee_output_address_raw_hex = str(build["solver_fee_output_address_raw_hex"]).strip().lower()
        fee_zat = int(build["fee_zat"])
        change_zat = int(build["change_zat"])
        seller_fill_total = int(build["seller_fill_total_zat"])
        input_count = int(build["input_count"])
        recipient_count = int(build["recipient_output_count"])
        change_count = int(build["change_output_count"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Build report is missing numeric transaction-balance fields")
    try:
        planned_solver_fee = Decimal(str(plan.get("solver_fee_zec", 0)))
        if not planned_solver_fee.is_finite() or planned_solver_fee < 0:
            raise ValueError("non-finite or negative solver fee")
        expected_solver_fee_zat = int(
            (planned_solver_fee * Decimal(100_000_000)).quantize(
                Decimal("1"), rounding=ROUND_HALF_UP
            )
        )
    except (InvalidOperation, ValueError, TypeError):
        raise HTTPException(status_code=409, detail="FBA plan has an invalid ZEC solver fee")

    configured_fee_receiver = os.getenv("DARKBATCH_SOLVER_FEE_RECEIVER_RAW_HEX", "").strip().lower()
    if expected_solver_fee_zat > 0:
        if len(configured_fee_receiver) != 86 or any(ch not in "0123456789abcdef" for ch in configured_fee_receiver):
            raise HTTPException(
                status_code=503,
                detail="DARKBATCH_SOLVER_FEE_RECEIVER_RAW_HEX must be configured to the exact 43-byte fee receiver before non-zero-fee FBA settlement",
            )
        if solver_fee_output_address_raw_hex != configured_fee_receiver:
            raise HTTPException(status_code=422, detail="PCZT solver-fee output address does not match the configured fee receiver")
    elif solver_fee_output_address_raw_hex:
        raise HTTPException(status_code=422, detail="zero-fee FBA transaction unexpectedly reports a solver-fee receiver")

    if (
        solver_fee_output_zat != expected_solver_fee_zat
        or buyer_output_total != total_buys
        or recipient_total != total_buys + expected_solver_fee_zat
        or seller_fill_total != total_sells + expected_solver_fee_zat
        or seller_fill_total != recipient_total
        or recipient_count != len(buy_fills) + (1 if expected_solver_fee_zat > 0 else 0)
        or input_count < change_count
        or change_count <= 0
        or fee_zat <= 0
        or change_zat <= 0
        or input_total != recipient_total + fee_zat + change_zat
    ):
        raise HTTPException(status_code=422, detail="Build report does not balance against buyer fills, solver fee, seller debits and network fee")
    # USDC must be fully escrowed before we submit any ZEC transaction. If the quote leg is
    # unavailable, incorrectly funded, or belongs to a different fill plan, nothing is broadcast.
    try:
        quote_lock = verify_funded_quote_batch(req.quote_batch_id, plan)
    except QuoteEscrowError as exc:
        raise HTTPException(status_code=409, detail=f"USDC escrow verification failed; ZEC was not broadcast: {exc}")

    # Broadcast only raw transaction bytes plus non-secret target/branch metadata. Never send
    # PCZT data, note openings or keys to Zebra.
    try:
        record = TESTNET_ADAPTER.broadcast_raw_transaction(raw_hex, metadata={
            "target_height": target_height,
            "consensus_branch_id": expected_branch,
            "quote_batch_id": req.quote_batch_id,
            "quote_plan_hash": quote_plan_hash(plan),
            "quote_escrow_data_hash": quote_lock["escrow_data_hash"],
            "quote_total_micro": int(plan["quote_total_micro"]),
            "quote_chain_id": int(quote_lock["chain_id"]),
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
        "quote_batch_id": req.quote_batch_id,
        "quote_plan_hash": quote_plan_hash(plan),
        "quote_escrow_data_hash": quote_lock["escrow_data_hash"],
        "quote_total_micro": int(plan["quote_total_micro"]),
        "quote_chain_id": int(quote_lock["chain_id"]),
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
            quote_batch_id=req.quote_batch_id,
            quote_plan_hash=quote_plan_hash(plan),
            quote_total_micro=int(plan["quote_total_micro"]),
            quote_escrow_data_hash=quote_lock["escrow_data_hash"],
            quote_chain_id=int(quote_lock["chain_id"]),
            target_height=target_height,
            consensus_branch_id=expected_branch,
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
        "message": "ZEC leg broadcast. Await a real Testnet block confirmation; the USDC escrow is checked, but this API does not submit the EVM release transaction.",
    }




@app.post("/api/v1/settlement/refund-preflight")
def preflight_expired_quote_refund(
    req: QuoteRefundPreflightRequest,
    x_darkbatch_settlement_token: Optional[str] = Header(default=None),
):
    """Read-only gate for oracle-only refund of an expired batch with no associated ZEC TX."""
    _require_local_settlement_token(x_darkbatch_settlement_token)
    if req.epoch_id != get_active_epoch_id():
        raise HTTPException(status_code=409, detail="Only the currently active epoch can be considered for refund")
    epoch_record = get_epoch_by_id(req.epoch_id)
    if epoch_record:
        if str(epoch_record.get("status", "")).upper() != "ACTIVE" or str(epoch_record.get("tx_id") or "").strip():
            raise HTTPException(status_code=409, detail="Epoch already has a settlement lifecycle or tracked ZEC TX; refund is refused")
    for tracked in TESTNET_ADAPTER.broadcast_history.values():
        try:
            tracked_epoch = int(tracked.get("epoch_id", -1))
        except (TypeError, ValueError):
            continue
        if tracked_epoch == req.epoch_id:
            raise HTTPException(status_code=409, detail="Settlement adapter has a tracked ZEC transaction for this epoch; refund is refused")

    plan = SOLVER.local_settlement_plans.get(req.epoch_id)
    if not plan:
        pending = get_pending_intents(req.epoch_id)
        if not pending:
            raise HTTPException(status_code=404, detail="Cannot reconstruct the active epoch's FBA plan for refund preflight")
        result = SOLVER.run_epoch_settlement(req.epoch_id, pending)
        if result.get("status") != "LOCAL_PCZT_REQUIRED":
            raise HTTPException(status_code=409, detail="Epoch is not awaiting local PCZT and cannot be refunded via this path")
        plan = SOLVER.local_settlement_plans.get(req.epoch_id)
    if not plan or plan.get("status") != "LOCAL_PCZT_REQUIRED":
        raise HTTPException(status_code=409, detail="No refundable local FBA plan exists for this epoch")
    try:
        plan_hash = quote_plan_hash(plan)
        payout_hash = quote_escrow_data_hash(plan)
        # Must match register-usdc-batch.mjs: keccak256(abi.encode(uint256 epochId, bytes32 planHash)).
        expected_batch = "0x" + _keccak256_hex(_abi_word_uint(req.epoch_id) + bytes.fromhex(plan_hash))
        requested_batch = "0x" + str(req.quote_batch_id).strip().lower().removeprefix("0x")
        if len(requested_batch) != 66 or not re.fullmatch(r"0x[0-9a-f]{64}", requested_batch):
            raise QuoteEscrowError("quote_batch_id must be 32-byte hexadecimal text")
        if requested_batch != expected_batch:
            raise HTTPException(status_code=409, detail="Requested escrow batch ID does not match this epoch and signed FBA plan")
    except QuoteEscrowError as exc:
        raise HTTPException(status_code=409, detail=f"FBA plan is not refund-preflight eligible: {exc}")
    return {
        "status": "REFUND_PREFLIGHT_PASSED",
        "epoch_id": req.epoch_id,
        "quote_batch_id": expected_batch,
        "quote_plan_hash": plan_hash,
        "quote_escrow_data_hash": payout_hash,
        "epoch_status": "ACTIVE",
        "epoch_has_tracked_zec_tx": False,
        "operator_no_broadcast_attestation_required": True,
        "warning": "This coordinator cannot prove global ZEC non-inclusion. The configured oracle/operator must verify there is no broadcast or unresolved ZEC transaction before authorizing refund.",
    }


@app.post("/api/v1/settlement/quote-finalize")
def finalize_quote_leg(
    req: QuoteFinalizeRequest,
    x_darkbatch_settlement_token: Optional[str] = Header(default=None),
):
    """Finalize FILLED status only after confirmed ZEC and successful on-chain USDC release."""
    _require_local_settlement_token(x_darkbatch_settlement_token)
    try:
        minimum_confirmations = max(2, int(os.getenv("DARKBATCH_MINIMUM_FINALIZATION_CONFIRMATIONS", "2")))
    except ValueError:
        raise HTTPException(status_code=503, detail="DARKBATCH_MINIMUM_FINALIZATION_CONFIRMATIONS must be an integer")
    zec_txid = req.zec_txid.strip().lower()
    record = TESTNET_ADAPTER.get_transaction(zec_txid)
    if not record:
        raise HTTPException(status_code=404, detail="ZEC transaction is not tracked by the settlement adapter")
    if record.get("status") != "CONFIRMED" or int(record.get("confirmations", 0)) < minimum_confirmations:
        raise HTTPException(
            status_code=409,
            detail=f"ZEC leg does not meet the required {minimum_confirmations} real Testnet confirmations",
        )
    if int(record.get("epoch_id", -1)) != req.epoch_id:
        raise HTTPException(status_code=409, detail="ZEC transaction does not belong to the requested FBA epoch")
    if str(record.get("quote_batch_id", "")).lower() != req.quote_batch_id.strip().lower():
        raise HTTPException(status_code=409, detail="USDC batch ID does not match the funded ZEC settlement")
    plan_hash = str(record.get("quote_plan_hash", "")).lower()
    quote_total = int(record.get("quote_total_micro", 0))
    if not plan_hash or quote_total <= 0:
        raise HTTPException(status_code=409, detail="ZEC settlement record is missing its quote commitment")
    try:
        released = verify_released_quote_batch_by_hash(
            req.quote_batch_id,
            plan_hash,
            quote_total,
            req.quote_release_txid,
            str(record.get("quote_escrow_data_hash", "")),
            zec_txid,
            str(record.get("block_hash", "")),
        )
    except QuoteEscrowError as exc:
        raise HTTPException(status_code=409, detail=f"USDC payout is not verified; epoch remains pending: {exc}")
    try:
        record_epoch_quote_settled(
            epoch_id=req.epoch_id,
            zec_tx_id=zec_txid,
            zec_block_hash=str(record["block_hash"]),
            quote_batch_id=req.quote_batch_id,
            quote_plan_hash=plan_hash,
            quote_total_micro=quote_total,
            quote_tx_id=str(released["release_txid"]),
        )
    except Exception as exc:
        raise HTTPException(status_code=409, detail=f"Quote release verified but epoch database reconciliation failed: {exc}")
    record["quote_leg_status"] = "SETTLED"
    record["quote_txid"] = released["release_txid"]
    record["epoch_settled"] = True
    record["epoch_status"] = "CLEARED"
    record["quote_escrow_status"] = "USDC_RELEASED"
    return {
        "status": "CLEARED",
        "epoch_id": req.epoch_id,
        "zec_txid": zec_txid,
        "quote_txid": released["release_txid"],
        "quote_total_micro": quote_total,
        "quote_asset": "USDC",
        "epoch_settled": True,
    }


@app.get("/api/v1/settlement/tx/{txid}")
def get_testnet_tx(txid: str):
    normalized_txid = txid.strip().lower()
    tx = TESTNET_ADAPTER.get_transaction(normalized_txid)
    if not tx:
        persisted = get_epoch_by_txid(normalized_txid)
        if not persisted:
            raise HTTPException(status_code=404, detail="Transaction is not tracked by the adapter or settlement database")
        persisted_status = str(persisted.get("status") or "")
        if persisted_status not in {"ZEC_LEG_PENDING", "ZEC_CONFIRMED_QUOTE_PENDING", "CLEARED"}:
            raise HTTPException(status_code=409, detail=f"Persisted epoch is not recoverable from settlement state: {persisted_status}")
        restored_metadata = {
            "epoch_id": int(persisted["epoch_id"]),
            "clearing_price_usd": persisted.get("clearing_price_usd"),
            "total_cleared_zec": persisted.get("total_cleared_zec"),
            "total_cleared_usd": persisted.get("total_cleared_usd"),
            "intent_ids": persisted.get("intent_ids", []),
            "quote_batch_id": persisted.get("quote_batch_id"),
            "quote_plan_hash": persisted.get("quote_plan_hash"),
            "quote_escrow_data_hash": persisted.get("quote_escrow_data_hash"),
            "quote_total_micro": persisted.get("quote_total_micro"),
            "quote_chain_id": persisted.get("quote_chain_id"),
            "target_height": persisted.get("target_height"),
            "consensus_branch_id": persisted.get("consensus_branch_id"),
        }
        tx = TESTNET_ADAPTER.track_existing_raw_transaction(normalized_txid, restored_metadata)
        if persisted_status == "CLEARED":
            tx["epoch_settled"] = True
            tx["quote_leg_status"] = "SETTLED"
            tx["quote_txid"] = persisted.get("quote_tx_id")
        tx = TESTNET_ADAPTER.get_transaction(normalized_txid)
        if not tx:
            raise HTTPException(status_code=502, detail="Persisted transaction could not be refreshed through Zebra RPC")
    if tx.get("status") == "CONFIRMED" and tx.get("epoch_id") is not None and tx.get("block_hash"):
        try:
            persisted_epoch = get_epoch_by_txid(str(tx["txid"]))
            if persisted_epoch and persisted_epoch.get("status") == "CLEARED":
                tx["epoch_status"] = "CLEARED"
                tx["quote_leg_status"] = "SETTLED"
                tx["epoch_settled"] = True
                tx["quote_txid"] = persisted_epoch.get("quote_tx_id")
                return tx
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
