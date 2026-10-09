"""
DarkBatch FBA prototype coordinator API.
Provides local demo wallets, off-chain intent matching, and simulation-only state; no on-chain settlement.
"""

import asyncio
from contextlib import asynccontextmanager
import os
import time
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from darkbatch.core.repo import (
    list_wallets,
    get_wallet,
    save_intent,
    get_pending_intents,
    mark_intents_settled,
    mark_intents_simulated,
    get_active_epoch_id,
    record_epoch_clear,
    record_epoch_simulation,
    get_epoch_history,
    update_wallet_balance
)
from darkbatch.core.wallet import ShieldedWallet
from darkbatch.core.intent import SwapOrderIntent, OrderDirection, create_intent
from darkbatch.node.simulator import ZcashNodeSimulator
from darkbatch.solver.engine import AutonomousSolverDaemon
from darkbatch.settlement.testnet_adapter import TestnetSettlementAdapter

NODE = ZcashNodeSimulator()
SOLVER = AutonomousSolverDaemon(NODE)
TESTNET_ADAPTER = TestnetSettlementAdapter(NODE)

class IntentSubmitRequest(BaseModel):
    direction: OrderDirection
    zec_amount: float
    limit_price_usd: float
    shielded_address: str

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
                    # Collect wallet IVKs to encrypt receipts to individual recipient viewing keys
                    all_wallets = {w["unified_address"]: get_wallet(w["alias"]).ivk for w in list_wallets() if get_wallet(w["alias"])}
                    res = SOLVER.run_epoch_settlement(epoch_id, pending, wallets_ivk_map=all_wallets)
                    if res.get("status") == "SETTLED_AND_MINED":
                        record_epoch_clear(
                            epoch_id=epoch_id,
                            clearing_price_usd=res["clearing_price_usd"],
                            total_cleared_zec=res["cleared_zec"],
                            total_cleared_usd=res["cleared_usd"],
                            tx_id=res["tx_id"],
                            block_hash=res["block_hash"]
                        )
                        mark_intents_settled([i.intent_id for i in pending])
                    elif res.get("status") == "SIMULATED_ONLY":
                        record_epoch_simulation(
                            epoch_id=epoch_id,
                            clearing_price_usd=res["clearing_price_usd"],
                            total_cleared_zec=res["cleared_zec"],
                            total_cleared_usd=res["cleared_usd"],
                            simulation_id=res["simulation_id"],
                        )
                        # Exclude these exact orders from being re-matched every 30s;
                        # this status explicitly does not mean filled/settled on-chain.
                        mark_intents_simulated([i.intent_id for i in pending])
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
    description="Ironwood-targeted FBA matching prototype; settlement is simulation-only",
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
        "network": "Ironwood local simulation only (NU6.3+ target)",
        "protocol_version": "ZIP-228 / ZIP-229 v6",
        "current_epoch": epoch_id,
        "seconds_until_clear": round(remaining, 1),
        "sealed_intent_count": len(pending),
        "local_simulated_block_count": len(NODE.blocks),
        "consensus_ready": False,
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

    # Broadcast only the commitment in the public feed; intent terms are still stored by this server.
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
    Returns only commitments and metadata in this response.
    This does not hide order terms from the server, which stores the submitted intent.
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
        "confidentiality_scope": "Plaintext order terms are omitted from this response but remain visible to the server; this is not zero-knowledge privacy."
    }

@app.post("/api/v1/epoch/clear")
async def clear_current_epoch():
    global epoch_start_time
    epoch_id = get_active_epoch_id()
    pending = get_pending_intents()

    if not pending:
        return {"status": "EMPTY", "message": "No pending orders to clear."}

    all_wallets = {w["unified_address"]: get_wallet(w["alias"]).ivk for w in list_wallets() if get_wallet(w["alias"])}
    res = SOLVER.run_epoch_settlement(epoch_id, pending, wallets_ivk_map=all_wallets)

    if res.get("status") == "SETTLED_AND_MINED":
        record_epoch_clear(
            epoch_id=epoch_id,
            clearing_price_usd=res["clearing_price_usd"],
            total_cleared_zec=res["cleared_zec"],
            total_cleared_usd=res["cleared_usd"],
            tx_id=res["tx_id"],
            block_hash=res["block_hash"]
        )
        mark_intents_settled([i.intent_id for i in pending])
    elif res.get("status") == "SIMULATED_ONLY":
        record_epoch_simulation(
            epoch_id=epoch_id,
            clearing_price_usd=res["clearing_price_usd"],
            total_cleared_zec=res["cleared_zec"],
            total_cleared_usd=res["cleared_usd"],
            simulation_id=res["simulation_id"],
        )
        mark_intents_simulated([i.intent_id for i in pending])

    epoch_start_time = time.time()

    await manager.broadcast({
        "type": "EPOCH_CLEARED",
        "epoch_id": epoch_id,
        "result": res
    })

    return {
        "status": res.get("status", "SIMULATED_ONLY"),
        "cleared_epoch": epoch_id,
        "consensus_ready": False,
        "result": res
    }

@app.get("/api/v1/epoch/history")
def get_history():
    return {"history": get_epoch_history()}

@app.get("/api/v1/node/blocks")
def get_node_blocks():
    return {
        "source": "local-simulation",
        "consensus_validated": False,
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
    """Decode a local demo receipt only; the simulated wallet is not an Ironwood wallet."""
    alias = req.get("alias")
    memo_hex = req.get("memo_hex", "").strip()
    wallet = get_wallet(alias)
    if not wallet:
        raise HTTPException(status_code=404, detail="Demo wallet not found")
    try:
        memo_bytes = bytes.fromhex(memo_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="memo_hex must be valid hexadecimal")
    if len(memo_bytes) == 580:
        raise HTTPException(status_code=501, detail="Ironwood note decryption is not implemented in the demo wallet.")
    if len(memo_bytes) != 512:
        raise HTTPException(status_code=400, detail="Expected a 512-byte local demo receipt; this is not an Ironwood ciphertext.")
    try:
        from darkbatch.core.crypto import decrypt_512_memo, derive_shared_key
        plaintext = decrypt_512_memo(memo_bytes, derive_shared_key(wallet.ivk))
        return {"status": "SUCCESS", "mode": "LOCAL_DEMO_ONLY", "note": "Not Zcash Ironwood note decryption.", "receipt": json.loads(plaintext.decode("utf-8"))}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Local demo receipt decryption failed: {exc}")

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
    live_rpc = TESTNET_ADAPTER.is_live_rpc_available()
    result = {
        "status": "LIVE_TESTNET_RPC_AVAILABLE" if live_rpc else "LOCAL_SIMULATION_ONLY",
        "network": "Zcash Testnet (Ironwood target; remote node not independently identity-verified)" if live_rpc else "No live Zcash testnet connection",
        "protocol_version": "ZIP-229 Transaction v6 (Ironwood component)",
        "consensus_branch_id": "selected by official builder for target height; builder not wired to coordinator",
        "validator_implementation": "Remote node (identity/version not independently verified)" if live_rpc else "None — local simulator is not a consensus validator",
        "testnet_activation_height_reference": 4134000,
        "live_rpc_connected": live_rpc,
        "rpc_endpoint": TESTNET_ADAPTER.rpc_url if live_rpc else None,
        "settlement_builder_ready": False,
        "simulated_anchor": NODE.current_anchor(),
        "simulated_height": NODE.height,
        "live_testnet_broadcast_records": len(TESTNET_ADAPTER.broadcast_history),
    }
    if live_rpc:
        try:
            info = TESTNET_ADAPTER.get_testnet_info()
            result["live_node_height"] = info.get("blocks")
            result["live_chain"] = info.get("chain")
        except Exception as exc:
            result["live_rpc_connected"] = False
            result["status"] = "LOCAL_SIMULATION_ONLY"
            result["validator_implementation"] = "Unverified"
            result["rpc_error"] = str(exc)
    return result


@app.get("/api/v1/settlement/tx/{txid}")
def get_testnet_tx(txid: str):
    tx = TESTNET_ADAPTER.get_transaction(txid)
    if not tx:
        raise HTTPException(status_code=404, detail="No live-node broadcast record exists; local simulation IDs are not transaction IDs.")
    return tx

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "..", "web", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()
