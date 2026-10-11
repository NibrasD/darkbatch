from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_operator_scripts_match_the_canonical_escrow_contract_abi():
    contract = _read("contracts/src/DarkBatchQuoteEscrow.sol")
    register = _read("scripts/register-usdc-batch.mjs")
    deposit = _read("scripts/deposit-usdc-batch.mjs")
    release = _read("scripts/confirm-zec-and-release-usdc.mjs")

    assert "function markZecConfirmed(bytes32 batchId, bytes32 zecTxid, bytes32 zecBlockHash)" in contract
    assert "function buyerAt(bytes32 batchId, uint256 index)" in contract
    assert "function getBatchStatus(bytes32 batchId)" in contract
    assert "bytes32 escrowDataHash" in contract

    assert "uint256 deadline)" in register
    assert "uint64 deadline)" not in register
    assert "escrowDataHash" in register
    assert "buyerAt(bytes32,uint256)" in deposit
    assert "buyerDue(bytes32,address)" not in deposit
    assert "buyerPaid(bytes32,address)" not in deposit
    assert "function fundBuyer(bytes32,uint256)" in deposit
    assert "function deposit(bytes32)" not in deposit
    assert "escrow.fundBuyer(batchId, foundBuyerIndex)" in deposit

    assert '"function markZecConfirmed(bytes32 batchId,bytes32 zecTxid,bytes32 zecBlockHash)"' in release
    assert "confirmZecSettlement" not in release
    assert "function BatchReleased" not in release  # event is declared in the ABI, not a callable method
    assert "event BatchReleased(bytes32 indexed batchId,bytes32 indexed zecTxid)" in release
    assert "minimumZecConfirmations < 2" in release
    assert "minimumEvmConfirmations < 2" in release
    assert "signPersistThenBroadcast" in release
    assert "DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY" in release
    assert "DARKBATCH_SETTLEMENT_ORACLE_PRIVATE_KEY" not in release


def test_escrow_refund_transition_is_oracle_gated_and_expiry_tooling_is_available():
    contract = _read("contracts/src/DarkBatchQuoteEscrow.sol")
    docs = _read("contracts/README.md")
    scripts = _read("scripts/refund-expired-usdc-batch.mjs")
    claims = _read("scripts/claim-usdc-refund.mjs")
    package_json = _read("scripts/package.json")

    assert "function markRefundable(bytes32 batchId) external onlyOracle" in contract
    assert "escrow:refund:attest" in docs
    assert "escrow:refund:claim" in docs
    assert "markRefundable" in scripts
    assert "DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY" in scripts
    assert "DARKBATCH_USDC_REFUND_GRACE_SECONDS" in scripts
    assert "--confirm-no-zec-broadcast" in scripts
    assert "DARKBATCH_QUOTE_DEPLOYMENT_BLOCK" in scripts
    assert "BatchMarkedRefundable" in scripts
    assert "USDC_REFUNDS_COMPLETE" in scripts
    assert "REFUNDED_NO_DEPOSITS" not in scripts
    assert "refundBuyer(bytes32 batchId,uint256 buyerIndex)" in claims
    assert "DARKBATCH_QUOTE_DEPLOYMENT_BLOCK" in claims
    assert "BatchMarkedRefundable" in claims
    assert "USDC_REFUND_CONFIRMED" in claims
    assert "escrow:refund:attest" in package_json
    assert "escrow:refund:claim" in package_json
