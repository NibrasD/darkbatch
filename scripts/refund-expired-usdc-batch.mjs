import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, JsonRpcProvider, Wallet, keccak256 } from "ethers";

const required = [
  "DARKBATCH_QUOTE_RPC_URL",
  "DARKBATCH_QUOTE_CHAIN_ID",
  "DARKBATCH_QUOTE_DEPLOYMENT_BLOCK",
  "DARKBATCH_USDC_ESCROW_ADDRESS",
  "DARKBATCH_USDC_TOKEN_ADDRESS",
  "DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY",
  "DARKBATCH_COORDINATOR_API_BASE",
  "DARKBATCH_SETTLEMENT_TOKEN",
  "DARKBATCH_USDC_BATCH_ID",
  "DARKBATCH_EPOCH_ID"
];
for (const key of required) {
  if (!process.env[key]) throw new Error("Missing environment variable " + key);
}
if (!process.argv.includes("--confirm-no-zec-broadcast")) {
  throw new Error("Refusing refund: rerun with --confirm-no-zec-broadcast only after verifying that no ZEC transaction was broadcast or remains unresolved for this epoch.");
}

function bytes32(value, label) {
  const normalized = String(value || "").trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(label + " must be exactly 32-byte hexadecimal text");
  }
  return "0x" + normalized;
}
function address(value, label) {
  const normalized = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(normalized)) throw new Error(label + " must be a valid EVM address");
  return normalized;
}
function saveJsonSecure(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  if (process.platform !== "win32") {
    try { fs.chmodSync(path.dirname(filePath), 0o700); } catch {}
  }
  const temporary = filePath + ".tmp";
  fs.writeFileSync(temporary, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(temporary, filePath);
  if (process.platform !== "win32") {
    try { fs.chmodSync(filePath, 0o600); } catch {}
  }
}

const batchId = bytes32(process.env.DARKBATCH_USDC_BATCH_ID, "USDC batch ID");
const epochId = Number(process.env.DARKBATCH_EPOCH_ID);
if (!Number.isSafeInteger(epochId) || epochId < 0) throw new Error("DARKBATCH_EPOCH_ID must be a non-negative integer");
const chainId = Number(process.env.DARKBATCH_QUOTE_CHAIN_ID);
if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error("DARKBATCH_QUOTE_CHAIN_ID must be a positive integer");
const graceSeconds = Number(process.env.DARKBATCH_USDC_REFUND_GRACE_SECONDS || "86400");
if (!Number.isSafeInteger(graceSeconds) || graceSeconds < 86400) {
  throw new Error("DARKBATCH_USDC_REFUND_GRACE_SECONDS must be an integer of at least 86400 seconds");
}
const minimumEvmConfirmations = Number(process.env.DARKBATCH_QUOTE_MIN_CONFIRMATIONS || "2");
if (!Number.isSafeInteger(minimumEvmConfirmations) || minimumEvmConfirmations < 2) {
  throw new Error("DARKBATCH_QUOTE_MIN_CONFIRMATIONS must be an integer >= 2");
}

const provider = new JsonRpcProvider(process.env.DARKBATCH_QUOTE_RPC_URL);
const network = await provider.getNetwork();
if (Number(network.chainId) !== chainId) throw new Error("EVM RPC chain ID mismatch");

const signer = new Wallet(process.env.DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY, provider);
const escrowAddress = address(process.env.DARKBATCH_USDC_ESCROW_ADDRESS, "USDC escrow address");
const tokenAddress = address(process.env.DARKBATCH_USDC_TOKEN_ADDRESS, "USDC token address");
const apiBase = process.env.DARKBATCH_COORDINATOR_API_BASE.replace(/\/+$/, "");
const apiUrl = new URL(apiBase);
if (apiUrl.protocol !== "https:" && !["localhost", "127.0.0.1", "::1"].includes(apiUrl.hostname)) {
  throw new Error("Remote coordinator APIs must use HTTPS");
}

async function coordinatorRefundPreflight() {
  const response = await fetch(apiBase + "/api/v1/settlement/refund-preflight", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-DarkBatch-Settlement-Token": process.env.DARKBATCH_SETTLEMENT_TOKEN
    },
    body: JSON.stringify({ epoch_id: epochId, quote_batch_id: batchId })
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error("Coordinator refund preflight rejected: " + response.status + " " + JSON.stringify(result));
  }
  if (
    result.status !== "REFUND_PREFLIGHT_PASSED" ||
    Number(result.epoch_id) !== epochId ||
    bytes32(result.quote_batch_id, "Coordinator batch ID") !== batchId ||
    result.epoch_has_tracked_zec_tx !== false ||
    result.operator_no_broadcast_attestation_required !== true
  ) {
    throw new Error("Coordinator did not provide the exact safe-refund preflight response");
  }
  return result;
}

const escrow = new Contract(escrowAddress, [
  "function usdc() view returns (address)",
  "function oracle() view returns (address)",
  "event BatchMarkedRefundable(bytes32 indexed batchId)",
  "function getBatchStatus(bytes32) view returns (uint8 status,bytes32 planHash,uint256 buyerTotalMicro,uint256 sellerTotalMicro,uint256 buyerCount,uint256 paidBuyerCount,uint256 deadline,address tokenAddress,bytes32 zecTxid,bytes32 zecBlockHash,bytes32 escrowDataHash)",
  "function markRefundable(bytes32 batchId)"
], signer);

const configuredOracle = address(await escrow.oracle(), "Escrow oracle");
if (configuredOracle.toLowerCase() !== signer.address.toLowerCase()) {
  throw new Error("Local signer is not the oracle configured in the escrow contract");
}
if ((await escrow.usdc()).toLowerCase() !== tokenAddress.toLowerCase()) {
  throw new Error("Escrow token does not match DARKBATCH_USDC_TOKEN_ADDRESS");
}
const token = new Contract(tokenAddress, ["function decimals() view returns (uint8)"], provider);
if (Number(await token.decimals()) !== 6) throw new Error("Configured USDC token must have six decimals");

const preflight = await coordinatorRefundPreflight();
const batch = await escrow.getBatchStatus(batchId);
const status = Number(batch.status);
if (![1, 2, 5, 6].includes(status)) {
  throw new Error("Only OPEN/FUNDED batches or batches already marked REFUNDABLE/REFUNDED are supported; current status is " + status);
}
const zero = "0x" + "00".repeat(32);
if (String(batch.zecTxid).toLowerCase() !== zero || String(batch.zecBlockHash).toLowerCase() !== zero) {
  throw new Error("Escrow already references a ZEC transaction/block; refund is refused");
}
if (String(batch.planHash).toLowerCase() !== bytes32(preflight.quote_plan_hash, "Coordinator plan hash")) {
  throw new Error("Escrow plan hash does not match the coordinator's active epoch");
}
if (String(batch.escrowDataHash).toLowerCase() !== bytes32(preflight.quote_escrow_data_hash, "Coordinator payout hash")) {
  throw new Error("Escrow payout data hash does not match the coordinator's active epoch");
}
if (String(batch.tokenAddress).toLowerCase() !== tokenAddress.toLowerCase()) {
  throw new Error("Escrow reports a different USDC token address");
}
const deadline = Number(batch.deadline);
const now = Math.floor(Date.now() / 1000);
if ((status === 1 || status === 2) && (!Number.isSafeInteger(deadline) || deadline + graceSeconds > now)) {
  throw new Error("Refund requires the escrow deadline to have passed by the configured safety grace period");
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaultStatePath = path.join(repoRoot, "private-work", "quote-refund-" + batchId.slice(2) + ".json");
const statePath = path.resolve(process.env.DARKBATCH_REFUND_STATE_PATH || defaultStatePath);
let state = {};
if (fs.existsSync(statePath)) {
  state = JSON.parse(fs.readFileSync(statePath, "utf8"));
  if (
    bytes32(state.batchId, "Saved state batch ID") !== batchId ||
    Number(state.epochId) !== epochId ||
    bytes32(state.quotePlanHash, "Saved state plan hash") !== bytes32(preflight.quote_plan_hash, "Coordinator plan hash") ||
    bytes32(state.escrowDataHash, "Saved state payout hash") !== bytes32(preflight.quote_escrow_data_hash, "Coordinator payout hash")
  ) {
    throw new Error("Saved refund state belongs to a different epoch, batch, or escrow commitment");
  }
}

async function waitForExistingRefundEvent() {
  const deploymentBlock = Number(process.env.DARKBATCH_QUOTE_DEPLOYMENT_BLOCK);
  if (!Number.isSafeInteger(deploymentBlock) || deploymentBlock < 0) {
    throw new Error("DARKBATCH_QUOTE_DEPLOYMENT_BLOCK must be a confirmed non-negative block number");
  }
  const events = await escrow.queryFilter(escrow.filters.BatchMarkedRefundable(batchId), deploymentBlock);
  const event = events.length ? events[events.length - 1] : null;
  if (!event) throw new Error("Escrow reports a refundable state, but no BatchMarkedRefundable event was found from the configured deployment block");
  const receipt = await provider.waitForTransaction(event.transactionHash, minimumEvmConfirmations, 180000);
  if (!receipt) throw new Error("Refund transition exists but has not reached the required EVM confirmation depth");
  if (receipt.status !== 1) throw new Error("Saved refund transition transaction reverted: " + event.transactionHash);
  return receipt;
}

async function waitForRefundReceipt(txHash) {
  const receipt = await provider.waitForTransaction(txHash, minimumEvmConfirmations, 180000);
  if (!receipt) throw new Error("Refund attestation remains pending. Its exact signed bytes are saved; rerun to recover the same transaction.");
  if (receipt.status !== 1) throw new Error("markRefundable transaction reverted: " + txHash);
  const refreshed = await escrow.getBatchStatus(batchId);
  const nextStatus = Number(refreshed.status);
  if (nextStatus !== 5 && nextStatus !== 6) {
    throw new Error("Oracle receipt succeeded but escrow is not REFUNDABLE/REFUNDED; inspect on-chain state before retrying");
  }
  state.stage = nextStatus === 6 ? "USDC_REFUNDS_COMPLETE" : "REFUNDABLE_BUYERS_CAN_CLAIM";
  state.receiptBlock = Number(receipt.blockNumber);
  state.status = nextStatus;
  state.updatedAt = new Date().toISOString();
  saveJsonSecure(statePath, state);
  return receipt;
}

if (status === 5 || status === 6) {
  const receipt = state.txHash
    ? await (async () => {
        const raw = String(state.rawSignedTransaction || "");
        if (!raw || keccak256(raw).toLowerCase() !== String(state.txHash).toLowerCase()) {
          throw new Error("Saved refund state lacks matching signed bytes; inspect the original refund transaction");
        }
        return waitForRefundReceipt(state.txHash);
      })()
    : await waitForExistingRefundEvent();
  console.log(JSON.stringify({
    status: status === 6 ? "USDC_REFUNDS_COMPLETE" : "REFUNDABLE_BUYERS_CAN_CLAIM",
    batchId, epochId, planHash: preflight.quote_plan_hash,
    txHash: receipt.hash,
    evmConfirmationsRequired: minimumEvmConfirmations,
    note: "The on-chain refund transition has reached the required EVM confirmation depth; no new transaction was sent."
  }, null, 2));
} else {
  let txHash = String(state.txHash || "");
  let rawSigned = String(state.rawSignedTransaction || "");
  if (txHash) {
    if (!rawSigned || keccak256(rawSigned).toLowerCase() !== txHash.toLowerCase()) {
      throw new Error("Saved refund hash has no matching signed transaction bytes; refusing to create a replacement");
    }
    const receipt = await provider.getTransactionReceipt(txHash).catch(() => null);
    if (receipt) {
      if (receipt.status !== 1) throw new Error("Saved refund transaction reverted: " + txHash);
      await waitForRefundReceipt(txHash);
    } else {
      let pendingTx = await provider.getTransaction(txHash).catch(() => null);
      if (!pendingTx) {
        try {
          const rebroadcast = await provider.broadcastTransaction(rawSigned);
          if (rebroadcast.hash.toLowerCase() !== txHash.toLowerCase()) {
            throw new Error("RPC returned a different transaction hash for the saved signed bytes");
          }
        } catch (error) {
          pendingTx = await provider.getTransaction(txHash).catch(() => null);
          if (!pendingTx) {
            throw new Error("Existing refund transaction is absent/pending. Same signed bytes remain saved; no replacement was generated. " + String(error?.message || error));
          }
        }
      }
      await waitForRefundReceipt(txHash);
    }
  } else {
    const request = await escrow.markRefundable.populateTransaction(batchId);
    const populated = await signer.populateTransaction(request);
    rawSigned = await signer.signTransaction(populated);
    txHash = keccak256(rawSigned).toLowerCase();
    state = {
      batchId, epochId,
      quotePlanHash: bytes32(preflight.quote_plan_hash, "Coordinator plan hash"),
      escrowDataHash: bytes32(preflight.quote_escrow_data_hash, "Coordinator payout hash"),
      deadline,
      graceSeconds,
      txHash,
      rawSignedTransaction: rawSigned,
      stage: "REFUND_ATTESTATION_SIGNED",
      createdAt: new Date().toISOString()
    };
    saveJsonSecure(statePath, state);
    try {
      const submitted = await provider.broadcastTransaction(rawSigned);
      if (submitted.hash.toLowerCase() !== txHash) {
        throw new Error("RPC transaction hash does not match saved signed transaction hash");
      }
    } catch (error) {
      const seen = await provider.getTransaction(txHash).catch(() => null);
      if (!seen) {
        throw new Error("Refund broadcast outcome is uncertain; signed bytes and hash are saved. Rerun to rebroadcast the same transaction only. " + String(error?.message || error));
      }
    }
    console.log(JSON.stringify({
      status: "REFUND_ATTESTATION_SUBMITTED",
      batchId, epochId, txHash, statePath,
      note: "The operator attests no ZEC transaction was broadcast or remains unresolved; the EVM oracle cannot independently prove Zcash non-inclusion."
    }, null, 2));
    const receipt = await waitForRefundReceipt(txHash);
    console.log(JSON.stringify({
      status: state.stage, batchId, epochId,
      txHash: receipt.hash,
      evmConfirmationsRequired: minimumEvmConfirmations,
      deadline, graceSeconds, statePath
    }, null, 2));
  }
}
