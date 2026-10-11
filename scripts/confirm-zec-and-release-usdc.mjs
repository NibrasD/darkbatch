import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, JsonRpcProvider, Wallet, keccak256 } from "ethers";

const required = [
  "DARKBATCH_QUOTE_RPC_URL",
  "DARKBATCH_QUOTE_CHAIN_ID",
  "DARKBATCH_USDC_TOKEN_ADDRESS",
  "DARKBATCH_USDC_ESCROW_ADDRESS",
  "DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY",
  "DARKBATCH_COORDINATOR_API_BASE",
  "DARKBATCH_SETTLEMENT_TOKEN",
  "DARKBATCH_USDC_BATCH_ID",
  "DARKBATCH_EPOCH_ID",
  "DARKBATCH_ZEC_TXID"
];
for (const key of required) {
  if (!process.env[key]) throw new Error("Missing environment variable " + key);
}

function bytes32(value, label, allowPrefix = true) {
  const raw = String(value || "").trim();
  const normalized = allowPrefix ? raw.replace(/^0x/i, "") : raw;
  if (!/^[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error(label + " must be exactly 32-byte hexadecimal text");
  }
  return "0x" + normalized.toLowerCase();
}

const batchId = bytes32(process.env.DARKBATCH_USDC_BATCH_ID, "USDC batch ID");
const zecTxid = bytes32(process.env.DARKBATCH_ZEC_TXID, "ZEC TXID", false);
const epochId = Number(process.env.DARKBATCH_EPOCH_ID);
if (!Number.isSafeInteger(epochId) || epochId < 0) throw new Error("DARKBATCH_EPOCH_ID must be a non-negative integer");

const minimumZecConfirmations = Number(process.env.DARKBATCH_MINIMUM_ZEC_CONFIRMATIONS || "2");
const minimumEvmConfirmations = Number(process.env.DARKBATCH_QUOTE_MIN_CONFIRMATIONS || "2");
if (!Number.isSafeInteger(minimumZecConfirmations) || minimumZecConfirmations < 2) {
  throw new Error("DARKBATCH_MINIMUM_ZEC_CONFIRMATIONS must be an integer >= 2");
}
if (!Number.isSafeInteger(minimumEvmConfirmations) || minimumEvmConfirmations < 2) {
  throw new Error("DARKBATCH_QUOTE_MIN_CONFIRMATIONS must be an integer >= 2");
}

const provider = new JsonRpcProvider(process.env.DARKBATCH_QUOTE_RPC_URL);
const network = await provider.getNetwork();
if (Number(network.chainId) !== Number(process.env.DARKBATCH_QUOTE_CHAIN_ID)) {
  throw new Error("EVM RPC chain ID mismatch");
}
const signer = new Wallet(process.env.DARKBATCH_QUOTE_ORACLE_PRIVATE_KEY, provider);
const escrowAddress = process.env.DARKBATCH_USDC_ESCROW_ADDRESS;
const tokenAddress = process.env.DARKBATCH_USDC_TOKEN_ADDRESS;
const apiBase = process.env.DARKBATCH_COORDINATOR_API_BASE.replace(/\/+$/, "");
const apiUrl = new URL(apiBase);
if (apiUrl.protocol !== "https:" && !["localhost", "127.0.0.1", "::1"].includes(apiUrl.hostname)) {
  throw new Error("Remote coordinator APIs must use HTTPS");
}

async function api(endpoint, options = {}) {
  const response = await fetch(apiBase + endpoint, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-DarkBatch-Settlement-Token": process.env.DARKBATCH_SETTLEMENT_TOKEN,
      ...(options.headers || {})
    }
  });
  const body = await response.json();
  if (!response.ok) throw new Error("Coordinator API " + response.status + ": " + JSON.stringify(body));
  return body;
}

const tracked = await api("/api/v1/settlement/tx/" + zecTxid.slice(2));
if (
  tracked.status !== "CONFIRMED" ||
  Number(tracked.confirmations) < minimumZecConfirmations ||
  !tracked.block_hash
) {
  throw new Error("ZEC transaction must have at least " + minimumZecConfirmations + " real Zebra confirmations before USDC release");
}
if (Number(tracked.epoch_id) !== epochId) throw new Error("ZEC transaction does not belong to the requested FBA epoch");
if (bytes32(tracked.quote_batch_id, "Tracked quote batch") !== batchId) throw new Error("USDC batch ID differs from the tracked ZEC transaction");
const blockHash = bytes32(tracked.block_hash, "ZEC block hash");
const expectedPlanHash = bytes32(tracked.quote_plan_hash, "FBA plan hash");
const expectedEscrowDataHash = bytes32(tracked.quote_escrow_data_hash, "Escrow payout data hash");

const escrow = new Contract(escrowAddress, [
  "event BatchReleased(bytes32 indexed batchId,bytes32 indexed zecTxid)",
  "function getBatchStatus(bytes32) view returns (uint8 status,bytes32 planHash,uint256 totalBuyerAmount,uint256 totalSellerAmount,uint256 buyerCount,uint256 paidBuyerCount,uint256 deadline,address quoteToken,bytes32 zecTxid,bytes32 zecBlockHash,bytes32 escrowDataHash)",
  "function markZecConfirmed(bytes32 batchId,bytes32 zecTxid,bytes32 zecBlockHash)",
  "function releaseBatch(bytes32 batchId)"
], signer);

const quoteTokenAddress = await (async () => {
  const tokenCheck = new Contract(tokenAddress, ["function decimals() view returns (uint8)"], provider);
  if (Number(await tokenCheck.decimals()) !== 6) throw new Error("Configured USDC token must have six decimals");
  return tokenAddress.toLowerCase();
})();
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const statePath = path.resolve(
  process.env.DARKBATCH_RELEASE_STATE_PATH ||
  path.join(repoRoot, "private-work", "quote-release-" + batchId.slice(2) + ".json")
);
fs.mkdirSync(path.dirname(statePath), { recursive: true });
if (process.platform !== "win32") {
  try { fs.chmodSync(path.dirname(statePath), 0o700); } catch {}
}
let state = {};
if (fs.existsSync(statePath)) {
  state = JSON.parse(fs.readFileSync(statePath, "utf8"));
  if (
    bytes32(state.batchId, "Saved state batch ID") !== batchId ||
    Number(state.epochId) !== epochId ||
    bytes32(state.zecTxid, "Saved state ZEC TXID") !== zecTxid ||
    bytes32(state.zecBlockHash, "Saved state ZEC block hash") !== blockHash ||
    bytes32(state.quotePlanHash, "Saved state plan hash") !== expectedPlanHash ||
    bytes32(state.escrowDataHash, "Saved state escrow data hash") !== expectedEscrowDataHash
  ) {
    throw new Error("Saved release state belongs to a different epoch, ZEC transaction, or escrow commitment");
  }
}
state = {
  ...state,
  batchId,
  epochId,
  zecTxid,
  zecBlockHash: blockHash,
  quotePlanHash: expectedPlanHash,
  escrowDataHash: expectedEscrowDataHash,
  updatedAt: new Date().toISOString()
};
function saveState() {
  state.updatedAt = new Date().toISOString();
  const temporary = statePath + ".tmp";
  fs.writeFileSync(temporary, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(temporary, statePath);
  if (process.platform !== "win32") {
    try { fs.chmodSync(statePath, 0o600); } catch {}
  }
}

async function waitForSuccessfulReceipt(txHash, label) {
  const receipt = await provider.waitForTransaction(txHash, minimumEvmConfirmations, 180_000);
  if (!receipt) throw new Error(label + " remains pending. Its transaction hash is saved; rerun this command to resume without resubmitting it.");
  if (receipt.status !== 1) throw new Error(label + " transaction mined but reverted: " + txHash);
  return receipt;
}

async function signPersistThenBroadcast(methodName, args, stateKey, stage) {
  const transactionRequest = await escrow[methodName].populateTransaction(...args);
  const populated = await signer.populateTransaction(transactionRequest);
  const rawSigned = await signer.signTransaction(populated);
  const localHash = keccak256(rawSigned).toLowerCase();

  // Persist the locally derived Ethereum transaction hash before contacting the RPC.
  // If the RPC accepts the raw transaction but the response is lost, recovery polls this
  // same hash rather than constructing and broadcasting a duplicate payment.
  state[stateKey] = localHash;
  state.stage = stage;
  saveState();

  try {
    const submitted = await provider.broadcastTransaction(rawSigned);
    if (submitted.hash.toLowerCase() !== localHash) {
      throw new Error("RPC transaction hash differs from the locally derived signed transaction hash");
    }
    return { hash: localHash };
  } catch (error) {
    throw new Error(
      stage + " broadcast outcome is uncertain; saved transaction " + localHash +
      ". Inspect on-chain state and rerun this command to poll the same hash. " +
      String(error?.message || error)
    );
  }
}

let batch = await escrow.getBatchStatus(batchId);
if (Number(batch.status) < 2 || Number(batch.status) > 4) {
  throw new Error("Escrow status must be FUNDED, ZEC_CONFIRMED, or RELEASED (found " + Number(batch.status) + ")");
}
if (String(batch.quoteToken).toLowerCase() !== quoteTokenAddress) throw new Error("Escrow's configured quote token differs from DARKBATCH_USDC_TOKEN_ADDRESS");
if (String(batch.planHash).toLowerCase() !== expectedPlanHash.toLowerCase()) throw new Error("Escrow plan hash differs from the committed FBA fills");
if (String(batch.escrowDataHash).toLowerCase() !== expectedEscrowDataHash.toLowerCase()) throw new Error("Escrow buyer/seller payout addresses or amounts differ from the FBA plan");
if (BigInt(batch.totalBuyerAmount) !== BigInt(tracked.quote_total_micro) ||
    BigInt(batch.totalSellerAmount) !== BigInt(tracked.quote_total_micro)) {
  throw new Error("USDC totals do not match the tracked FBA quote commitment");
}

if (Number(batch.status) === 2) {
  if (BigInt(batch.deadline) <= BigInt(Math.floor(Date.now() / 1000))) {
    throw new Error("Escrow deadline has passed; refusing to attest or release this batch");
  }
  if (state.attestationTxHash) {
    const receipt = await waitForSuccessfulReceipt(state.attestationTxHash, "Saved ZEC attestation");
    console.log(JSON.stringify({ status: "ORACLE_ATTESTATION_CONFIRMED", batchId, txHash: receipt.hash, confirmationsRequired: minimumEvmConfirmations }, null, 2));
  } else {
    // Save the deterministic settlement context first. Once the wallet returns a tx hash,
    // persist that hash before waiting for its receipt so a timeout can be resumed safely.
    const tx = await signPersistThenBroadcast(
      "markZecConfirmed", [batchId, zecTxid, blockHash],
      "attestationTxHash", "ATTESTATION_PENDING"
    );
    console.log(JSON.stringify({ status: "ORACLE_ATTESTATION_SUBMITTED", batchId, zecTxid, blockHash, txHash: tx.hash }, null, 2));
    const receipt = await waitForSuccessfulReceipt(tx.hash, "ZEC attestation");
    console.log(JSON.stringify({ status: "ORACLE_ATTESTATION_CONFIRMED", batchId, txHash: receipt.hash, confirmationsRequired: minimumEvmConfirmations }, null, 2));
  }
  batch = await escrow.getBatchStatus(batchId);
}
if (Number(batch.status) >= 3) {
  if (String(batch.zecTxid).toLowerCase() !== zecTxid.toLowerCase() ||
      String(batch.zecBlockHash).toLowerCase() !== blockHash.toLowerCase()) {
    throw new Error("Escrow is associated with a different ZEC transaction or block");
  }
}
if (Number(batch.status) === 3) {
  if (state.releaseTxHash) {
    const receipt = await waitForSuccessfulReceipt(state.releaseTxHash, "Saved USDC release");
    console.log(JSON.stringify({ status: "USDC_RELEASE_CONFIRMED", batchId, txHash: receipt.hash, confirmationsRequired: minimumEvmConfirmations }, null, 2));
  } else {
    const tx = await signPersistThenBroadcast(
      "releaseBatch", [batchId], "releaseTxHash", "RELEASE_PENDING"
    );
    console.log(JSON.stringify({ status: "USDC_RELEASE_SUBMITTED", batchId, txHash: tx.hash }, null, 2));
    const receipt = await waitForSuccessfulReceipt(tx.hash, "USDC release");
    console.log(JSON.stringify({ status: "USDC_RELEASE_CONFIRMED", batchId, txHash: receipt.hash, confirmationsRequired: minimumEvmConfirmations }, null, 2));
  }
  batch = await escrow.getBatchStatus(batchId);
}
if (Number(batch.status) !== 4) throw new Error("Escrow is not RELEASED; current status is " + Number(batch.status));

// Recover if the release was mined before the local state file could save its hash.
// The matching event binds this exact batch to this exact confirmed ZEC TXID.
if (!state.releaseTxHash) {
  const events = await escrow.queryFilter(escrow.filters.BatchReleased(batchId, zecTxid));
  const event = events.find(e => e.transactionHash);
  if (event?.transactionHash) {
    state.releaseTxHash = event.transactionHash;
    state.stage = "RELEASE_DISCOVERED";
    saveState();
  }
}
if (!state.releaseTxHash) {
  throw new Error("Escrow is RELEASED but the exact release transaction hash could not be recovered. Do not mark the epoch settled without it.");
}
const releaseReceipt = await waitForSuccessfulReceipt(state.releaseTxHash, "USDC release");
const afterRelease = await escrow.getBatchStatus(batchId);
if (Number(afterRelease.status) !== 4 ||
    String(afterRelease.zecTxid).toLowerCase() !== zecTxid.toLowerCase() ||
    String(afterRelease.zecBlockHash).toLowerCase() !== blockHash.toLowerCase()) {
  throw new Error("Final escrow state does not match the confirmed ZEC transaction");
}

const finalized = await api("/api/v1/settlement/quote-finalize", {
  method: "POST",
  body: JSON.stringify({
    epoch_id: epochId,
    zec_txid: zecTxid.slice(2),
    quote_batch_id: batchId,
    quote_release_txid: releaseReceipt.hash
  })
});
state.stage = "CLEARED";
state.finalization = finalized;
saveState();
console.log(JSON.stringify({
  status: "FBA_TRADE_CLEARED",
  batchId,
  epochId,
  zecTxid: zecTxid.slice(2),
  zecBlockHash: blockHash,
  minimumZecConfirmations,
  minimumEvmConfirmations,
  usdcReleaseTxid: releaseReceipt.hash,
  finalized
}, null, 2));
