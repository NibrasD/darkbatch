import { Contract, JsonRpcProvider, Wallet } from "ethers";

const required = [
  "DARKBATCH_QUOTE_RPC_URL",
  "DARKBATCH_QUOTE_CHAIN_ID",
  "DARKBATCH_USDC_ESCROW_ADDRESS",
  "DARKBATCH_USDC_TOKEN_ADDRESS",
  "DARKBATCH_BUYER_PRIVATE_KEY",
  "DARKBATCH_USDC_BATCH_ID"
];
for (const key of required) {
  if (!process.env[key]) throw new Error("Missing environment variable " + key);
}

function bytes32(value, label) {
  const normalized = String(value || "").trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(normalized)) throw new Error(label + " must be 32-byte hex");
  return "0x" + normalized.toLowerCase();
}
function address(value, label) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(String(value || ""))) throw new Error(label + " must be an EVM address");
  return value;
}
const batchId = bytes32(process.env.DARKBATCH_USDC_BATCH_ID, "USDC batch ID");
const expectedChainId = Number(process.env.DARKBATCH_QUOTE_CHAIN_ID);
const minimumConfirmations = Number(process.env.DARKBATCH_QUOTE_MIN_CONFIRMATIONS || "2");
if (!Number.isSafeInteger(expectedChainId) || expectedChainId <= 0) throw new Error("EVM chain ID must be a positive integer");
if (!Number.isSafeInteger(minimumConfirmations) || minimumConfirmations < 2) throw new Error("DARKBATCH_QUOTE_MIN_CONFIRMATIONS must be an integer >= 2");

const provider = new JsonRpcProvider(process.env.DARKBATCH_QUOTE_RPC_URL);
const network = await provider.getNetwork();
if (Number(network.chainId) !== expectedChainId) throw new Error("EVM RPC chain ID mismatch");
const signer = new Wallet(process.env.DARKBATCH_BUYER_PRIVATE_KEY, provider);
const tokenAddress = address(process.env.DARKBATCH_USDC_TOKEN_ADDRESS, "USDC token address");
const escrowAddress = address(process.env.DARKBATCH_USDC_ESCROW_ADDRESS, "USDC escrow address");
const token = new Contract(tokenAddress, [
  "function balanceOf(address) view returns (uint256)",
  "function decimals() view returns (uint8)"
], provider);
const escrow = new Contract(escrowAddress, [
  "function usdc() view returns (address)",
  "function getBatchStatus(bytes32) view returns (uint8 status,bytes32 planHash,uint256 totalBuyerMicro,uint256 totalSellerMicro,uint256 buyerCount,uint256 paidBuyerCount,uint256 deadline,address tokenAddress,bytes32 zecTxid,bytes32 zecBlockHash,bytes32 escrowDataHash)",
  "function buyerAt(bytes32,uint256) view returns (address recipient,uint256 amount,bool paid,bool refunded)",
  "function refundBuyer(bytes32 batchId,uint256 buyerIndex)"
], signer);

if ((await escrow.usdc()).toLowerCase() !== tokenAddress.toLowerCase()) throw new Error("Escrow token differs from the configured USDC token");
if (Number(await token.decimals()) !== 6) throw new Error("Configured USDC token must have six decimals");

const batch = await escrow.getBatchStatus(batchId);
if (Number(batch.status) === 6) throw new Error("Batch is already REFUNDED; no further buyer refund is available");
if (Number(batch.status) !== 5) throw new Error("Batch must be REFUNDABLE (status 5); current status is " + Number(batch.status));

let buyerIndex = -1;
let amountDue = 0n;
const count = Number(batch.buyerCount);
for (let index = 0; index < count; index += 1) {
  const row = await escrow.buyerAt(batchId, index);
  if (String(row.recipient).toLowerCase() !== signer.address.toLowerCase()) continue;
  if (buyerIndex !== -1) throw new Error("Escrow unexpectedly contains duplicate buyer rows for this wallet");
  buyerIndex = index;
  amountDue = BigInt(row.amount);
  if (!row.paid) throw new Error("This buyer did not deposit USDC into the expired batch");
  if (row.refunded) throw new Error("This buyer's USDC deposit was already refunded");
}
if (buyerIndex < 0 || amountDue <= 0n) throw new Error("This wallet has no refundable USDC deposit in this batch");

const balanceBefore = await token.balanceOf(signer.address);
const tx = await escrow.refundBuyer(batchId, buyerIndex);
console.log(JSON.stringify({
  status: "USDC_REFUND_SUBMITTED",
  batchId,
  buyer: signer.address,
  buyerIndex,
  amountMicro: amountDue.toString(),
  txHash: tx.hash
}, null, 2));

const receipt = await tx.wait(minimumConfirmations);
if (!receipt || receipt.status !== 1) throw new Error("USDC refund did not confirm successfully");
const rowAfter = await escrow.buyerAt(batchId, buyerIndex);
const balanceAfter = await token.balanceOf(signer.address);
if (!rowAfter.refunded || balanceAfter - balanceBefore !== amountDue) {
  throw new Error("Refund receipt was mined, but buyer refund flag or exact USDC balance delta did not match");
}
const statusAfter = Number((await escrow.getBatchStatus(batchId)).status);
console.log(JSON.stringify({
  status: "USDC_REFUND_CONFIRMED",
  batchId,
  buyer: signer.address,
  amountMicro: amountDue.toString(),
  txHash: receipt.hash,
  evmConfirmationsRequired: minimumConfirmations,
  escrowStatus: statusAfter
}, null, 2));
