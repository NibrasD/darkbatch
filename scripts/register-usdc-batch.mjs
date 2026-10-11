import fs from "node:fs";
import { AbiCoder, Contract, JsonRpcProvider, Wallet, keccak256 } from "ethers";

const required = ["DARKBATCH_QUOTE_RPC_URL","DARKBATCH_QUOTE_CHAIN_ID","DARKBATCH_USDC_ESCROW_ADDRESS","DARKBATCH_QUOTE_COORDINATOR_PRIVATE_KEY","DARKBATCH_USDC_BATCH_DEADLINE_SECONDS"];
for (const key of required) if (!process.env[key]) throw new Error("Missing environment variable " + key);
const planPath = process.argv[2] || "../private-work/fba-plan.json";
const plan = JSON.parse(fs.readFileSync(planPath, "utf8"));
if (plan.schema !== "darkbatch.fba-local-pczt-plan.v1" || plan.quote_escrow_ready !== true) throw new Error("File is not a complete private DarkBatch FBA quote plan");
if (!/^[0-9a-fA-F]{64}$/.test(String(plan.quote_plan_hash || ""))) throw new Error("Plan must include quote_plan_hash from the API");
const provider = new JsonRpcProvider(process.env.DARKBATCH_QUOTE_RPC_URL);
const network = await provider.getNetwork();
if (Number(network.chainId) !== Number(process.env.DARKBATCH_QUOTE_CHAIN_ID)) throw new Error("EVM RPC chain ID mismatch");
const signer = new Wallet(process.env.DARKBATCH_QUOTE_COORDINATOR_PRIVATE_KEY, provider);
const escrow = new Contract(process.env.DARKBATCH_USDC_ESCROW_ADDRESS, [
  "function openBatch(bytes32 batchId,bytes32 planHash,address[] buyers,uint256[] buyerAmounts,address[] sellers,uint256[] sellerAmounts,uint256 deadline)",
  "function getBatchStatus(bytes32 batchId) view returns (uint8 status,bytes32 planHash,uint256 totalBuyerAmount,uint256 totalSellerAmount,uint256 buyerCount,uint256 paidBuyerCount,uint256 deadline,address quoteToken,bytes32 zecTxid,bytes32 zecBlockHash,bytes32 escrowDataHash)"
], signer);
function aggregate(fills) {
  const sums = new Map();
  for (const fill of fills) {
    const address = String(fill.quote_address || "").toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(address)) throw new Error("Missing/invalid signed quote address for intent " + fill.intent_id);
    const amount = BigInt(fill.quote_amount_micro);
    if (amount <= 0n) throw new Error("USDC obligation must be positive");
    sums.set(address, (sums.get(address) || 0n) + amount);
  }
  const rows = [...sums.entries()].sort((a,b) => a[0].localeCompare(b[0]));
  return {addresses: rows.map(x => x[0]), amounts: rows.map(x => x[1])};
}
const buyers = aggregate(plan.buy_fills);
const sellers = aggregate(plan.sell_fills);
const sum = list => list.reduce((a,b) => a+b, 0n);
const total = BigInt(plan.quote_total_micro);
if (sum(buyers.amounts) !== total || sum(sellers.amounts) !== total) throw new Error("Aggregated buyer/seller USDC obligations do not balance with plan total");
const planHash = "0x" + plan.quote_plan_hash.toLowerCase();
const coder = AbiCoder.defaultAbiCoder();
const escrowDataHash = keccak256(coder.encode(
  ["address[]", "uint256[]", "address[]", "uint256[]"],
  [buyers.addresses, buyers.amounts, sellers.addresses, sellers.amounts]
));
const batchId = keccak256(coder.encode(["uint256","bytes32"], [plan.epoch_id, planHash]));
const duration = Number(process.env.DARKBATCH_USDC_BATCH_DEADLINE_SECONDS);
if (!Number.isSafeInteger(duration) || duration < 1800 || duration > 604800) throw new Error("Deadline must be between 30 minutes and 7 days");
const deadline = Math.floor(Date.now()/1000) + duration;
const existing = await escrow.getBatchStatus(batchId);
if (Number(existing.status) !== 0) {
  if (String(existing.planHash).toLowerCase() !== planHash.toLowerCase()) throw new Error("Existing escrow batch has a different plan hash");
  if (String(existing.escrowDataHash).toLowerCase() !== escrowDataHash.toLowerCase()) throw new Error("Existing escrow batch has different aggregated buyer/seller payout data");
  if (String(existing.quoteToken).toLowerCase() !== String(process.env.DARKBATCH_USDC_TOKEN_ADDRESS || "").toLowerCase()) {
    throw new Error("Existing escrow batch uses a different quote token; set DARKBATCH_USDC_TOKEN_ADDRESS and check the deployment");
  }
  console.log(JSON.stringify({status:"BATCH_ALREADY_REGISTERED",batchId,planHash,escrowDataHash,statusCode:Number(existing.status),quoteTotalMicro:total.toString()},null,2));
} else {
  const tx = await escrow.openBatch(batchId,planHash,buyers.addresses,buyers.amounts,sellers.addresses,sellers.amounts,deadline);
  console.log(JSON.stringify({status:"BATCH_REGISTRATION_SUBMITTED",batchId,planHash,epochId:plan.epoch_id,quoteTotalMicro:total.toString(),buyerCount:buyers.addresses.length,sellerCount:sellers.addresses.length,deadline,txHash:tx.hash},null,2));
  const receipt = await tx.wait();
  if (!receipt || receipt.status !== 1) throw new Error("openBatch was not confirmed successfully");
  const status = await escrow.getBatchStatus(batchId);
  console.log(JSON.stringify({status:"BATCH_OPEN",batchId,planHash,statusCode:Number(status.status),deadline:Number(status.deadline),openBatchTx:receipt.hash},null,2));
}
