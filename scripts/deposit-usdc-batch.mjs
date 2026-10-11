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

const provider = new JsonRpcProvider(process.env.DARKBATCH_QUOTE_RPC_URL);
const network = await provider.getNetwork();
if (Number(network.chainId) !== Number(process.env.DARKBATCH_QUOTE_CHAIN_ID)) {
  throw new Error("EVM RPC chain ID mismatch");
}

const signer = new Wallet(process.env.DARKBATCH_BUYER_PRIVATE_KEY, provider);
const batchId = process.env.DARKBATCH_USDC_BATCH_ID;
if (!/^0x[0-9a-fA-F]{64}$/.test(batchId)) throw new Error("USDC batch ID must be bytes32 hex");

const escrowAddress = process.env.DARKBATCH_USDC_ESCROW_ADDRESS;
const configuredTokenAddress = process.env.DARKBATCH_USDC_TOKEN_ADDRESS;
const token = new Contract(configuredTokenAddress, [
  "function allowance(address,address) view returns (uint256)",
  "function approve(address,uint256) returns (bool)",
  "function balanceOf(address) view returns (uint256)",
  "function decimals() view returns (uint8)"
], signer);

const escrow = new Contract(escrowAddress, [
  "function getBatchStatus(bytes32) view returns (uint8 status,bytes32 planHash,uint256 totalBuyerAmount,uint256 totalSellerAmount,uint256 buyerCount,uint256 paidBuyerCount,uint256 deadline,address quoteToken,bytes32 zcashTxid,bytes32 zcashBlockHash,bytes32 escrowDataHash)",
  "function buyerAt(bytes32,uint256) view returns (address recipient,uint256 amount,bool paid,bool refunded)",
  "function fundBuyer(bytes32,uint256)"
], signer);

if (Number(await token.decimals()) !== 6) {
  throw new Error("Configured quote token is not six-decimal USDC");
}
const batch = await escrow.getBatchStatus(batchId);
if (Number(batch.status) !== 1) throw new Error("USDC batch must be OPEN (status 1) before buyer deposit");
if (String(batch.quoteToken).toLowerCase() !== (await token.getAddress()).toLowerCase()) {
  throw new Error("The escrow's quote token differs from DARKBATCH_USDC_TOKEN_ADDRESS");
}
if (BigInt(batch.deadline) <= BigInt(Math.floor(Date.now() / 1000))) {
  throw new Error("USDC batch deposit deadline has passed");
}

let due = 0n;
let alreadyPaid = false;
let alreadyRefunded = false;
let foundBuyer = false;
let foundBuyerIndex = -1;
const count = Number(batch.buyerCount);
for (let i = 0; i < count; i += 1) {
  const row = await escrow.buyerAt(batchId, i);
  if (String(row.recipient).toLowerCase() !== signer.address.toLowerCase()) continue;
  if (foundBuyer) throw new Error("Escrow unexpectedly contains duplicate rows for this buyer");
  foundBuyer = true;
  foundBuyerIndex = i;
  due = BigInt(row.amount);
  alreadyPaid = Boolean(row.paid);
  alreadyRefunded = Boolean(row.refunded);
}
if (!foundBuyer || due <= 0n) throw new Error("This EVM wallet is not included as a buyer in the batch");
if (alreadyPaid || alreadyRefunded) throw new Error("This buyer has already deposited or refunded this batch");

const balance = await token.balanceOf(signer.address);
if (balance < due) {
  throw new Error("Insufficient USDC. Need micro-USDC " + due.toString() + ", have " + balance.toString());
}
const escrowAddressForAllowance = await escrow.getAddress();
if (await token.allowance(signer.address, escrowAddressForAllowance) < due) {
  const approval = await token.approve(escrowAddressForAllowance, due);
  console.log(JSON.stringify({
    status: "APPROVE_SUBMITTED",
    txHash: approval.hash,
    amountMicro: due.toString(),
    batchId
  }, null, 2));
  const receipt = await approval.wait();
  if (!receipt || receipt.status !== 1) throw new Error("USDC approval failed");
}
const tx = await escrow.fundBuyer(batchId, foundBuyerIndex);
console.log(JSON.stringify({
  status: "USDC_DEPOSIT_SUBMITTED",
  buyer: signer.address,
  batchId,
  amountMicro: due.toString(),
  txHash: tx.hash
}, null, 2));
const receipt = await tx.wait();
if (!receipt || receipt.status !== 1) throw new Error("USDC deposit failed");
console.log(JSON.stringify({
  status: "USDC_DEPOSIT_CONFIRMED",
  buyer: signer.address,
  batchId,
  amountMicro: due.toString(),
  txHash: receipt.hash
}, null, 2));
