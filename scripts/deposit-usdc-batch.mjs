import { Contract, JsonRpcProvider, Wallet } from "ethers";
const required = ["DARKBATCH_QUOTE_RPC_URL","DARKBATCH_QUOTE_CHAIN_ID","DARKBATCH_USDC_ESCROW_ADDRESS","DARKBATCH_USDC_TOKEN_ADDRESS","DARKBATCH_BUYER_PRIVATE_KEY","DARKBATCH_USDC_BATCH_ID"];
for (const key of required) if (!process.env[key]) throw new Error("Missing environment variable " + key);
const provider = new JsonRpcProvider(process.env.DARKBATCH_QUOTE_RPC_URL);
const network = await provider.getNetwork();
if (Number(network.chainId) !== Number(process.env.DARKBATCH_QUOTE_CHAIN_ID)) throw new Error("EVM RPC chain ID mismatch");
const signer = new Wallet(process.env.DARKBATCH_BUYER_PRIVATE_KEY, provider);
const batchId = process.env.DARKBATCH_USDC_BATCH_ID;
if (!/^0x[0-9a-fA-F]{64}$/.test(batchId)) throw new Error("USDC batch ID must be bytes32 hex");
const escrowAddress = process.env.DARKBATCH_USDC_ESCROW_ADDRESS;
const token = new Contract(process.env.DARKBATCH_USDC_TOKEN_ADDRESS, [
  "function allowance(address,address) view returns (uint256)",
  "function approve(address,uint256) returns (bool)",
  "function balanceOf(address) view returns (uint256)",
  "function decimals() view returns (uint8)"
], signer);
const escrow = new Contract(escrowAddress, [
  "function buyerDue(bytes32,address) view returns (uint256)",
  "function buyerPaid(bytes32,address) view returns (uint256)",
  "function deposit(bytes32)"
], signer);
if (Number(await token.decimals()) !== 6) throw new Error("Configured quote token is not six-decimal USDC");
const due = await escrow.buyerDue(batchId, signer.address);
const paid = await escrow.buyerPaid(batchId, signer.address);
if (due <= 0n) throw new Error("This EVM wallet is not included as a buyer in the batch");
if (paid > 0n) throw new Error("This buyer has already deposited");
const balance = await token.balanceOf(signer.address);
if (balance < due) throw new Error("Insufficient USDC. Need micro-USDC " + due + ", have " + balance);
if (await token.allowance(signer.address, escrowAddress) < due) {
  const approval = await token.approve(escrowAddress, due);
  console.log(JSON.stringify({status:"APPROVE_SUBMITTED",txHash:approval.hash,amountMicro:due.toString(),batchId},null,2));
  const receipt = await approval.wait();
  if (!receipt || receipt.status !== 1) throw new Error("USDC approval failed");
}
const tx = await escrow.deposit(batchId);
console.log(JSON.stringify({status:"USDC_DEPOSIT_SUBMITTED",buyer:signer.address,batchId,amountMicro:due.toString(),txHash:tx.hash},null,2));
const receipt = await tx.wait();
if (!receipt || receipt.status !== 1) throw new Error("USDC deposit failed");
console.log(JSON.stringify({status:"USDC_DEPOSIT_CONFIRMED",buyer:signer.address,batchId,amountMicro:due.toString(),txHash:receipt.hash},null,2));
