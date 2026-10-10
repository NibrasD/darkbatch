import { Contract, JsonRpcProvider, Wallet } from "ethers";
const required = ["DARKBATCH_QUOTE_RPC_URL","DARKBATCH_QUOTE_CHAIN_ID","DARKBATCH_USDC_ESCROW_ADDRESS","DARKBATCH_SETTLEMENT_ORACLE_PRIVATE_KEY","DARKBATCH_COORDINATOR_API_BASE","DARKBATCH_SETTLEMENT_TOKEN","DARKBATCH_USDC_BATCH_ID","DARKBATCH_EPOCH_ID","DARKBATCH_ZEC_TXID"];
for (const key of required) if (!process.env[key]) throw new Error("Missing environment variable " + key);
const provider = new JsonRpcProvider(process.env.DARKBATCH_QUOTE_RPC_URL);
const network = await provider.getNetwork();
if (Number(network.chainId) !== Number(process.env.DARKBATCH_QUOTE_CHAIN_ID)) throw new Error("EVM RPC chain ID mismatch");
const signer = new Wallet(process.env.DARKBATCH_SETTLEMENT_ORACLE_PRIVATE_KEY, provider);
const escrowAddress = process.env.DARKBATCH_USDC_ESCROW_ADDRESS;
const batchId = process.env.DARKBATCH_USDC_BATCH_ID;
const zecTxid = process.env.DARKBATCH_ZEC_TXID.toLowerCase();
if (!/^0x[0-9a-fA-F]{64}$/.test(batchId)) throw new Error("Batch ID must be bytes32 hex");
if (!/^[0-9a-fA-F]{64}$/.test(zecTxid)) throw new Error("Zcash TXID must be 32-byte hex without 0x");
const apiBase = process.env.DARKBATCH_COORDINATOR_API_BASE.replace(/\/+$/,"");
async function api(path, options={}) {
  const response = await fetch(apiBase+path,{...options,headers:{"Content-Type":"application/json","X-DarkBatch-Settlement-Token":process.env.DARKBATCH_SETTLEMENT_TOKEN,...(options.headers||{})}});
  const body = await response.json();
  if (!response.ok) throw new Error("Coordinator API " + response.status + ": " + JSON.stringify(body));
  return body;
}
const tracked = await api("/api/v1/settlement/tx/"+zecTxid);
if (tracked.status !== "CONFIRMED" || Number(tracked.confirmations) < 1 || !tracked.block_hash) throw new Error("ZEC transaction is not confirmed in a real Zebra block");
if (Number(tracked.epoch_id) !== Number(process.env.DARKBATCH_EPOCH_ID)) throw new Error("ZEC transaction does not belong to requested FBA epoch");
if (String(tracked.quote_batch_id).toLowerCase() !== batchId.toLowerCase()) throw new Error("USDC batch ID differs from funded ZEC transaction record");
const escrow = new Contract(escrowAddress,[
  "function getBatchStatus(bytes32) view returns (uint8 status,bytes32 planHash,uint256 totalBuyerAmount,uint256 totalSellerAmount,uint256 buyerCount,uint256 paidBuyerCount,uint256 deadline,address quoteToken,bytes32 zcashTxid,bytes32 zcashBlockHash)",
  "function confirmZecSettlement(bytes32,bytes32,bytes32)",
  "function releaseBatch(bytes32)"
],signer);
const status = await escrow.getBatchStatus(batchId);
if (Number(status.status) !== 2) throw new Error("USDC batch must be FUNDED (status 2)");
if (BigInt(status.totalBuyerAmount) !== BigInt(tracked.quote_total_micro) || BigInt(status.totalSellerAmount) !== BigInt(tracked.quote_total_micro)) throw new Error("USDC totals do not match FBA quote commitment");
const expectedPlanHash = "0x" + String(tracked.quote_plan_hash).replace(/^0x/i,"");
if (String(status.planHash).toLowerCase() !== expectedPlanHash.toLowerCase()) throw new Error("Escrow plan hash differs from the committed FBA fills");
const blockHash = "0x" + String(tracked.block_hash).replace(/^0x/i,"");
const confirmTx = await escrow.confirmZecSettlement(batchId,"0x"+zecTxid,blockHash);
console.log(JSON.stringify({status:"ORACLE_ATTESTATION_SUBMITTED",batchId,zecTxid,blockHash,txHash:confirmTx.hash},null,2));
const confirmReceipt = await confirmTx.wait();
if (!confirmReceipt || confirmReceipt.status !== 1) throw new Error("ZEC confirmation attestation transaction failed");
const afterConfirm = await escrow.getBatchStatus(batchId);
if (Number(afterConfirm.status) !== 3) throw new Error("Escrow did not transition to ZEC_CONFIRMED");
const releaseTx = await escrow.releaseBatch(batchId);
console.log(JSON.stringify({status:"USDC_RELEASE_SUBMITTED",batchId,txHash:releaseTx.hash},null,2));
const releaseReceipt = await releaseTx.wait();
if (!releaseReceipt || releaseReceipt.status !== 1) throw new Error("USDC release transaction failed");
const afterRelease = await escrow.getBatchStatus(batchId);
if (Number(afterRelease.status) !== 4) throw new Error("Escrow did not transition to RELEASED");
const finalized = await api("/api/v1/settlement/quote-finalize",{
 method:"POST",
 body:JSON.stringify({epoch_id:Number(process.env.DARKBATCH_EPOCH_ID),zec_txid:zecTxid,quote_batch_id:batchId,quote_release_txid:releaseReceipt.hash})
});
console.log(JSON.stringify({status:"FBA_TRADE_CLEARED",batchId,zecTxid,zecBlockHash:tracked.block_hash,usdcReleaseTxid:releaseReceipt.hash,finalized},null,2));
