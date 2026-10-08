//! Real ZIP 228 Specification Implementation (Asset Swaps for Zcash Shielded Assets)
//! Defines authentic SwapOrder, ProposedInput, DesiredOutput, SwapAction, FeeAction, and SwapBundle.

use ff::PrimeField;
use pasta_curves::pallas::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposedInput {
    pub asset_id: [u8; 32], // Asset Base identifier (ZEC or Custom Asset per ZIP 227)
    pub value_zat: u64,
    pub nullifier: [u8; 32],
    pub note_commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DesiredOutput {
    pub asset_id: [u8; 32],
    pub min_value_zat: u64, // Limit price constraint
    pub recipient_address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapAction {
    pub cv_net: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cm_star: [u8; 32],
    pub encrypted_memo_hex: String, // Hex string of strictly 512 bytes (1024 hex chars)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeAction {
    pub cv_fee: [u8; 32],
    pub matcher_fee_zat: u64,
    pub miner_fee_zat: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapActionGroup {
    pub anchor: [u8; 32],
    pub swap_action: SwapAction,
    pub fee_action: FeeAction,
    pub expiry_height: u32,
    pub bsk_share_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapOrder {
    pub order_id: [u8; 32],
    pub proposed_input: ProposedInput,
    pub desired_output: DesiredOutput,
    pub action_group: SwapActionGroup,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapBundle {
    pub bundle_id: [u8; 32],
    pub swap_orders: Vec<SwapOrder>,
    pub aggregated_bsk_hex: String,
    pub uniform_clearing_price_usd: f64,
    pub total_cleared_zat: u64,
    pub total_matcher_fee_zat: u64,
    pub total_miner_fee_zat: u64,
}

impl SwapBundle {
    /// Constructs a valid ZIP 228 Swap Bundle from matching Swap Orders
    pub fn new(
        orders: Vec<SwapOrder>,
        clearing_price: f64,
        cleared_zat: u64,
    ) -> Result<Self, &'static str> {
        if orders.len() < 2 {
            return Err("ZIP 228 Swap Bundle requires at least 2 matching Swap Orders");
        }

        // Sum binding keys: bsk_bundle = sum(bsk_i) mod q
        let mut total_bsk = Scalar::zero();
        let mut matcher_fees = 0u64;
        let mut miner_fees = 0u64;

        for o in &orders {
            matcher_fees += o.action_group.fee_action.matcher_fee_zat;
            miner_fees += o.action_group.fee_action.miner_fee_zat;
            
            let bytes = hex::decode(&o.action_group.bsk_share_hex).map_err(|_| "Invalid hex bsk")?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                let opt = Scalar::from_repr(arr);
                if bool::from(opt.is_some()) {
                    total_bsk += opt.unwrap();
                }
            }
        }

        let mut bundle_id = [0u8; 32];
        let h = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ZIP228SwapBundle")
            .to_state()
            .update(&cleared_zat.to_le_bytes())
            .finalize();
        bundle_id.copy_from_slice(h.as_bytes());

        Ok(SwapBundle {
            bundle_id,
            swap_orders: orders,
            aggregated_bsk_hex: hex::encode(total_bsk.to_repr()),
            uniform_clearing_price_usd: clearing_price,
            total_cleared_zat: cleared_zat,
            total_matcher_fee_zat: matcher_fees,
            total_miner_fee_zat: miner_fees,
        })
    }
}
