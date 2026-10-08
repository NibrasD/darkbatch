//! ZIP 229: Transaction v6 Format for Ironwood Shielded Pool
//! Provides binary serialization matching consensus layout.

use serde::{Deserialize, Serialize};
use crate::zip228::SwapBundle;

pub const TX_VERSION_6: u32 = 0x80000006;
pub const VERSION_GROUP_ID_V6: u32 = 0x26a7270a;
pub const CONSENSUS_BRANCH_ID_IRONWOOD: u32 = 0x2f8b66c3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionV6 {
    pub header: u32,
    pub version_group_id: u32,
    pub consensus_branch_id: u32,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub value_balance_ironwood: i64,
    pub anchor_ironwood: [u8; 32],
    pub swap_bundle: SwapBundle,
    pub raw_tx_bytes: Vec<u8>,
}

impl TransactionV6 {
    pub fn from_swap_bundle(
        bundle: SwapBundle,
        expiry_height: u32,
        anchor: [u8; 32],
    ) -> Self {
        let mut raw_bytes = Vec::new();

        // 1. Header (4 bytes LE)
        raw_bytes.extend_from_slice(&TX_VERSION_6.to_le_bytes());
        // 2. Version Group ID (4 bytes LE)
        raw_bytes.extend_from_slice(&VERSION_GROUP_ID_V6.to_le_bytes());
        // 3. Consensus Branch ID (4 bytes LE)
        raw_bytes.extend_from_slice(&CONSENSUS_BRANCH_ID_IRONWOOD.to_le_bytes());
        // 4. Lock Time (4 bytes LE)
        raw_bytes.extend_from_slice(&0u32.to_le_bytes());
        // 5. Expiry Height (4 bytes LE)
        raw_bytes.extend_from_slice(&expiry_height.to_le_bytes());
        // 6. Net Value Balance (8 bytes LE signed)
        raw_bytes.extend_from_slice(&0i64.to_le_bytes());
        // 7. Anchor (32 bytes)
        raw_bytes.extend_from_slice(&anchor);

        // 8. Number of Action Groups (CompactSize / 1 byte)
        raw_bytes.push(bundle.swap_orders.len() as u8);

        // 9. Encode each Action Group
        for o in &bundle.swap_orders {
            raw_bytes.extend_from_slice(&o.action_group.anchor);
            // 2 actions per group (Swap Action + Fee Action)
            raw_bytes.push(2u8);

            // Action 1: Swap Action
            raw_bytes.extend_from_slice(&o.action_group.swap_action.cv_net);
            raw_bytes.extend_from_slice(&o.action_group.swap_action.nullifier);
            raw_bytes.extend_from_slice(&o.action_group.swap_action.rk);
            raw_bytes.extend_from_slice(&o.action_group.swap_action.cm_star);
            
            // Strictly 512-byte memo payload
            let memo_bytes = hex::decode(&o.action_group.swap_action.encrypted_memo_hex).unwrap_or_else(|_| vec![0u8; 512]);
            if memo_bytes.len() == 512 {
                raw_bytes.extend_from_slice(&memo_bytes);
            } else {
                raw_bytes.extend_from_slice(&vec![0u8; 512]);
            }

            // Action 2: Fee Action
            raw_bytes.extend_from_slice(&o.action_group.fee_action.cv_fee);
            raw_bytes.extend_from_slice(&o.action_group.fee_action.matcher_fee_zat.to_le_bytes());
            raw_bytes.extend_from_slice(&o.action_group.fee_action.miner_fee_zat.to_le_bytes());
        }

        TransactionV6 {
            header: TX_VERSION_6,
            version_group_id: VERSION_GROUP_ID_V6,
            consensus_branch_id: CONSENSUS_BRANCH_ID_IRONWOOD,
            lock_time: 0,
            expiry_height,
            value_balance_ironwood: 0,
            anchor_ironwood: anchor,
            swap_bundle: bundle,
            raw_tx_bytes: raw_bytes,
        }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.raw_tx_bytes)
    }

    pub fn tx_id(&self) -> [u8; 32] {
        let h = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ZcashTxHashIronw")
            .to_state()
            .update(&self.raw_tx_bytes)
            .finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(h.as_bytes());
        out
    }
}
