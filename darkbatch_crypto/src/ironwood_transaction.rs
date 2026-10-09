//! Consensus transaction construction for the Ironwood pool.
//!
//! This module delegates transaction format, v6 digests, action construction,
//! Halo 2 proof generation, spend authorization, and binding authorization to
//! the official Zcash transaction builder. It deliberately accepts real wallet
//! inputs (notes, their Ironwood Merkle witnesses, and spend-authorizing keys)
//! instead of deriving spends from DarkBatch order intents or recipient IVKs.
//!
//! No seed, viewing key, note, or witness is synthesized here.

use orchard::{
    keys::{FullViewingKey, OutgoingViewingKey, SpendAuthorizingKey},
    tree::{Anchor, MerklePath},
    Address, Note,
};
use rand_core_06::{CryptoRng, RngCore};
use sapling::prover::{OutputProver, SpendProver};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BuildResult, BundlePadding},
    fees::FeeRule,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Parameters},
    memo::MemoBytes,
    value::Zatoshis,
};

/// One real, previously received Ironwood note and its membership witness.
///
/// `note` must be the original Ironwood V3 note reconstructed from the note
/// plaintext and its original rho. `witness` must be a note-tree witness for
/// the same current Ironwood anchor passed to `build_ironwood_transaction`.
pub struct IronwoodSpendInput {
    pub full_viewing_key: FullViewingKey,
    pub note: Note,
    pub witness: MerklePath,
}

/// An Ironwood recipient output. Use `MemoBytes` to enforce canonical memo size.
pub struct IronwoodOutput {
    pub ovk: Option<OutgoingViewingKey>,
    pub recipient: Address,
    pub value: Zatoshis,
    pub memo: MemoBytes,
}

/// Fully serialized transaction produced by the official Zcash v6 transaction builder.
#[derive(Debug, Clone)]
pub struct BuiltIronwoodTransaction {
    pub txid_hex: String,
    pub raw_tx_hex: String,
    pub raw_tx_bytes_len: usize,
    pub target_height: u32,
    pub consensus_branch_id: u32,
    pub transaction_version: u32,
    pub version_group_id: u32,
}

/// Validate transaction-target and required-input invariants before invoking the
/// expensive proving pipeline. Ironwood remains the pool after NU7; the consensus
/// branch is selected from target height, not inferred from the pool name.
fn validate_ironwood_request(
    branch_id: BranchId,
    spend_count: usize,
    output_count: usize,
) -> Result<(), String> {
    if branch_id != BranchId::Nu6_3 && branch_id != BranchId::Nu7 {
        return Err(format!(
            "Refusing Ironwood transaction: unsupported target branch {:?}.",
            branch_id
        ));
    }
    if spend_count == 0 {
        return Err(
            "An Ironwood settlement must include wallet-authorized input notes; output-only synthetic bundles are forbidden."
                .to_owned(),
        );
    }
    if output_count == 0 {
        return Err("An Ironwood transaction requires at least one output.".to_owned());
    }
    Ok(())
}

/// Build and prove a real NU6.3 / Ironwood transaction.
///
/// The caller must supply notes and witnesses obtained from a real wallet/node,
/// a matching spend-authorizing key for every real input, and configured proving
/// implementations. Value conservation and fee sufficiency are checked by the
/// official builder. Excess funds require an explicit change output; insufficient
/// funds are an error. An output-only bundle is rejected before construction.
///
/// This function is deliberately not called by the FBA simulator: the current
/// Python demo wallet has no real Ironwood notes or witnesses to pass here.
pub fn build_ironwood_transaction<P, SP, OP, FR, R>(
    params: P,
    target_height: BlockHeight,
    ironwood_anchor: Anchor,
    spends: Vec<IronwoodSpendInput>,
    outputs: Vec<IronwoodOutput>,
    spend_authorizing_keys: &[SpendAuthorizingKey],
    rng: R,
    spend_prover: &SP,
    output_prover: &OP,
    fee_rule: &FR,
) -> Result<BuiltIronwoodTransaction, String>
where
    P: Parameters,
    SP: SpendProver,
    OP: OutputProver,
    FR: FeeRule,
    R: RngCore + CryptoRng,
    FR::Error: core::fmt::Display,
{
    let branch_id = BranchId::for_height(&params, target_height);
    validate_ironwood_request(branch_id, spends.len(), outputs.len()).map_err(|e| {
        format!("Target height {}: {e}", u32::from(target_height))
    })?;
    let expected_branch_id: u32 = branch_id.into();

    let build_config = BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: None,
        ironwood_anchor: Some(ironwood_anchor),
        orchard_padding: BundlePadding::DEFAULT,
        ironwood_padding: BundlePadding::DEFAULT,
    };
    let mut builder = Builder::new(params, target_height, build_config);

    for input in spends {
        if input.note.version() != orchard::note::NoteVersion::V3 {
            return Err("Ironwood inputs must use NoteVersion::V3.".to_owned());
        }
        builder
            .add_ironwood_spend::<FR::Error>(
                input.full_viewing_key,
                input.note,
                input.witness,
            )
            .map_err(|e| format!("Official Ironwood spend validation failed: {e}"))?;
    }

    for output in outputs {
        builder
            .add_ironwood_output::<FR::Error>(
                output.ovk,
                output.recipient,
                output.value,
                output.memo,
            )
            .map_err(|e| format!("Official Ironwood output construction failed: {e}"))?;
    }

    // No transparent inputs are supported in this shielded-only path. The official
    // builder still accepts a signing set, which is empty for this transaction.
    let built: BuildResult = builder
        .build(
            &Default::default(),
            &[],
            spend_authorizing_keys,
            rng,
            spend_prover,
            output_prover,
            fee_rule,
        )
        .map_err(|e| format!("Official Zcash v6 transaction builder failed: {e}"))?;

    let transaction = built.transaction();
    let mut raw_tx = Vec::new();
    transaction
        .write(&mut raw_tx)
        .map_err(|e| format!("Canonical transaction serialization failed: {e}"))?;

    if raw_tx.len() < 12 {
        return Err("Official transaction builder returned a truncated v6 transaction.".to_owned());
    }

    let header = u32::from_le_bytes(raw_tx[0..4].try_into().unwrap());
    let version_group_id = u32::from_le_bytes(raw_tx[4..8].try_into().unwrap());
    let serialized_branch_id = u32::from_le_bytes(raw_tx[8..12].try_into().unwrap());
    if header != 0x8000_0006
        || version_group_id != 0xD884_B698
        || serialized_branch_id != expected_branch_id
    {
        return Err(format!(
            "Official builder output failed v6/Ironwood header assertions: header={header:#010x}, version_group_id={version_group_id:#010x}, expected_branch_id={expected_branch_id:#010x}, branch_id={serialized_branch_id:#010x}."
        ));
    }

    let txid_hex = hex::encode(transaction.txid().as_ref());
    Ok(BuiltIronwoodTransaction {
        txid_hex,
        raw_tx_hex: hex::encode(&raw_tx),
        raw_tx_bytes_len: raw_tx.len(),
        target_height: u32::from(target_height),
        consensus_branch_id: serialized_branch_id,
        transaction_version: 6,
        version_group_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ironwood_request_validation_supports_nu6_3_and_nu7_but_requires_real_spends() {
        assert_eq!(u32::from(BranchId::Nu6_3), 0x37A5_165B_u32);
        assert_eq!(u32::from(BranchId::Nu7), 0x7719_0AD9_u32);

        assert!(validate_ironwood_request(BranchId::Nu6_3, 1, 1).is_ok());
        assert!(validate_ironwood_request(BranchId::Nu7, 1, 1).is_ok());
        assert!(validate_ironwood_request(BranchId::Nu6_2, 1, 1).is_err());
        assert!(validate_ironwood_request(BranchId::Nu6_3, 0, 1).is_err());
        assert!(validate_ironwood_request(BranchId::Nu7, 1, 0).is_err());
    }
}
