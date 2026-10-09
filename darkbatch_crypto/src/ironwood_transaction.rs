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
use rand::Rng;
use rand_core::CryptoRng;
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
#[derive(Clone)]
pub struct IronwoodSpendInput {
    pub full_viewing_key: FullViewingKey,
    pub note: Note,
    pub witness: MerklePath,
}

/// An Ironwood recipient output. Use `MemoBytes` to enforce canonical memo size.
#[derive(Clone)]
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
    R: Rng + CryptoRng,
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


/// Untrusted JSON envelope accepted by the local transaction-building CLI.
/// Secret keys are read from stdin, never from command-line arguments or logs.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IronwoodBuildRequest {
    network: String,
    target_height: u32,
    ironwood_anchor_hex: String,
    spends: Vec<IronwoodSpendRequest>,
    outputs: Vec<IronwoodOutputRequest>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IronwoodSpendRequest {
    /// Raw protocol SpendingKey bytes from a real Ironwood-capable wallet.
    spending_key_hex: String,
    /// Raw 43-byte address of the note being spent, decoded by the wallet scanner.
    note_address_raw_hex: String,
    value_zat: u64,
    nullifier_hex: String,
    rho_hex: String,
    rseed_hex: String,
    witness_position: u32,
    /// Exactly 32 canonical MerkleHashOrchard nodes, leaf-to-root order.
    witness_auth_path_hex: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IronwoodOutputRequest {
    /// Standard Testnet Unified Address. Must contain an Orchard-protocol receiver.
    #[serde(default)]
    recipient_address: Option<String>,
    /// Optional raw 43-byte receiver encoding for trusted wallet integrations.
    #[serde(default)]
    recipient_address_raw_hex: Option<String>,
    value_zat: u64,
    #[serde(default)]
    memo_hex: String,
    #[serde(default)]
    ovk_hex: Option<String>,
}

fn parse_fixed_hex<const N: usize>(hex_value: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(hex_value)
        .map_err(|_| format!("{field} must be valid hexadecimal."))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!("{field} must be exactly {} bytes; got {}.", N, bytes.len())
    })
}

/// Builds a fully-authorized v6 Ironwood transaction from real wallet inputs.
///
/// Input data must come from an Ironwood-capable wallet scanner and current Zebra
/// tree state. This method will not derive fake notes, witnesses, roots, or keys.
/// It uses the official zcash_primitives transaction builder; the returned txid and
/// raw transaction are generated from that same authorized transaction object.
pub fn build_ironwood_transaction_from_json(
    input_json: &str,
) -> Result<BuiltIronwoodTransaction, String> {
    use orchard::{
        keys::{Diversifier, FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
        note::{ExtractedNoteCommitment, Note, NoteVersion, Rho, RandomSeed},
        tree::{MerkleHashOrchard, MerklePath},
        value::NoteValue,
        Address,
    };
    use zcash_protocol::{
        consensus::{BlockHeight, Network},
        memo::MemoBytes,
        value::Zatoshis,
    };

    let request: IronwoodBuildRequest = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid build request JSON: {e}"))?;

    // The initial wallet integration is deliberately testnet-only.
    if request.network != "testnet" {
        return Err("Only network='testnet' is enabled in this initial real-transaction path; mainnet build is deliberately disabled.".into());
    }
    if request.target_height < 4_134_000 {
        return Err("Target height is before NU6.3 Testnet activation (4,134,000).".into());
    }
    if request.spends.is_empty() {
        return Err("At least one real wallet-authorized Ironwood note is required.".into());
    }
    if request.outputs.is_empty() {
        return Err("At least one Ironwood output is required.".into());
    }
    if request.spends.len() > 64 || request.outputs.len() > 64 {
        return Err("This CLI accepts at most 64 spends and 64 outputs per transaction.".into());
    }

    let anchor_bytes = parse_fixed_hex::<32>(&request.ironwood_anchor_hex, "ironwood_anchor_hex")?;
    let anchor = Anchor::from_bytes(anchor_bytes)
        .into_option()
        .ok_or_else(|| "Ironwood anchor is not a canonical field encoding.".to_owned())?;

    // This local wallet builder is a single-wallet operation. Cooperative FBA
    // settlement must use PCZT and per-party signatures; it must not collect multiple
    // traders' spending keys in the coordinator.
    let first_key = parse_fixed_hex::<32>(
        &request.spends[0].spending_key_hex,
        "spends[0].spending_key_hex",
    )?;
    if request.spends.iter().enumerate().any(|(index, spend)| {
        parse_fixed_hex::<32>(&spend.spending_key_hex, &format!("spends[{index}].spending_key_hex"))
            .map(|key| key != first_key)
            .unwrap_or(true)
    }) {
        return Err("This local wallet CLI accepts notes from one wallet only. Multi-party DarkBatch settlement must use the PCZT collaborative-signing path; never collect traders' keys in the coordinator.".into());
    }

    let mut spends = Vec::with_capacity(request.spends.len());
    let mut spend_authorizing_keys = Vec::with_capacity(request.spends.len());
    let mut total_input_value_zat: u64 = 0;

    for (index, spend_request) in request.spends.into_iter().enumerate() {
        let label = format!("spends[{index}]");
        let spending_key_bytes =
            parse_fixed_hex::<32>(&spend_request.spending_key_hex, &format!("{label}.spending_key_hex"))?;
        let spending_key = SpendingKey::from_bytes(spending_key_bytes)
            .into_option()
            .ok_or_else(|| format!("{label}: invalid raw Ironwood spending key."))?;

        let raw_note_address =
            parse_fixed_hex::<43>(&spend_request.note_address_raw_hex, &format!("{label}.note_address_raw_hex"))?;
        let note_address = Address::from_raw_address_bytes(&raw_note_address)
            .into_option()
            .ok_or_else(|| format!("{label}: invalid raw 43-byte Ironwood note address."))?;

        let rho_bytes = parse_fixed_hex::<32>(&spend_request.rho_hex, &format!("{label}.rho_hex"))?;
        let rho = Rho::from_bytes(&rho_bytes)
            .into_option()
            .ok_or_else(|| format!("{label}: invalid note rho encoding."))?;
        let rseed_bytes = parse_fixed_hex::<32>(&spend_request.rseed_hex, &format!("{label}.rseed_hex"))?;
        let rseed = RandomSeed::from_bytes(rseed_bytes, &rho)
            .into_option()
            .ok_or_else(|| format!("{label}: rseed does not correspond to the supplied rho."))?;

        let note_value = Zatoshis::from_u64(spend_request.value_zat)
            .map_err(|e| format!("{label}: note value is outside MAX_MONEY: {e}"))?;
        if note_value.is_zero() {
            return Err(format!("{label}: zero-value notes are not spendable inputs."));
        }
        total_input_value_zat = total_input_value_zat
            .checked_add(note_value.into_u64())
            .ok_or_else(|| "Input value sum overflow.".to_owned())?;

        let note = Note::from_parts(
            note_address,
            NoteValue::from_raw(note_value.into_u64()),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .into_option()
        .ok_or_else(|| format!("{label}: failed to reconstruct the Ironwood V3 note."))?;

        if spend_request.witness_auth_path_hex.len() != 32 {
            return Err(format!("{label}.witness_auth_path_hex must contain exactly 32 Merkle nodes."));
        }
        let mut auth_nodes = Vec::with_capacity(32);
        for (level, encoded_node) in spend_request.witness_auth_path_hex.iter().enumerate() {
            let node_bytes = parse_fixed_hex::<32>(
                encoded_node,
                &format!("{label}.witness_auth_path_hex[{level}]"),
            )?;
            auth_nodes.push(
                MerkleHashOrchard::from_bytes(&node_bytes)
                    .into_option()
                    .ok_or_else(|| format!("{label}: Merkle path node {level} is not canonical."))?,
            );
        }
        let auth_path: [MerkleHashOrchard; 32] = auth_nodes
            .try_into()
            .map_err(|_| format!("{label}: Merkle path must have exactly 32 nodes."))?;
        let witness = MerklePath::from_parts(spend_request.witness_position, auth_path);

        let cmx = ExtractedNoteCommitment::from(note.commitment());
        if witness.root(cmx) != anchor {
            return Err(format!(
                "{label}: witness root does not equal ironwood_anchor_hex. Refresh the witness and anchor from the same Zebra treestate."
            ));
        }

        let fvk = FullViewingKey::from(&spending_key);
        if fvk.scope_for_address(&note_address).is_none() {
            return Err(format!(
                "{label}: the supplied spending key does not control this note's receiver."
            ));
        }
        let expected_nullifier = hex::encode(note.nullifier(&fvk).to_bytes());
        if expected_nullifier != spend_request.nullifier_hex.to_lowercase() {
            return Err(format!(
                "{label}: the derived nullifier does not match the synchronized wallet record."
            ));
        }
        spend_authorizing_keys.push(SpendAuthorizingKey::from(&spending_key));
        spends.push(IronwoodSpendInput {
            full_viewing_key: fvk,
            note,
            witness,
        });
    }

    let mut outputs = Vec::with_capacity(request.outputs.len());
    let mut requested_output_value_zat: u64 = 0;
    for (index, output_request) in request.outputs.into_iter().enumerate() {
        let label = format!("outputs[{index}]");
        let has_unified = output_request.recipient_address.as_deref().is_some_and(|s| !s.trim().is_empty());
        let has_raw = output_request.recipient_address_raw_hex.as_deref().is_some_and(|s| !s.trim().is_empty());
        if has_unified == has_raw {
            return Err(format!("{label}: provide exactly one of recipient_address (Testnet Unified Address) or recipient_address_raw_hex."));
        }
        let raw_recipient = if has_unified {
            let encoded = output_request.recipient_address.as_deref().unwrap().trim();
            let decoded = zcash_keys::address::Address::decode(&Network::TestNetwork, encoded)
                .ok_or_else(|| format!("{label}: recipient_address is invalid or belongs to another network."))?;
            let orchard_receiver = decoded
                .as_understood_unified_receivers()
                .into_iter()
                .find_map(|receiver| match receiver {
                    zcash_keys::address::Receiver::Orchard(address) => Some(address),
                    _ => None,
                })
                .ok_or_else(|| format!("{label}: Testnet Unified Address has no valid Orchard-protocol receiver for Ironwood."))?;
            orchard_receiver.to_raw_address_bytes()
        } else {
            parse_fixed_hex::<43>(
                output_request.recipient_address_raw_hex.as_deref().unwrap(),
                &format!("{label}.recipient_address_raw_hex"),
            )?
        };
        let recipient = Address::from_raw_address_bytes(&raw_recipient)
            .into_option()
            .ok_or_else(|| format!("{label}: invalid raw Ironwood recipient address."))?;
        let value = Zatoshis::from_u64(output_request.value_zat)
            .map_err(|e| format!("{label}: output value is outside MAX_MONEY: {e}"))?;
        if value.is_zero() {
            return Err(format!("{label}: output value must be greater than zero."));
        }
        requested_output_value_zat = requested_output_value_zat
            .checked_add(value.into_u64())
            .ok_or_else(|| "Requested output value sum overflow.".to_owned())?;

        let memo_bytes = if output_request.memo_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(&output_request.memo_hex)
                .map_err(|_| format!("{label}.memo_hex must be valid hexadecimal."))?
        };
        let memo = MemoBytes::from_bytes(&memo_bytes)
            .map_err(|e| format!("{label}: memo is invalid or exceeds 512 bytes: {e}"))?;

        let ovk = output_request
            .ovk_hex
            .as_deref()
            .map(|raw| {
                parse_fixed_hex::<32>(raw, &format!("{label}.ovk_hex"))
                    .map(OutgoingViewingKey::from)
            })
            .transpose()?;

        outputs.push(IronwoodOutput {
            ovk,
            recipient,
            value,
            memo,
        });
    }
    if total_input_value_zat <= requested_output_value_zat {
        return Err(format!(
            "Inputs total {} zatoshis must exceed requested outputs total {} zatoshis so the network fee can be paid.",
            total_input_value_zat, requested_output_value_zat
        ));
    }

    // All inputs belong to the same wallet (enforced above), so remaining value is
    // returned to its internal Ironwood address. Iterate to a stable change amount
    // because adding a change output can change ZIP-317 action count and fee.
    let spending_key = SpendingKey::from_bytes(first_key)
        .into_option()
        .ok_or_else(|| "Invalid wallet spending key.".to_owned())?;
    let fvk = FullViewingKey::from(&spending_key);
    let change_recipient = fvk.address_at(0u32, Scope::Internal);
    let change_ovk = fvk.to_ovk(Scope::Internal);
    let mut change_zat = total_input_value_zat - requested_output_value_zat;

    let fee_rule = zcash_primitives::transaction::fees::zip317::FeeRule::standard();
    let mut stable_builder = None;
    for _ in 0..8 {
        let mut builder = Builder::new(
            Network::TestNetwork,
            BlockHeight::from_u32(request.target_height),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        for input in spends.iter().cloned() {
            builder
                .add_ironwood_spend::<std::convert::Infallible>(
                    input.full_viewing_key,
                    input.note,
                    input.witness,
                )
                .map_err(|e| format!("Official Ironwood spend validation failed: {e}"))?;
        }
        for output in outputs.iter().cloned() {
            builder
                .add_ironwood_output::<std::convert::Infallible>(
                    output.ovk,
                    output.recipient,
                    output.value,
                    output.memo,
                )
                .map_err(|e| format!("Official Ironwood output construction failed: {e}"))?;
        }
        if change_zat > 0 {
            let change = Zatoshis::from_u64(change_zat)
                .map_err(|e| format!("Calculated change is outside MAX_MONEY: {e}"))?;
            builder
                .add_ironwood_output::<std::convert::Infallible>(
                    Some(change_ovk.clone()),
                    change_recipient,
                    change,
                    MemoBytes::empty(),
                )
                .map_err(|e| format!("Could not add wallet change output: {e}"))?;
        }

        let fee = builder
            .get_fee(&fee_rule)
            .map_err(|e| format!("Could not calculate ZIP-317 fee: {e}"))?
            .into_u64();
        let required = requested_output_value_zat
            .checked_add(fee)
            .ok_or_else(|| "Output plus fee value overflow.".to_owned())?;
        if total_input_value_zat < required {
            return Err(format!(
                "Insufficient funds: inputs={} zat, requested outputs={} zat, ZIP-317 fee={} zat.",
                total_input_value_zat, requested_output_value_zat, fee
            ));
        }
        let new_change = total_input_value_zat - required;
        if new_change == change_zat {
            stable_builder = Some(builder);
            break;
        }
        change_zat = new_change;
    }
    let builder = stable_builder.ok_or_else(|| {
        "Could not converge on a stable ZIP-317 change amount; refusing to build.".to_owned()
    })?;

    let prover = zcash_proofs::prover::LocalTxProver::bundled();
    let built = builder
        .build(
            &Default::default(),
            &[],
            &spend_authorizing_keys,
            rand::rng(),
            &prover,
            &prover,
            &fee_rule,
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
    let expected_branch_id = BranchId::for_height(&Network::TestNetwork, BlockHeight::from_u32(request.target_height));
    let expected_branch_id: u32 = expected_branch_id.into();
    if header != 0x8000_0006
        || version_group_id != 0xD884_B698
        || serialized_branch_id != expected_branch_id
    {
        return Err(format!(
            "Official builder output failed v6/Ironwood header assertions: header={header:#010x}, version_group_id={version_group_id:#010x}, expected_branch_id={expected_branch_id:#010x}, branch_id={serialized_branch_id:#010x}."
        ));
    }

    // Use the canonical display encoding. TxId::as_ref() exposes digest bytes,
    // while Display/to_string() emits the byte-reversed txid hex expected by Zebra RPC.
    let txid_hex = transaction.txid().to_string().to_lowercase();
    Ok(BuiltIronwoodTransaction {
        txid_hex,
        raw_tx_hex: hex::encode(&raw_tx),
        raw_tx_bytes_len: raw_tx.len(),
        target_height: u32::from(BlockHeight::from_u32(request.target_height)),
        consensus_branch_id: serialized_branch_id,
        transaction_version: 6,
        version_group_id,
    })
}
