//! Official Zcash V6 / NU6.3 transaction construction for local settlement agents.
//!
//! This module replaces transaction-shaped byte assembly with the official
//! zcash_primitives Builder -> PCZT -> participant signing -> Halo 2 proof ->
//! Transaction extraction flow. The build JSON and intermediate PCZT contain sensitive
//! note data and viewing-key material; keep them on a trusted local machine. Spending keys
//! are loaded only by the local signing command, never by the DarkBatch API.
use std::fs;

use orchard::{
    keys::{Diversifier, FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Address,
};
use pczt::{
    Pczt,
    roles::{
        combiner::Combiner,
        creator::Creator,
        io_finalizer::IoFinalizer,
        prover::Prover,
        signer::Signer,
        tx_extractor::TransactionExtractor,
    },
};
use serde::{Deserialize, Serialize};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    memo::MemoBytes,
    value::Zatoshis,
};

const TESTNET_NU6_3_HEIGHT: u32 = 4_134_000;
const TESTNET_NU7_HEIGHT: u32 = 4_465_026;
const TESTNET_NU6_3_BRANCH_ID: u32 = 0x37A5_165B;
const TESTNET_NU7_BRANCH_ID: u32 = 0x7719_0AD9;

#[derive(Debug, Deserialize)]
pub struct PcztBuildRequest {
    pub target_height: u32,
    pub ironwood_anchor_hex: String,
    pub inputs: Vec<PcztSpendInput>,
    pub outputs: Vec<PcztRecipient>,
    /// Explicit per-owner change outputs are required for multi-participant settlements.
    /// Each change note must return to the FVK that owned the corresponding input note.
    #[serde(default)]
    pub change_outputs: Vec<PcztChangeOutput>,
    /// Legacy single-owner change fallback. Must match the one input owner when change_outputs is empty.
    #[serde(default)]
    pub change_fvk_hex: String,
    #[serde(default)]
    pub change_address_raw_hex: String,
}
#[derive(Debug, Deserialize)]
pub struct PcztSpendInput {
    /// Serialized FullViewingKey (96 bytes). This file is private input to the local builder.
    pub fvk_hex: String,
    /// Raw 43-byte receiver address for this decrypted note.
    pub raw_address_hex: String,
    pub value_zat: u64,
    pub rho_hex: String,
    pub rseed_hex: String,
    pub merkle_position: u32,
    /// Exactly 32 path siblings, each a 32-byte hex string.
    pub merkle_path_hex: Vec<String>,
}
#[derive(Debug, Deserialize)]
pub struct PcztRecipient {
    pub address_raw_hex: String,
    pub value_zat: u64,
    /// Hex memo plaintext of 0..=512 bytes.
    #[serde(default)]
    pub memo_hex: String,
}
#[derive(Debug, Deserialize)]
pub struct PcztChangeOutput {
    /// FullViewingKey belonging to the input owner receiving this change.
    pub fvk_hex: String,
    pub address_raw_hex: String,
    /// Explicit change value for generic PCZT builds. Use null for FBA auto-allocation.
    pub value_zat: Option<u64>,
    /// Amount of the owner's input ZEC committed to buyer fills in an FBA build.
    #[serde(default)]
    pub seller_fill_zat: u64,
    /// Optional encrypted receipt memo for the seller's change output.
    #[serde(default)]
    pub memo_hex: String,
}
#[derive(Clone)]
struct PreparedSpend {
    fvk: FullViewingKey,
    note: Note,
    path: MerklePath,
    value_zat: u64,
}
#[derive(Clone)]
struct PreparedOutput {
    address: Address,
    value_zat: u64,
    memo: Vec<u8>,
}
#[derive(Clone)]
struct PreparedChange {
    fvk: FullViewingKey,
    address: Address,
    value_zat: Option<u64>,
    seller_fill_zat: u64,
    memo: Vec<u8>,
}
fn ensure_fvk_owns_address(fvk: &FullViewingKey, raw_address: &[u8; 43], field: &str) -> Result<(), String> {
    let diversifier_bytes: [u8; 11] = raw_address[..11].try_into()
        .map_err(|_| format!("{field}: address diversifier has invalid size"))?;
    let external = fvk.address(Diversifier::from_bytes(diversifier_bytes), Scope::External).to_raw_address_bytes();
    let internal = fvk.address(Diversifier::from_bytes(diversifier_bytes), Scope::Internal).to_raw_address_bytes();
    if external != *raw_address && internal != *raw_address {
        return Err(format!("{field} does not belong to the supplied FullViewingKey"));
    }
    Ok(())
}
#[derive(Debug, Clone, Serialize)]
pub struct PcztBuildReport {
    pub status: String,
    pub network: String,
    pub target_height: u32,
    pub expiry_height: u32,
    pub consensus_branch_id: String,
    pub ironwood_anchor_hex: String,
    pub input_count: usize,
    pub recipient_output_count: usize,
    pub input_total_zat: u64,
    pub recipient_total_zat: u64,
    pub fee_zat: u64,
    pub change_zat: u64,
    pub change_output_count: usize,
    pub seller_fill_total_zat: u64,
    pub ironwood_spend_action_indexes: Vec<usize>,
    pub pczt_bytes_len: usize,
    pub broadcast_ready: bool,
    pub warning: String,
}

fn decode_array<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value.trim()).map_err(|e| format!("{field} is not valid hex: {e}"))?;
    bytes.try_into().map_err(|v: Vec<u8>| format!("{field} must be exactly {N} bytes; got {}", v.len()))
}
fn zatoshis(value: u64, field: &str) -> Result<Zatoshis, String> {
    if value == 0 {
        return Err(format!("{field} must be greater than zero"));
    }
    Zatoshis::from_u64(value).map_err(|_| format!("{field} exceeds the Zcash monetary range"))
}
fn memo_bytes(bytes: &[u8]) -> Result<MemoBytes, String> {
    if bytes.is_empty() { Ok(MemoBytes::empty()) }
    else { MemoBytes::from_bytes(bytes).map_err(|e| format!("invalid memo bytes: {e}")) }
}
fn prepare_spend(input: &PcztSpendInput, anchor: Anchor) -> Result<PreparedSpend, String> {
    if input.merkle_path_hex.len() != 32 {
        return Err(format!("each Ironwood witness must have 32 siblings; got {}", input.merkle_path_hex.len()));
    }
    zatoshis(input.value_zat, "input value_zat")?;
    let fvk_bytes = decode_array::<96>(&input.fvk_hex, "input.fvk_hex")?;
    let fvk = FullViewingKey::from_bytes(&fvk_bytes)
        .ok_or_else(|| "input.fvk_hex is not a valid Zcash FullViewingKey".to_string())?;
    let address_bytes = decode_array::<43>(&input.raw_address_hex, "input.raw_address_hex")?;
    let address = Address::from_raw_address_bytes(&address_bytes).into_option()
        .ok_or_else(|| "input.raw_address_hex is not a valid raw Ironwood address".to_string())?;
    ensure_fvk_owns_address(&fvk, &address_bytes, "input.raw_address_hex")?;
    let rho_bytes = decode_array::<32>(&input.rho_hex, "input.rho_hex")?;
    let rho = Rho::from_bytes(&rho_bytes).into_option()
        .ok_or_else(|| "input.rho_hex is not a canonical Orchard rho".to_string())?;
    let rseed_bytes = decode_array::<32>(&input.rseed_hex, "input.rseed_hex")?;
    let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).into_option()
        .ok_or_else(|| "input.rseed_hex is not a valid rseed for this rho".to_string())?;
    let note = Note::from_parts(address, NoteValue::from_raw(input.value_zat), rho, rseed, NoteVersion::V3)
        .into_option().ok_or_else(|| "could not construct supplied Ironwood note".to_string())?;

    let mut siblings = Vec::with_capacity(32);
    for (i, sibling_hex) in input.merkle_path_hex.iter().enumerate() {
        let bytes = decode_array::<32>(sibling_hex, &format!("merkle_path_hex[{i}]"))?;
        siblings.push(MerkleHashOrchard::from_bytes(&bytes).into_option()
            .ok_or_else(|| format!("merkle_path_hex[{i}] is not a canonical Merkle node"))?);
    }
    let siblings: [MerkleHashOrchard; 32] = siblings.try_into()
        .map_err(|v: Vec<MerkleHashOrchard>| format!("invalid witness length: {}", v.len()))?;
    let path = MerklePath::from_parts(input.merkle_position, siblings);
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    if path.root(cmx).to_bytes() != anchor.to_bytes() {
        return Err("Merkle witness does not resolve to ironwood_anchor_hex; refusing to build PCZT".into());
    }
    Ok(PreparedSpend { fvk, note, path, value_zat: input.value_zat })
}
fn prepare_output(output: &PcztRecipient, index: usize) -> Result<PreparedOutput, String> {
    let bytes = decode_array::<43>(&output.address_raw_hex, &format!("outputs[{index}].address_raw_hex"))?;
    let address = Address::from_raw_address_bytes(&bytes).into_option()
        .ok_or_else(|| format!("outputs[{index}] is not a valid Ironwood address"))?;
    zatoshis(output.value_zat, &format!("outputs[{index}].value_zat"))?;
    let memo = if output.memo_hex.trim().is_empty() { Vec::new() } else {
        let bytes = hex::decode(output.memo_hex.trim())
            .map_err(|e| format!("outputs[{index}].memo_hex is invalid hex: {e}"))?;
        if bytes.len() > 512 { return Err(format!("outputs[{index}].memo_hex exceeds 512 bytes")); }
        bytes
    };
    Ok(PreparedOutput { address, value_zat: output.value_zat, memo })
}

fn allocate_pro_rata(total: u64, weights: &[u64]) -> Result<Vec<u64>, String> {
    if weights.is_empty() {
        return Err("cannot allocate fee without change owners".into());
    }
    let weight_total = weights.iter().try_fold(0u128, |sum, weight| sum.checked_add(*weight as u128)
        .ok_or_else(|| "allocation weight sum overflowed".to_string()))?;
    if weight_total == 0 {
        return Err("cannot allocate fee across zero residual value".into());
    }
    let mut shares = Vec::with_capacity(weights.len());
    let mut remainders = Vec::with_capacity(weights.len());
    let mut assigned = 0u64;
    for (index, weight) in weights.iter().enumerate() {
        let numerator = (total as u128).checked_mul(*weight as u128)
            .ok_or_else(|| "fee allocation multiplication overflowed".to_string())?;
        let base = (numerator / weight_total) as u64;
        shares.push(base);
        remainders.push((index, numerator % weight_total));
        assigned = assigned.checked_add(base).ok_or_else(|| "fee allocation sum overflowed".to_string())?;
    }
    let remaining = total.checked_sub(assigned).ok_or_else(|| "fee allocation rounding error".to_string())? as usize;
    remainders.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if remaining > remainders.len() {
        return Err("fee allocation remainder exceeded owner count".into());
    }
    for (index, _) in remainders.into_iter().take(remaining) {
        shares[index] += 1;
    }
    Ok(shares)
}

fn build_pczt(request: &PcztBuildRequest) -> Result<(Pczt, PcztBuildReport), String> {
    if request.target_height < TESTNET_NU6_3_HEIGHT {
        return Err(format!("target_height must be >= Testnet NU6.3 activation height {TESTNET_NU6_3_HEIGHT}"));
    }
    let target = BlockHeight::from_u32(request.target_height);
    let branch_id = BranchId::for_height(&Network::TestNetwork, target);
    let branch_id_u32 = u32::from(branch_id);
    let expected_branch_id = if request.target_height >= TESTNET_NU7_HEIGHT {
        TESTNET_NU7_BRANCH_ID
    } else {
        TESTNET_NU6_3_BRANCH_ID
    };
    if branch_id_u32 != expected_branch_id
        || !matches!(branch_id_u32, TESTNET_NU6_3_BRANCH_ID | TESTNET_NU7_BRANCH_ID)
    {
        return Err(format!(
            "target_height {} selects unsupported Testnet consensus branch 0x{branch_id_u32:08x}",
            request.target_height,
        ));
    }
    if request.inputs.is_empty() || request.outputs.is_empty() {
        return Err("at least one real spend input and recipient output are required".into());
    }
    let anchor_bytes = decode_array::<32>(&request.ironwood_anchor_hex, "ironwood_anchor_hex")?;
    let anchor = Anchor::from_bytes(anchor_bytes).into_option()
        .ok_or_else(|| "ironwood_anchor_hex is not a canonical Orchard anchor".to_string())?;
    let spends: Vec<PreparedSpend> = request.inputs.iter().map(|i| prepare_spend(i, anchor)).collect::<Result<_,_>>()?;
    let outputs: Vec<PreparedOutput> = request.outputs.iter().enumerate().map(|(i,o)| prepare_output(o,i)).collect::<Result<_,_>>()?;
    let mut change_templates: Vec<PreparedChange> = Vec::new();
    if !request.change_outputs.is_empty() {
        for (index, change) in request.change_outputs.iter().enumerate() {
            let fvk_bytes = decode_array::<96>(&change.fvk_hex, &format!("change_outputs[{index}].fvk_hex"))?;
            let fvk = FullViewingKey::from_bytes(&fvk_bytes)
                .ok_or_else(|| format!("change_outputs[{index}].fvk_hex is not a valid FullViewingKey"))?;
            if !spends.iter().any(|spend| spend.fvk.to_bytes() == fvk.to_bytes()) {
                return Err(format!("change_outputs[{index}] belongs to no owner of an input note"));
            }
            let address_bytes = decode_array::<43>(&change.address_raw_hex, &format!("change_outputs[{index}].address_raw_hex"))?;
            let address = Address::from_raw_address_bytes(&address_bytes).into_option()
                .ok_or_else(|| format!("change_outputs[{index}] has an invalid Ironwood address"))?;
            ensure_fvk_owns_address(&fvk, &address_bytes, &format!("change_outputs[{index}].address_raw_hex"))?;
            if let Some(value) = change.value_zat {
                zatoshis(value, &format!("change_outputs[{index}].value_zat"))?;
            }
            let memo = if change.memo_hex.trim().is_empty() {
                Vec::new()
            } else {
                let bytes = hex::decode(change.memo_hex.trim())
                    .map_err(|e| format!("change_outputs[{index}].memo_hex is invalid hex: {e}"))?;
                if bytes.len() > 512 {
                    return Err(format!("change_outputs[{index}].memo_hex exceeds 512 bytes"));
                }
                bytes
            };
            change_templates.push(PreparedChange {
                fvk, address, value_zat: change.value_zat,
                seller_fill_zat: change.seller_fill_zat, memo,
            });
        }
    } else {
        // A shared change output is only safe for a single distinct input owner.
        let mut owners: Vec<[u8; 96]> = spends.iter().map(|spend| spend.fvk.to_bytes()).collect();
        owners.sort();
        owners.dedup();
        if owners.len() != 1 {
            return Err("multi-owner settlement requires change_outputs with one change output per owner; refusing to send seller change to a shared wallet".into());
        }
        let fvk_bytes = decode_array::<96>(&request.change_fvk_hex, "change_fvk_hex")?;
        let fvk = FullViewingKey::from_bytes(&fvk_bytes)
            .ok_or_else(|| "change_fvk_hex is not a valid FullViewingKey".to_string())?;
        if fvk.to_bytes() != owners[0] {
            return Err("single-owner change_fvk_hex must match the owner of the input note".into());
        }
        let address_bytes = decode_array::<43>(&request.change_address_raw_hex, "change_address_raw_hex")?;
        let address = Address::from_raw_address_bytes(&address_bytes).into_option()
            .ok_or_else(|| "change_address_raw_hex is not a valid Ironwood address".to_string())?;
        ensure_fvk_owns_address(&fvk, &address_bytes, "change_address_raw_hex")?;
        change_templates.push(PreparedChange { fvk, address, value_zat: None, seller_fill_zat: 0, memo: Vec::new() });
    }
    let input_total = spends.iter().try_fold(0u64, |sum, input| sum.checked_add(input.value_zat).ok_or_else(|| "input sum overflowed".to_string()))?;
    let output_total = outputs.iter().try_fold(0u64, |sum, output| sum.checked_add(output.value_zat).ok_or_else(|| "output sum overflowed".to_string()))?;
    zatoshis(input_total, "input total")?;
    zatoshis(output_total, "recipient output total")?;

    // Probe and final transaction use identical action counts. For multiple input owners,
    // every change output remains with its original owner; no common-wallet fallback is allowed.
    macro_rules! make_builder {
        ($change_values:expr) => {{
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
            for input in &spends {
                builder.add_ironwood_spend::<zip317::FeeRule>(input.fvk.clone(), input.note.clone(), input.path.clone())
                    .map_err(|e| format!("invalid Ironwood input: {e:?}"))?;
            }
            for output in &outputs {
                builder.add_ironwood_output::<zip317::FeeRule>(None, output.address.clone(), zatoshis(output.value_zat, "recipient amount")?, memo_bytes(&output.memo)?)
                    .map_err(|e| format!("invalid Ironwood recipient: {e:?}"))?;
            }
            for (i, change_output) in change_templates.iter().enumerate() {
                let amount = $change_values[i];
                builder.add_ironwood_output::<zip317::FeeRule>(
                    Some(change_output.fvk.to_ovk(Scope::Internal)),
                    change_output.address.clone(),
                    zatoshis(amount, &format!("change_outputs[{i}].value_zat"))?,
                    memo_bytes(&change_output.memo)?,
                ).map_err(|e| format!("invalid Ironwood change output: {e:?}"))?;
            }
            builder
        }};
    }

    let probe_change_values = vec![1u64; change_templates.len()];
    let fee = make_builder!(&probe_change_values).get_fee(&zip317::FeeRule::standard())
        .map_err(|e| format!("ZIP 317 fee calculation failed: {e:?}"))?.into_u64();
    let change_total = input_total.checked_sub(output_total.checked_add(fee).ok_or_else(|| "fee sum overflowed".to_string())?)
        .ok_or_else(|| format!("insufficient input: {input_total} zat in, {output_total} zat to recipients, ZIP 317 fee {fee} zat"))?;
    if change_total == 0 { return Err("change output would be zero; adjust inputs or recipient values".into()); }

    let fba_auto_change = !request.change_outputs.is_empty()
        && change_templates.iter().all(|change| change.value_zat.is_none());

    let change_values: Vec<u64> = if fba_auto_change {
        // This mode is used for FBA fills: each buyer output is funded by an explicit amount
        // sold by input owners. Fee shares are then allocated over each owner's residual value,
        // and the remaining change returns to that same owner.
        let mut owner_inputs: std::collections::BTreeMap<[u8; 96], u64> = std::collections::BTreeMap::new();
        for spend in &spends {
            let owner = spend.fvk.to_bytes();
            let next = owner_inputs.get(&owner).copied().unwrap_or(0u64)
                .checked_add(spend.value_zat).ok_or_else(|| "per-owner input sum overflowed".to_string())?;
            owner_inputs.insert(owner, next);
        }
        let mut seen_change_owners = std::collections::BTreeSet::new();
        let mut weights = Vec::with_capacity(change_templates.len());
        let mut seller_fill_total = 0u64;
        for change in &change_templates {
            let owner = change.fvk.to_bytes();
            if !seen_change_owners.insert(owner) {
                return Err("FBA PCZT requires exactly one change allocation per input owner".into());
            }
            let owner_input = owner_inputs.get(&owner).copied()
                .ok_or_else(|| "change owner has no corresponding spend input".to_string())?;
            seller_fill_total = seller_fill_total.checked_add(change.seller_fill_zat)
                .ok_or_else(|| "sum of seller fills overflowed".to_string())?;
            if change.seller_fill_zat > owner_input {
                return Err("an owner's seller fills exceed that owner's supplied inputs".into());
            }
            weights.push(owner_input - change.seller_fill_zat);
        }
        if seen_change_owners.len() != owner_inputs.len() {
            return Err("FBA PCZT needs a change allocation for every input owner".into());
        }
        if seller_fill_total != output_total {
            return Err(format!(
                "FBA buy outputs total {output_total} zat but seller fills total {seller_fill_total} zat; refusing unbalanced batch"
            ));
        }
        let weights_total = weights.iter().try_fold(0u64, |total, value| total.checked_add(*value)
            .ok_or_else(|| "per-owner residual sum overflowed".to_string()))?;
        if weights_total != input_total - output_total {
            return Err("per-owner residual allocation does not match input minus recipient outputs".into());
        }
        let fee_shares = allocate_pro_rata(fee, &weights)?;
        let mut values = Vec::with_capacity(weights.len());
        for (i, (weight, fee_share)) in weights.iter().zip(fee_shares.iter()).enumerate() {
            let value = weight.checked_sub(*fee_share)
                .ok_or_else(|| format!("owner {i} cannot cover their allocated network fee"))?;
            if value == 0 {
                return Err(format!("owner {i} has no positive change after seller fill and ZIP 317 fee; use different input notes"));
            }
            values.push(value);
        }
        values
    } else if change_templates.iter().all(|change| change.value_zat.is_none()) {
        if change_templates.len() != 1 {
            return Err("automatic change calculation is supported only for a single-owner transaction".into());
        }
        vec![change_total]
    } else {
        if change_templates.iter().any(|change| change.value_zat.is_none()) {
            return Err("cannot mix automatic and explicit change outputs".into());
        }
        let values: Vec<u64> = change_templates.iter().map(|change| change.value_zat.unwrap()).collect();
        let sum = values.iter().try_fold(0u64, |total, value| total.checked_add(*value).ok_or_else(|| "change sum overflowed".to_string()))?;
        if sum != change_total {
            return Err(format!("explicit per-owner change outputs sum to {sum} zat, but must sum to {change_total} zat after fees"));
        }
        values
    };
    let builder = make_builder!(&change_values);
    let final_fee = builder.get_fee(&zip317::FeeRule::standard())
        .map_err(|e| format!("final ZIP 317 fee calculation failed: {e:?}"))?.into_u64();
    let change_sum = change_values.iter().try_fold(0u64, |total, value| total.checked_add(*value).ok_or_else(|| "change sum overflowed".to_string()))?;
    if fee != final_fee || output_total.checked_add(change_sum).and_then(|v| v.checked_add(fee)) != Some(input_total) {
        return Err("transaction value balance or fee invariant failed".into());
    }

    let mut rng = rand::rng();
    let PcztResult { pczt_parts, ironwood_meta, .. } = builder
        .build_for_pczt(&mut rng, &zip317::FeeRule::standard())
        .map_err(|e| format!("official Zcash transaction builder rejected the inputs: {e:?}"))?;
    let created = Creator::build_from_parts(pczt_parts)
        .ok_or_else(|| "PCZT Creator rejected V6 transaction parts".to_string())?;
    let pczt = IoFinalizer::new(created).finalize_io(&mut rng)
        .map_err(|e| format!("PCZT I/O finalization failed: {e:?}"))?;
    let ironwood_spend_action_indexes: Vec<usize> = (0..spends.len())
        .map(|i| ironwood_meta.spend_action_index(i).ok_or_else(|| format!("no PCZT action index for spend {i}")))
        .collect::<Result<_,_>>()?;
    let pczt_bytes_len = pczt.clone().serialize()
        .map_err(|e| format!("PCZT serialization failed: {e:?}"))?.len();

    Ok((pczt, PcztBuildReport {
        status: "PCZT_READY_FOR_LOCAL_PARTICIPANT_SIGNATURES".into(),
        network: "Zcash Testnet".into(),
        target_height: request.target_height,
        expiry_height: request.target_height.saturating_add(40),
        consensus_branch_id: format!("0x{branch_id_u32:08x}"),
        ironwood_anchor_hex: hex::encode(anchor.to_bytes()),
        input_count: spends.len(),
        recipient_output_count: outputs.len(),
        input_total_zat: input_total,
        recipient_total_zat: output_total,
        fee_zat: fee,
        change_zat: change_sum,
        change_output_count: change_values.len(),
        seller_fill_total_zat: change_templates.iter().try_fold(0u64, |sum, item| {
            sum.checked_add(item.seller_fill_zat).ok_or_else(|| "seller fill report sum overflowed".to_string())
        })?,
        ironwood_spend_action_indexes: ironwood_spend_action_indexes,
        pczt_bytes_len,
        broadcast_ready: false,
        warning: "Not broadcastable yet. Keep the build JSON and PCZT private. Each spend must be signed locally and the Ironwood proof must be generated. A successful local extraction does not establish that Zebra considers the note unspent or accepts the transaction.".into(),
    }))
}

pub fn build_pczt_from_files(input_json_path: &str, pczt_output_path: &str, report_output_path: &str) -> Result<PcztBuildReport, String> {
    let source = fs::read_to_string(input_json_path).map_err(|e| format!("could not read local build JSON: {e}"))?;
    let request: PcztBuildRequest = serde_json::from_str(&source).map_err(|e| format!("invalid PCZT build JSON: {e}"))?;
    let (pczt, report) = build_pczt(&request)?;
    fs::write(pczt_output_path, pczt.serialize().map_err(|e| format!("PCZT serialization failed: {e:?}"))?)
        .map_err(|e| format!("could not write PCZT: {e}"))?;
    fs::write(report_output_path, serde_json::to_vec_pretty(&report).map_err(|e| format!("report serialization failed: {e}"))?)
        .map_err(|e| format!("could not write PCZT report: {e}"))?;
    Ok(report)
}

pub fn build_fba_pczt_from_files(input_json_path: &str, pczt_output_path: &str, report_output_path: &str) -> Result<PcztBuildReport, String> {
    let source = fs::read_to_string(input_json_path).map_err(|e| format!("could not read local FBA settlement JSON: {e}"))?;
    let request: PcztBuildRequest = serde_json::from_str(&source).map_err(|e| format!("invalid FBA settlement JSON: {e}"))?;
    if request.change_outputs.is_empty() {
        return Err("FBA PCZT requires explicit change_outputs with seller fills per owner".into());
    }
    if request.change_outputs.iter().any(|change| change.value_zat.is_some()) {
        return Err("FBA PCZT expects null change_outputs[].value_zat so it can allocate residuals after the ZIP 317 fee".into());
    }
    let (pczt, mut report) = build_pczt(&request)?;
    report.status = "FBA_PCZT_READY_FOR_LOCAL_PARTICIPANT_SIGNATURES".into();
    report.warning = "Built from supplied FBA buyer outputs and per-owner seller fills. Input notes/witnesses must be real/current; transaction is not broadcast or confirmed. USDC/quote-leg settlement is not implemented. PCZT data is sensitive and must remain local.".into();
    fs::write(pczt_output_path, pczt.serialize().map_err(|e| format!("PCZT serialization failed: {e:?}"))?)
        .map_err(|e| format!("could not write FBA PCZT: {e}"))?;
    fs::write(report_output_path, serde_json::to_vec_pretty(&report).map_err(|e| format!("report serialization failed: {e}"))?)
        .map_err(|e| format!("could not write FBA PCZT report: {e}"))?;
    Ok(report)
}

fn parse_spending_key_file(path: &str) -> Result<SpendingKey, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("could not read local spending key file: {e}"))?;
    let bytes = decode_array::<32>(&text, "spending key")?;
    SpendingKey::from_bytes(bytes).into_option()
        .ok_or_else(|| "spending key file does not contain a valid Zcash Orchard spending key".into())
}
fn sign_pczt_value(pczt: Pczt, action_index: usize, key: &SpendingKey) -> Result<Pczt, String> {
    if pczt.ironwood().actions().get(action_index).is_none() {
        return Err(format!("Ironwood action index {action_index} is out of range"));
    }
    let ask = SpendAuthorizingKey::from(key);
    let mut rng = rand::rng();
    let mut signer = Signer::new(pczt).map_err(|e| format!("PCZT Signer rejected input: {e:?}"))?;
    signer.sign_ironwood(&mut rng, action_index, &ask)
        .map_err(|e| format!("local Ironwood signature failed: {e:?}"))?;
    Ok(signer.finish())
}
pub fn sign_pczt_from_local_key_file(pczt_input_path: &str, spending_key_file_path: &str, action_index: usize, pczt_output_path: &str) -> Result<(), String> {
    let key = parse_spending_key_file(spending_key_file_path)?;
    let bytes = fs::read(pczt_input_path).map_err(|e| format!("could not read PCZT: {e}"))?;
    let pczt = Pczt::parse(&bytes).map_err(|e| format!("input is not a valid PCZT: {e:?}"))?;
    let signed = sign_pczt_value(pczt, action_index, &key)?;
    fs::write(pczt_output_path, signed.serialize().map_err(|e| format!("signed PCZT serialization failed: {e:?}"))?)
        .map_err(|e| format!("could not write signed PCZT: {e}"))?;
    Ok(())
}
pub fn combine_pczt_files(input_paths: &[String], output_path: &str) -> Result<(), String> {
    if input_paths.len() < 2 {
        return Err("provide at least two PCZT files to combine independent signature contributions".into());
    }
    let mut pczts = Vec::with_capacity(input_paths.len());
    for path in input_paths {
        let bytes = fs::read(path).map_err(|e| format!("could not read PCZT file {path}: {e}"))?;
        let pczt = Pczt::parse(&bytes).map_err(|e| format!("file {path} is not a valid PCZT: {e:?}"))?;
        pczts.push(pczt);
    }
    let combined = Combiner::new(pczts)
        .combine()
        .map_err(|e| format!("official PCZT Combiner rejected the contributions: {e:?}"))?;
    fs::write(output_path, combined.serialize().map_err(|e| format!("combined PCZT serialization failed: {e:?}"))?)
        .map_err(|e| format!("could not write combined PCZT: {e}"))?;
    Ok(())
}

fn prove_and_extract(pczt: Pczt) -> Result<Vec<u8>, String> {
    let proving_key = orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let mut rng = rand::rng();
    let proved = Prover::new(pczt)
        .create_ironwood_proof(&mut rng, &proving_key)
        .map_err(|e| format!("official Ironwood Halo 2 proof failed: {e:?}"))?
        .finish();
    let tx = TransactionExtractor::new(proved).extract(&mut rng)
        .map_err(|e| format!("TransactionExtractor rejected the transaction: {e:?}"))?;
    let txid = tx.txid().to_string();
    let branch_id = u32::from(tx.consensus_branch_id());
    if !matches!(branch_id, TESTNET_NU6_3_BRANCH_ID | TESTNET_NU7_BRANCH_ID) {
        return Err(format!(
            "extracted transaction has unsupported Testnet consensus branch 0x{branch_id:08x}"
        ));
    }
    let mut raw = Vec::new();
    tx.write(&mut raw).map_err(|e| format!("transaction serialization failed: {e}"))?;
    if raw.len() < 1_000 { return Err(format!("extracted transaction is unexpectedly short: {} bytes", raw.len())); }
    let version = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if version != 0x8000_0006 { return Err(format!("expected transaction v6, got 0x{version:08x}")); }
    Ok((raw, txid, branch_id))
}
pub fn prove_extract_pczt_to_hex_file(pczt_input_path: &str, tx_hex_output_path: &str, report_output_path: &str) -> Result<(), String> {
    let bytes = fs::read(pczt_input_path).map_err(|e| format!("could not read signed PCZT: {e}"))?;
    let pczt = Pczt::parse(&bytes).map_err(|e| format!("input is not a valid PCZT: {e:?}"))?;
    let (raw, txid, branch_id) = prove_and_extract(pczt)?;
    fs::write(tx_hex_output_path, hex::encode(&raw)).map_err(|e| format!("could not write raw transaction hex: {e}"))?;
    let report = serde_json::json!({
        "status": "PROOF_GENERATED_AND_TRANSACTION_EXTRACTED",
        "network": "Zcash Testnet",
        "transaction_version": 6,
        "consensus_branch_id": format!("0x{branch_id:08x}"),
        "txid": txid,
        "raw_transaction_bytes": raw.len(),
        "broadcast_ready": true,
        "network_confirmed": false,
        "warning": "This V6 transaction was extracted by official Zcash Rust libraries after proof/signature validation. This tool has not proved the notes remain unspent or that Zebra accepts the transaction. Broadcast to activated Testnet Zebra and verify its txid and block confirmation before recording an FBA epoch."
    });
    fs::write(report_output_path, serde_json::to_vec_pretty(&report).map_err(|e| format!("report serialization failed: {e}"))?)
        .map_err(|e| format!("could not write transaction report: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_note_address_must_belong_to_supplied_fvk() {
        let sk_a = SpendingKey::from_bytes([1u8; 32]).into_option().expect("valid key A");
        let sk_b = SpendingKey::from_bytes([2u8; 32]).into_option().expect("valid key B");
        let fvk_a = FullViewingKey::from(&sk_a);
        let fvk_b = FullViewingKey::from(&sk_b);
        let address_a = fvk_a.address_at(0u32, Scope::External).to_raw_address_bytes();
        assert!(ensure_fvk_owns_address(&fvk_a, &address_a, "fixture A").is_ok());
        assert!(ensure_fvk_owns_address(&fvk_b, &address_a, "fixture A").is_err());
    }

    #[test]
    fn fba_pczt_conserves_seller_fills_and_allocates_change_per_owner() {
        let sk_bytes = [1u8; 32];
        let sk = SpendingKey::from_bytes(sk_bytes).into_option().expect("valid fixture key");
        let fvk = FullViewingKey::from(&sk);
        let address = fvk.address_at(0u32, Scope::External);
        let address_raw = address.to_raw_address_bytes();
        let rho_bytes = [3u8; 32];
        let rho = Rho::from_bytes(&rho_bytes).into_option().expect("valid rho");
        let rseed_bytes = [4u8; 32];
        let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).into_option().expect("valid rseed");
        let note = Note::from_parts(address.clone(), NoteValue::from_raw(1_000_000), rho, rseed, NoteVersion::V3)
            .into_option().expect("valid fixture note");
        let zero = MerkleHashOrchard::from_bytes(&[0u8; 32]).into_option().expect("canonical Merkle node");
        let path = MerklePath::from_parts(0, [zero; 32]);
        let anchor = path.root(note.commitment().into());
        let request = PcztBuildRequest {
            target_height: TESTNET_NU6_3_HEIGHT + 100,
            ironwood_anchor_hex: hex::encode(anchor.to_bytes()),
            inputs: vec![PcztSpendInput {
                fvk_hex: hex::encode(fvk.to_bytes()),
                raw_address_hex: hex::encode(address_raw),
                value_zat: 1_000_000,
                rho_hex: hex::encode(rho_bytes),
                rseed_hex: hex::encode(rseed_bytes),
                merkle_position: 0,
                merkle_path_hex: vec![hex::encode([0u8; 32]); 32],
            }],
            outputs: vec![PcztRecipient {
                address_raw_hex: hex::encode(address_raw),
                value_zat: 970_000,
                memo_hex: String::new(),
            }],
            change_fvk_hex: String::new(),
            change_address_raw_hex: String::new(),
            change_outputs: vec![PcztChangeOutput {
                fvk_hex: hex::encode(fvk.to_bytes()),
                address_raw_hex: hex::encode(address_raw),
                value_zat: None,
                seller_fill_zat: 970_000,
                memo_hex: String::new(),
            }],
        };
        let (pczt, report) = build_pczt(&request).expect("balanced FBA PCZT");
        assert_eq!(report.input_total_zat, 1_000_000);
        assert_eq!(report.recipient_total_zat, 970_000);
        assert!(report.fee_zat > 0);
        assert!(report.change_zat > 0);
        assert_eq!(report.recipient_total_zat + report.fee_zat + report.change_zat, report.input_total_zat);
        assert!(!report.broadcast_ready);
        let bytes = pczt.serialize().expect("PCZT serializes");
        assert!(Pczt::parse(&bytes).is_ok());
    }

    #[test]
    fn official_ironwood_pczt_sign_prove_extract_round_trip() {
        let sk_bytes = [1u8; 32];
        let sk = SpendingKey::from_bytes(sk_bytes).into_option().expect("valid fixture key");
        let fvk = FullViewingKey::from(&sk);
        let address = fvk.address_at(0u32, Scope::External);
        let address_raw = address.to_raw_address_bytes();
        let rho_bytes = [1u8; 32];
        let rho = Rho::from_bytes(&rho_bytes).into_option().expect("valid rho");
        let rseed_bytes = [2u8; 32];
        let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).into_option().expect("valid rseed");
        let note = Note::from_parts(address.clone(), NoteValue::from_raw(1_000_000), rho, rseed, NoteVersion::V3)
            .into_option().expect("valid fixture note");
        let zero = MerkleHashOrchard::from_bytes(&[0u8; 32]).into_option().expect("canonical Merkle node");
        let path = MerklePath::from_parts(0, [zero; 32]);
        let anchor = path.root(note.commitment().into());
        let request = PcztBuildRequest {
            target_height: TESTNET_NU6_3_HEIGHT + 100,
            ironwood_anchor_hex: hex::encode(anchor.to_bytes()),
            inputs: vec![PcztSpendInput {
                fvk_hex: hex::encode(fvk.to_bytes()),
                raw_address_hex: hex::encode(address_raw),
                value_zat: 1_000_000,
                rho_hex: hex::encode(rho_bytes),
                rseed_hex: hex::encode(rseed_bytes),
                merkle_position: 0,
                merkle_path_hex: vec![hex::encode([0u8; 32]); 32],
            }],
            outputs: vec![PcztRecipient {
                address_raw_hex: hex::encode(address_raw),
                value_zat: 970_000,
                memo_hex: String::new(),
            }],
            change_fvk_hex: hex::encode(fvk.to_bytes()),
            change_address_raw_hex: hex::encode(address_raw),
            change_outputs: Vec::new(),
        };
        let (pczt, report) = build_pczt(&request).expect("official PCZT build");
        assert_eq!(report.input_count, 1);
        assert_eq!(report.recipient_output_count, 1);
        assert!(report.change_zat > 0);
        assert!(!report.broadcast_ready);
        let encoded = pczt.clone().serialize().expect("serialize PCZT");
        let decoded = Pczt::parse(&encoded).expect("parse PCZT");
        assert_eq!(encoded, decoded.serialize().expect("reserialize PCZT"));
        let signed = sign_pczt_value(pczt, report.ironwood_spend_action_indexes[0], &sk)
            .expect("sign local spend");
        // A participant returns only their signed PCZT. The official Combiner merges it
        // with the unsigned transaction skeleton without pretending the signature is a proof.
        let combined = Combiner::new(vec![decoded, signed]).combine().expect("combine signed PCZT contribution");
        let raw = prove_and_extract(combined).expect("prove and extract real v6 transaction");
        assert!(raw.len() > 1_000);
        assert_eq!(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]), 0x8000_0006);
    }
}
