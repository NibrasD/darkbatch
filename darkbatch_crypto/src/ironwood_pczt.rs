//! Collaborative Ironwood transaction construction with the official PCZT roles.
//!
//! This module never accepts or exports another participant's spending key in the
//! coordinator-facing PCZT request. A participant signs locally with their own key;
//! the finalizer later attaches canonical witnesses and creates the proof for the
//! same PCZT before extracting the authorized transaction.

use std::sync::OnceLock;

use orchard::{
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, OutgoingViewingKey, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note, NoteVersion, Rho, RandomSeed},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pczt::{
    Pczt,
    roles::{
        combiner::Combiner,
        creator::Creator,
        io_finalizer::IoFinalizer,
        prover::Prover,
        redactor::Redactor,
        signer::Signer,
        tx_extractor::TransactionExtractor,
        updater::Updater,
    },
};
use serde::Deserialize;
use zcash_primitives::transaction::{
    builder::{BundlePadding, DeferredPcztBuilder},
    fees::zip317,
    Transaction,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, Network},
    memo::MemoBytes,
    value::Zatoshis,
};

use crate::ironwood_transaction::decode_ironwood_recipient;

const TESTNET_IRONWOOD_ACTIVATION_HEIGHT: u32 = 4_134_000;
const MAX_SPENDS: usize = 64;
const MAX_OUTPUTS: usize = 64;
const MAX_PCZT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    network: String,
    target_height: u32,
    #[serde(default)]
    expiry_height: Option<u32>,
    spends: Vec<SpendRequest>,
    outputs: Vec<OutputRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendRequest {
    input_id: String,
    full_viewing_key_hex: String,
    note_address_raw_hex: String,
    value_zat: u64,
    rho_hex: String,
    rseed_hex: String,
    nullifier_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputRequest {
    output_id: String,
    #[serde(default)]
    recipient_address: Option<String>,
    #[serde(default)]
    recipient_address_raw_hex: Option<String>,
    value_zat: u64,
    #[serde(default)]
    memo_hex: String,
    #[serde(default)]
    ovk_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignRequest {
    pczt_hex: String,
    spending_key_hex: String,
    nullifier_hex: String,
    expected_sighash_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectRequest {
    pczt_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CombineRequest {
    pczt_hexes: Vec<String>,
    required_nullifiers_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizeRequest {
    pczt_hex: String,
    anchor_hex: String,
    required_nullifiers_hex: Vec<String>,
    witnesses: Vec<WitnessRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessRequest {
    nullifier_hex: String,
    witness_position: u32,
    witness_auth_path_hex: Vec<String>,
}

#[derive(Clone)]
struct ParsedSpend {
    input_id: String,
    nullifier: [u8; 32],
}

fn parse_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value)
        .map_err(|_| format!("{label} must be valid hexadecimal."))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!("{label} must be {N} bytes, got {}.", bytes.len())
    })
}

fn decode_pczt(hex_string: &str) -> Result<Pczt, String> {
    if hex_string.len() % 2 != 0 {
        return Err("pczt_hex must have an even number of hexadecimal characters.".to_owned());
    }
    if hex_string.len() / 2 > MAX_PCZT_BYTES {
        return Err(format!("PCZT exceeds the {MAX_PCZT_BYTES}-byte local limit."));
    }
    let bytes = hex::decode(hex_string)
        .map_err(|_| "pczt_hex must be valid hexadecimal.".to_owned())?;
    Pczt::parse(&bytes).map_err(|e| format!("Official PCZT decoder rejected the data: {e:?}"))
}

fn encode_pczt(pczt: Pczt) -> Result<String, String> {
    let bytes = pczt
        .serialize()
        .map_err(|e| format!("Official PCZT serialization failed: {e:?}"))?;
    if bytes.len() > MAX_PCZT_BYTES {
        return Err(format!("Serialized PCZT exceeds the {MAX_PCZT_BYTES}-byte local limit."));
    }
    Ok(hex::encode(bytes))
}

fn proving_key() -> &'static ProvingKey {
    static KEY: OnceLock<ProvingKey> = OnceLock::new();
    KEY.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::PostNu6_3))
}

fn verifying_key() -> &'static VerifyingKey {
    static KEY: OnceLock<VerifyingKey> = OnceLock::new();
    KEY.get_or_init(|| VerifyingKey::build(OrchardCircuitVersion::PostNu6_3))
}

/// Constructs and finalizes PCZT I/O only. No Merkle witnesses, spend signatures,
/// proof, binding signature, or raw transaction are fabricated by this operation.
///
/// The caller must ensure `sum(input notes) - sum(outputs) == ZIP-317 fee`.
/// For a multi-party transaction, the PCZT carries public key material and note
/// data required by the prover; distribute it only through the intended secure
/// participant channel. It does not contain a participant's spending key.
pub fn create_ironwood_pczt_json(input_json: &str) -> Result<serde_json::Value, String> {
    use std::convert::Infallible;

    let request: CreateRequest = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid Ironwood PCZT request JSON: {e}"))?;
    if request.network != "testnet" {
        return Err("Collaborative Ironwood PCZT creation is restricted to Testnet.".to_owned());
    }
    if request.target_height < TESTNET_IRONWOOD_ACTIVATION_HEIGHT {
        return Err("Target height precedes Testnet NU6.3/Ironwood activation.".to_owned());
    }
    if request.spends.is_empty() || request.outputs.is_empty() {
        return Err("PCZT requires at least one spend and at least one output.".to_owned());
    }
    if request.spends.len() > MAX_SPENDS || request.outputs.len() > MAX_OUTPUTS {
        return Err(format!("PCZT limit is {MAX_SPENDS} spends and {MAX_OUTPUTS} outputs."));
    }

    let target_height = BlockHeight::from_u32(request.target_height);
    let default_expiry = request.target_height.saturating_add(20);
    let expiry_height_u32 = request.expiry_height.unwrap_or(default_expiry);
    if expiry_height_u32 <= request.target_height {
        return Err("expiry_height must be greater than target_height.".to_owned());
    }
    let expiry_height = BlockHeight::from_u32(expiry_height_u32);
    let fee_rule = zip317::FeeRule::standard();
    let mut builder = DeferredPcztBuilder::new::<Infallible>(
        Network::TestNetwork,
        target_height,
        BundlePadding::DEFAULT,
        BundlePadding::DEFAULT,
    )
    .map_err(|e| format!("Official deferred Ironwood PCZT builder rejected the target: {e:?}"))?
    .with_expiry_height(expiry_height);

    let mut parsed_spends = Vec::with_capacity(request.spends.len());
    let mut total_input_value_zat: u64 = 0;
    for (index, spend) in request.spends.iter().enumerate() {
        let label = format!("spends[{index}]");
        if spend.input_id.trim().is_empty() {
            return Err(format!("{label}.input_id must not be empty."));
        }
        let fvk_bytes = parse_hex::<96>(
            &spend.full_viewing_key_hex,
            &format!("{label}.full_viewing_key_hex"),
        )?;
        let fvk = FullViewingKey::from_bytes(&fvk_bytes)
            .ok_or_else(|| format!("{label}: invalid FullViewingKey encoding."))?;
        let raw_address = parse_hex::<43>(
            &spend.note_address_raw_hex,
            &format!("{label}.note_address_raw_hex"),
        )?;
        let note_address = orchard::Address::from_raw_address_bytes(&raw_address)
            .into_option()
            .ok_or_else(|| format!("{label}: invalid note receiver."))?;
        if fvk.scope_for_address(&note_address).is_none() {
            return Err(format!("{label}: supplied FullViewingKey does not control this note receiver."));
        }
        let rho_bytes = parse_hex::<32>(&spend.rho_hex, &format!("{label}.rho_hex"))?;
        let rho = Rho::from_bytes(&rho_bytes)
            .into_option()
            .ok_or_else(|| format!("{label}: invalid rho encoding."))?;
        let rseed_bytes = parse_hex::<32>(&spend.rseed_hex, &format!("{label}.rseed_hex"))?;
        let rseed = RandomSeed::from_bytes(rseed_bytes, &rho)
            .into_option()
            .ok_or_else(|| format!("{label}: rseed is invalid for the supplied rho."))?;
        let value = Zatoshis::from_u64(spend.value_zat)
            .map_err(|e| format!("{label}: value is outside MAX_MONEY: {e}"))?;
        if value.is_zero() {
            return Err(format!("{label}: zero-value notes cannot be spent."));
        }

        let note = Note::from_parts(
            note_address,
            NoteValue::from_raw(value.into_u64()),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .into_option()
        .ok_or_else(|| format!("{label}: could not reconstruct the Ironwood V3 note."))?;
        let derived_nullifier = note.nullifier(&fvk).to_bytes();
        let supplied_nullifier = parse_hex::<32>(
            &spend.nullifier_hex,
            &format!("{label}.nullifier_hex"),
        )?;
        if derived_nullifier != supplied_nullifier {
            return Err(format!("{label}: nullifier does not match the note and FullViewingKey."));
        }
        if parsed_spends.iter().any(|item: &ParsedSpend| item.nullifier == supplied_nullifier) {
            return Err(format!("{label}: duplicate input nullifier."));
        }

        total_input_value_zat = total_input_value_zat
            .checked_add(value.into_u64())
            .ok_or_else(|| "Total input value overflow.".to_owned())?;
        builder
            .add_ironwood_spend::<Infallible>(fvk, note)
            .map_err(|e| format!("{label}: official builder rejected the input note: {e:?}"))?;
        parsed_spends.push(ParsedSpend {
            input_id: spend.input_id.clone(),
            nullifier: supplied_nullifier,
        });
    }

    let mut total_output_value_zat: u64 = 0;
    let mut output_ids = std::collections::BTreeSet::new();
    for (index, output) in request.outputs.iter().enumerate() {
        let label = format!("outputs[{index}]");
        if output.output_id.trim().is_empty() || !output_ids.insert(output.output_id.clone()) {
            return Err(format!("{label}.output_id must be non-empty and unique."));
        }
        let recipient = decode_ironwood_recipient(
            output.recipient_address.as_deref(),
            output.recipient_address_raw_hex.as_deref(),
            &label,
        )?;
        let value = Zatoshis::from_u64(output.value_zat)
            .map_err(|e| format!("{label}: output value is outside MAX_MONEY: {e}"))?;
        if value.is_zero() {
            return Err(format!("{label}: output value must be greater than zero."));
        }
        let memo_bytes = if output.memo_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(&output.memo_hex)
                .map_err(|_| format!("{label}.memo_hex must be valid hexadecimal."))?
        };
        let memo = MemoBytes::from_bytes(&memo_bytes)
            .map_err(|e| format!("{label}.memo_hex is not a valid memo up to 512 bytes: {e}"))?;
        let ovk = output.ovk_hex.as_deref().map(|value| {
            parse_hex::<32>(value, &format!("{label}.ovk_hex")).map(OutgoingViewingKey::from)
        }).transpose()?;

        total_output_value_zat = total_output_value_zat
            .checked_add(value.into_u64())
            .ok_or_else(|| "Total output value overflow.".to_owned())?;
        builder
            .add_ironwood_output::<Infallible>(ovk, recipient, value, memo)
            .map_err(|e| format!("{label}: official builder rejected the output: {e:?}"))?;
    }

    if total_input_value_zat <= total_output_value_zat {
        return Err("Total inputs must exceed total outputs to pay the network fee.".to_owned());
    }
    let required_fee = builder
        .get_fee(&fee_rule)
        .map_err(|e| format!("Could not calculate ZIP-317 fee: {e:?}"))?
        .into_u64();
    let actual_fee = total_input_value_zat - total_output_value_zat;
    if actual_fee != required_fee {
        return Err(format!(
            "Value conservation failed: input-output difference is {actual_fee} zatoshis, but the official ZIP-317 fee is {required_fee}. Add or adjust explicit change outputs before creating the PCZT."
        ));
    }

    let result = builder
        .build_for_pczt(rand::rng(), &fee_rule)
        .map_err(|e| format!("Official deferred PCZT build failed: {e:?}"))?;
    let action_indices: Vec<serde_json::Value> = parsed_spends
        .iter()
        .enumerate()
        .map(|(spend_index, spend)| {
            let action_index = result
                .ironwood_meta
                .spend_action_index(spend_index)
                .expect("metadata must include each real spend");
            serde_json::json!({
                "input_id": spend.input_id,
                "nullifier_hex": hex::encode(spend.nullifier),
                "action_index": action_index,
            })
        })
        .collect();

    let pczt = Creator::build_from_parts(result.pczt_parts)
        .ok_or_else(|| "Official PCZT Creator could not represent the transaction version.".to_owned())?;
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(rand::rng())
        .map_err(|e| format!("Official PCZT I/O finalization failed: {e:?}"))?;
    let serialized = encode_pczt(pczt.clone())?;
    let signer = Signer::new(pczt)
        .map_err(|e| format!("Could not derive the PCZT's canonical signing digest: {e:?}"))?;
    let sighash_hex = hex::encode(signer.shielded_sighash());

    let branch_id = BranchId::for_height(&Network::TestNetwork, target_height);
    let branch_id_u32: u32 = branch_id.into();
    Ok(serde_json::json!({
        "status": "PCZT_READY_FOR_REVIEW_AND_PARTICIPANT_SIGNATURES",
        "network": "testnet",
        "transaction_version": 6,
        "version_group_id": "0xd884b698",
        "consensus_branch_id": format!("0x{branch_id_u32:08x}"),
        "target_height": request.target_height,
        "expiry_height": expiry_height_u32,
        "input_value_zat": total_input_value_zat,
        "output_value_zat": total_output_value_zat,
        "fee_zat": required_fee,
        "input_action_indices": action_indices,
        "sighash_hex": sighash_hex,
        "pczt_hex": serialized,
        "broadcast": false,
        "note": "PCZT is unsigned until each owner signs their own action; no raw transaction exists yet."
    }))
}

/// Returns the action/output manifest and canonical sighash for a PCZT before signing.
/// This must be displayed and reviewed by each participant; matching a sighash does not
/// replace the user's verification of recipients, amounts, fees, and change.
pub fn inspect_ironwood_pczt_json(input_json: &str) -> Result<serde_json::Value, String> {
    let request: InspectRequest = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid PCZT inspection request JSON: {e}"))?;
    let pczt = decode_pczt(&request.pczt_hex)?;
    let signer = Signer::new(pczt.clone())
        .map_err(|e| format!("PCZT cannot produce a canonical signing digest: {e:?}"))?;
    let actions: Vec<serde_json::Value> = pczt
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .map(|(index, action)| {
            serde_json::json!({
                "action_index": index,
                "nullifier_hex": hex::encode(action.spend().nullifier()),
                "rk_hex": hex::encode(action.spend().rk()),
                "spend_signature_present": action.spend().spend_auth_sig().is_some(),
                "output_receiver_raw_hex": action.output().recipient().map(hex::encode),
                "output_value_zat": action.output().value(),
                "cmx_hex": action.output().cmx().map(hex::encode),
                "epk_hex": hex::encode(action.output().ephemeral_key()),
            })
        })
        .collect();
    Ok(serde_json::json!({
        "status": "PCZT_INSPECTED_NOT_SIGNED",
        "network": "testnet",
        "action_count": actions.len(),
        "sighash_hex": hex::encode(signer.shielded_sighash()),
        "actions": actions,
        "note": "Inspect all outputs and fees before signing; the displayed sighash commits to transaction effects, not to anchors or witnesses."
    }))
}

/// Creates the version of a PCZT that one input owner should receive and sign.
/// Other owners' note-opening data, FVKs, witnesses, and randomizers are redacted.
/// Output effects remain visible for participant review; the signer must still review
/// the full output manifest and the unchanged transaction sighash.
pub fn prepare_ironwood_pczt_for_signer_json(input_json: &str) -> Result<serde_json::Value, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        pczt_hex: String,
        signer_nullifier_hex: String,
    }
    let request: Request = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid signer-preparation request JSON: {e}"))?;
    let target_nullifier = parse_hex::<32>(&request.signer_nullifier_hex, "signer_nullifier_hex")?;
    let pczt = decode_pczt(&request.pczt_hex)?;
    let before_signer = Signer::new(pczt.clone())
        .map_err(|e| format!("PCZT cannot produce a canonical signing digest: {e:?}"))?;
    let expected_sighash = before_signer.shielded_sighash();
    let actions = pczt.ironwood().actions();
    let matches: Vec<usize> = actions.iter().enumerate()
        .filter(|(_, action)| action.spend().nullifier() == &target_nullifier)
        .map(|(index, _)| index)
        .collect();
    if matches.len() != 1 {
        return Err("Signer nullifier must identify exactly one action in this PCZT.".to_owned());
    }
    let own_index = matches[0];
    let action_count = actions.len();

    let redacted = Redactor::new(pczt)
        .redact_ironwood_with(|mut bundle| {
            for index in 0..action_count {
                if index == own_index {
                    continue;
                }
                bundle.redact_action(index, |mut action| {
                    action.clear_spend_recipient();
                    action.clear_spend_value();
                    action.clear_spend_rho();
                    action.clear_spend_rseed();
                    action.clear_spend_fvk();
                    action.clear_spend_witness();
                    action.clear_spend_alpha();
                    action.clear_spend_zip32_derivation();
                    action.clear_spend_dummy_sk();
                    action.clear_spend_proprietary();
                    action.clear_rcv();
                });
            }
        })
        .finish();

    let after_signer = Signer::new(redacted.clone())
        .map_err(|e| format!("Redacted PCZT cannot produce a canonical signing digest: {e:?}"))?;
    if after_signer.shielded_sighash() != expected_sighash {
        return Err("Signer redaction changed the transaction effects or signing digest; refusing to export.".to_owned());
    }
    let encoded = encode_pczt(redacted)?;
    Ok(serde_json::json!({
        "status": "PCZT_REDACTED_FOR_PARTICIPANT",
        "network": "testnet",
        "signer_nullifier_hex": hex::encode(target_nullifier),
        "action_index": own_index,
        "sighash_hex": hex::encode(expected_sighash),
        "pczt_hex": encoded,
        "broadcast": false,
        "privacy_note": "Other input-note opening fields were redacted. Output effects remain visible and must be reviewed. The PCZT creator/prover still sees input data supplied during construction."
    }))
}

/// Signs exactly the Ironwood action whose nullifier is controlled by the provided
/// spending key. The expected sighash is mandatory so the local signer can reject a
/// PCZT that changed after the user reviewed its manifest.
pub fn sign_ironwood_pczt_json(input_json: &str) -> Result<serde_json::Value, String> {
    let request: SignRequest = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid PCZT signing request JSON: {e}"))?;
    let expected_nullifier = parse_hex::<32>(&request.nullifier_hex, "nullifier_hex")?;
    let expected_sighash = parse_hex::<32>(&request.expected_sighash_hex, "expected_sighash_hex")?;
    let spending_key_bytes = parse_hex::<32>(&request.spending_key_hex, "spending_key_hex")?;
    let spending_key = SpendingKey::from_bytes(spending_key_bytes)
        .into_option()
        .ok_or_else(|| "Invalid raw Ironwood spending key.".to_owned())?;
    let ask = SpendAuthorizingKey::from(&spending_key);
    let pczt = decode_pczt(&request.pczt_hex)?;
    let signer = Signer::new(pczt)
        .map_err(|e| format!("PCZT cannot be signed: {e:?}"))?;
    let actual_sighash = signer.shielded_sighash();
    if actual_sighash != expected_sighash {
        return Err("PCZT signing digest differs from the digest reviewed by this wallet; refusing to sign.".to_owned());
    }

    let pczt = signer.finish();
    let mut matches = pczt
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, action)| action.spend().nullifier() == &expected_nullifier);
    let (action_index, _) = matches
        .next()
        .ok_or_else(|| "The requested nullifier is not present in the PCZT's Ironwood action set.".to_owned())?;
    if matches.next().is_some() {
        return Err("PCZT contains the requested nullifier more than once.".to_owned());
    }

    let mut signer = Signer::new(pczt)
        .map_err(|e| format!("Could not initialize the official PCZT signer: {e:?}"))?;
    signer
        .sign_ironwood(rand::rng(), action_index, &ask)
        .map_err(|e| format!("This spending key cannot authorize the selected PCZT action: {e:?}"))?;
    let signed_pczt = signer.finish();
    let signed_hex = encode_pczt(signed_pczt.clone())?;
    let signature_present = signed_pczt
        .ironwood()
        .actions()
        .get(action_index)
        .is_some_and(|action| action.spend().spend_auth_sig().is_some());
    if !signature_present {
        return Err("Official PCZT signer returned without an authorization signature.".to_owned());
    }

    Ok(serde_json::json!({
        "status": "PARTICIPANT_SIGNATURE_ADDED",
        "network": "testnet",
        "signed_nullifier_hex": hex::encode(expected_nullifier),
        "action_index": action_index,
        "sighash_hex": hex::encode(actual_sighash),
        "pczt_hex": signed_hex,
        "broadcast": false,
        "note": "Only the selected participant's action was signed. Send this PCZT to the next signer/prover over a secure channel."
    }))
}

/// Combines separately signed copies of the same PCZT without reconstructing
/// or changing transaction effects. Every required real input must have a signature.
pub fn combine_ironwood_pczts_json(input_json: &str) -> Result<serde_json::Value, String> {
    let request: CombineRequest = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid PCZT combine request JSON: {e}"))?;
    if request.pczt_hexes.is_empty() || request.pczt_hexes.len() > MAX_SPENDS + 1 {
        return Err("pczt_hexes must contain between 1 and 65 participant PCZTs.".to_owned());
    }
    if request.required_nullifiers_hex.is_empty() {
        return Err("required_nullifiers_hex must enumerate every real input.".to_owned());
    }

    let mut required = std::collections::BTreeSet::new();
    for (index, value) in request.required_nullifiers_hex.iter().enumerate() {
        let nullifier = parse_hex::<32>(value, &format!("required_nullifiers_hex[{index}]"))?;
        if !required.insert(nullifier) {
            return Err("required_nullifiers_hex contains a duplicate nullifier.".to_owned());
        }
    }
    let pczts = request.pczt_hexes.iter()
        .map(|value| decode_pczt(value))
        .collect::<Result<Vec<_>, _>>()?;
    let combined = Combiner::new(pczts)
        .combine()
        .map_err(|e| format!("Official PCZT Combiner rejected incompatible participant files: {e:?}"))?;

    let actions = combined.ironwood().actions();
    for nullifier in required.iter() {
        let matches: Vec<_> = actions.iter().filter(|action| action.spend().nullifier() == nullifier).collect();
        if matches.len() != 1 {
            return Err(format!("Required input {} must appear exactly once in the combined PCZT.", hex::encode(nullifier)));
        }
        if matches[0].spend().spend_auth_sig().is_none() {
            return Err(format!("Required input {} has no participant signature.", hex::encode(nullifier)));
        }
    }

    let signer = Signer::new(combined.clone())
        .map_err(|e| format!("Combined PCZT cannot produce a canonical signing digest: {e:?}"))?;
    let encoded = encode_pczt(combined)?;
    Ok(serde_json::json!({
        "status": "PCZT_COMBINED_AND_READY_FOR_FINALIZATION",
        "network": "testnet",
        "input_count": required.len(),
        "participant_pczt_count": request.pczt_hexes.len(),
        "sighash_hex": hex::encode(signer.shielded_sighash()),
        "pczt_hex": encoded,
        "broadcast": false,
        "note": "Official PCZT Combiner merged the participant signatures; fresh canonical Ironwood witnesses are still required before proving."
    }))
}

/// Adds every real input's current witness and anchor, generates the real proof for
/// this exact PCZT, extracts and verifies the authorized transaction, and returns raw
/// v6 transaction bytes for explicit downstream review/broadcast.
pub fn finalize_ironwood_pczt_json(input_json: &str) -> Result<serde_json::Value, String> {
    let request: FinalizeRequest = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid PCZT finalize request JSON: {e}"))?;
    if request.required_nullifiers_hex.is_empty() {
        return Err("required_nullifiers_hex must enumerate every real spend in this PCZT.".to_owned());
    }
    if request.witnesses.len() != request.required_nullifiers_hex.len() {
        return Err("A fresh Ironwood tree witness is required for every real input nullifier.".to_owned());
    }

    let pczt = decode_pczt(&request.pczt_hex)?;
    let anchor_bytes = parse_hex::<32>(&request.anchor_hex, "anchor_hex")?;
    let anchor = Anchor::from_bytes(anchor_bytes)
        .into_option()
        .ok_or_else(|| "anchor_hex is not a canonical Ironwood anchor.".to_owned())?;

    let mut required = std::collections::BTreeSet::new();
    for (index, value) in request.required_nullifiers_hex.iter().enumerate() {
        let nullifier = parse_hex::<32>(value, &format!("required_nullifiers_hex[{index}]"))?;
        if !required.insert(nullifier) {
            return Err("required_nullifiers_hex contains a duplicate nullifier.".to_owned());
        }
    }
    let actions = pczt.ironwood().actions();
    for nullifier in required.iter() {
        let matches: Vec<_> = actions.iter().filter(|action| action.spend().nullifier() == nullifier).collect();
        if matches.len() != 1 {
            return Err(format!("Required input {} must appear exactly once in the PCZT.", hex::encode(nullifier)));
        }
    }
    let mut witness_indices = std::collections::BTreeSet::new();
    let mut witnesses = Vec::with_capacity(request.witnesses.len());

    for (index, witness_request) in request.witnesses.iter().enumerate() {
        let nullifier = parse_hex::<32>(
            &witness_request.nullifier_hex,
            &format!("witnesses[{index}].nullifier_hex"),
        )?;
        if !required.contains(&nullifier) {
            return Err(format!("witnesses[{index}] does not correspond to a required transaction input."));
        }
        let action_index = actions
            .iter()
            .position(|action| action.spend().nullifier() == &nullifier)
            .ok_or_else(|| format!("witnesses[{index}] nullifier is not present in the PCZT."))?;
        if !witness_indices.insert(action_index) {
            return Err("Two witnesses map to the same PCZT action.".to_owned());
        }
        if actions[action_index].spend().spend_auth_sig().is_none() {
            return Err(format!("Input nullifier {} has not been signed by its owner.", hex::encode(nullifier)));
        }
        if witness_request.witness_auth_path_hex.len() != 32 {
            return Err(format!("witnesses[{index}].witness_auth_path_hex must contain exactly 32 nodes."));
        }
        let mut nodes = Vec::with_capacity(32);
        for (level, encoded) in witness_request.witness_auth_path_hex.iter().enumerate() {
            let bytes = parse_hex::<32>(encoded, &format!("witnesses[{index}].witness_auth_path_hex[{level}]"))?;
            let node = MerkleHashOrchard::from_bytes(&bytes)
                .into_option()
                .ok_or_else(|| format!("witnesses[{index}] has a non-canonical Merkle node at level {level}."))?;
            nodes.push(node);
        }
        let auth_path: [MerkleHashOrchard; 32] = nodes
            .try_into()
            .map_err(|_| format!("witnesses[{index}] must contain 32 nodes."))?;
        witnesses.push((
            action_index,
            MerklePath::from_parts(witness_request.witness_position, auth_path),
        ));
    }
    if required.len() != witness_indices.len() {
        return Err("Some required inputs are missing their witnesses.".to_owned());
    }
    // Reject missing or unexpectedly added real actions against the caller's signed input manifest.
    for nullifier in required.iter() {
        if !actions.iter().any(|action| action.spend().nullifier() == nullifier) {
            return Err(format!("Required input {} is absent from the PCZT.", hex::encode(nullifier)));
        }
    }

    let updater = Updater::new(pczt)
        .set_ironwood_anchor(anchor)
        .map_err(|e| format!("Could not set current Ironwood anchor: {e:?}"))?;
    let pczt = updater
        .set_ironwood_spend_witnesses(witnesses)
        .map_err(|e| format!("Could not install Ironwood note witnesses: {e:?}"))?
        .finish();

    let witnessed_nullifiers: std::collections::BTreeSet<[u8; 32]> = pczt
        .ironwood()
        .actions()
        .iter()
        .filter(|action| action.spend().witness().is_some())
        .map(|action| *action.spend().nullifier())
        .collect();
    if witnessed_nullifiers != required {
        return Err("Final PCZT witness set does not exactly match the required real inputs.".to_owned());
    }

    let pczt = Prover::new(pczt)
        .create_ironwood_proof(rand::rng(), proving_key())
        .map_err(|e| format!("Official Ironwood prover rejected the witness/PCZT: {e:?}"))?
        .finish();

    let transaction: Transaction = TransactionExtractor::new(pczt)
        .with_orchard(verifying_key())
        .extract(rand::rng())
        .map_err(|e| format!("Official PCZT transaction extraction/authorization verification failed: {e:?}"))?;
    let txid_hex = transaction.txid().to_string().to_lowercase();
    let mut raw_tx = Vec::new();
    transaction
        .write(&mut raw_tx)
        .map_err(|e| format!("Could not serialize extracted Ironwood transaction: {e}"))?;
    if raw_tx.is_empty() {
        return Err("Official transaction extractor returned an empty transaction.".to_owned());
    }

    Ok(serde_json::json!({
        "status": "BUILT_NOT_BROADCAST",
        "network": "testnet",
        "consensus_ready": true,
        "transaction_version": 6,
        "version_group_id": "0xd884b698",
        "txid": txid_hex,
        "raw_tx_hex": hex::encode(&raw_tx),
        "raw_tx_bytes_len": raw_tx.len(),
        "broadcast": false,
        "confirmed": false,
        "input_count": required.len(),
        "note": "Finalized from the same signed PCZT with canonical witnesses, an official Ironwood proof, and verified spend/binding signatures. Not yet accepted by Zebra."
    }))
}
