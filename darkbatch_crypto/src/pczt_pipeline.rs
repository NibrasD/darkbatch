//! Local cooperative Ironwood PCZT workflow backed by librustzcash.
//!
//! This module intentionally does not broadcast transactions. It creates a PCZT from actual
//! note openings and viewing keys, lets each holder authorize only their own spend locally,
//! combines participant PCZTs, installs the real shared anchor/witnesses, creates the official
//! Ironwood proof, and extracts/validates the final transaction using the Zcash PCZT roles.
//!
//! Sensitive PCZTs, note openings, full viewing keys, and spending-key files must stay local.
//! The input JSON is a wallet-export format; it is not a note scanner or a source of chain data.

use std::{
    fs,
    path::{Path, PathBuf},
};

use orchard::{
    circuit::{OrchardCircuitVersion, ProvingKey},
    keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
    note::NoteVersion as OrchardNoteVersion,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Address, Anchor,
};
use pczt::{
    roles::{
        combiner::Combiner,
        creator::Creator,
        io_finalizer::IoFinalizer,
        prover::Prover,
        signer::Signer,
        tx_extractor::TransactionExtractor,
        updater::Updater,
    },
    Pczt,
};
use rand::rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zcash_primitives::transaction::{
    builder::{BundlePadding, DeferredPcztBuilder},
    fees::zip317,
};
use zcash_protocol::{
    consensus::{BlockHeight, Network},
    memo::MemoBytes,
    value::Zatoshis,
};

const MAX_MONEY_ZAT: u64 = 21_000_000 * 100_000_000;

#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    /// Next block height for which the transaction is intended, read from the local Testnet node.
    pub target_height: u32,
    pub expiry_height: u32,
    /// Inputs are public viewing metadata plus note openings; spending keys are NOT accepted here.
    pub inputs: Vec<CreateSpendInput>,
    pub outputs: Vec<CreateOutput>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSpendInput {
    pub id: String,
    /// Canonical 96-byte Orchard FullViewingKey from the participant's local wallet.
    pub fvk_hex: String,
    /// The note's 43-byte Orchard receiver recovered from its decrypted plaintext.
    pub raw_address_hex: String,
    pub value_zat: u64,
    pub rho_hex: String,
    pub rseed_hex: String,
    /// Must match the wallet's note commitment/nullifier record.
    pub expected_cmx_hex: String,
    pub expected_nullifier_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateOutput {
    pub id: String,
    pub raw_address_hex: String,
    pub value_zat: u64,
}

#[derive(Debug, Serialize)]
struct CreatedSpend {
    id: String,
    nullifier_hex: String,
    action_index: usize,
}

#[derive(Debug, Deserialize)]
pub struct WitnessManifest {
    /// For a transaction, every real spend must be proved against the same Ironwood anchor.
    pub inputs: Vec<WitnessedSpend>,
}

#[derive(Debug, Deserialize)]
pub struct WitnessedSpend {
    pub nullifier_hex: String,
    pub raw_address_hex: String,
    pub value_zat: u64,
    pub rho_hex: String,
    pub rseed_hex: String,
    pub expected_cmx_hex: String,
    pub position: u32,
    /// Exactly 32 siblings, bottom-up, each a canonical 32-byte Pallas base encoding.
    pub auth_path_hex: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FileResult {
    status: String,
    output_file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_tx_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inputs: Option<Vec<CreatedSpend>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outputs: Option<usize>,
    note: String,
}

fn hex_array<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value.trim()).map_err(|e| format!("{field}: invalid hex: {e}"))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        format!("{field}: expected {N} bytes, received {}", v.len())
    })
}

fn checked_value(value: u64, field: &str) -> Result<Zatoshis, String> {
    if value == 0 || value > MAX_MONEY_ZAT {
        return Err(format!("{field}: value must be between 1 and {MAX_MONEY_ZAT} zatoshis"));
    }
    // This is safe after the range check and matches librustzcash's monetary range.
    Ok(Zatoshis::const_from_u64(value))
}

fn parse_address(value: &str, field: &str) -> Result<Address, String> {
    let raw = hex_array::<43>(value, field)?;
    Address::from_raw_address_bytes(&raw)
        .into_option()
        .ok_or_else(|| format!("{field}: invalid raw Orchard address"))
}

fn parse_spending_note(
    raw_address_hex: &str,
    value_zat: u64,
    rho_hex: &str,
    rseed_hex: &str,
) -> Result<Note, String> {
    checked_value(value_zat, "note.value_zat")?;
    let address = parse_address(raw_address_hex, "note.raw_address_hex")?;
    let rho_bytes = hex_array::<32>(rho_hex, "note.rho_hex")?;
    let rho = Rho::from_bytes(&rho_bytes)
        .into_option()
        .ok_or_else(|| "note.rho_hex is not a canonical Orchard rho".to_string())?;
    let rseed_bytes = hex_array::<32>(rseed_hex, "note.rseed_hex")?;
    let rseed = RandomSeed::from_bytes(rseed_bytes, &rho)
        .into_option()
        .ok_or_else(|| "note.rseed_hex is invalid for its rho".to_string())?;
    Note::from_parts(address, NoteValue::from_raw(value_zat), rho, rseed, NoteVersion::V3)
        .into_option()
        .ok_or_else(|| "note fields do not form a valid Ironwood v3 note".to_string())
}

fn note_commitment(note: &Note) -> [u8; 32] {
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    cmx.to_bytes()
}

fn validate_expected_hex(actual: &[u8], expected: &str, field: &str) -> Result<(), String> {
    let expected = hex::decode(expected.trim())
        .map_err(|e| format!("{field}: invalid hex: {e}"))?;
    if expected.len() != actual.len() || expected.as_slice() != actual {
        return Err(format!("{field}: does not match the locally reconstructed note"));
    }
    Ok(())
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot restrict permissions on {}: {e}", path.display()))?;
    }
    Ok(())
}

fn parse_pczt(path: &Path) -> Result<Pczt, String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    pczt::parse(&bytes).map_err(|e| format!("invalid PCZT {}: {e:?}", path.display()))
}

/// Creates a private, unsigned PCZT from actual note openings and full viewing keys.
/// Spending keys never enter this function or its request type.
pub fn create_pczt_file(request_path: &Path, output_path: &Path) -> Result<Value, String> {
    if output_path.exists() {
        return Err(format!("refusing to overwrite existing PCZT: {}", output_path.display()));
    }
    let source = fs::read_to_string(request_path)
        .map_err(|e| format!("cannot read request {}: {e}", request_path.display()))?;
    let request: CreateRequest =
        serde_json::from_str(&source).map_err(|e| format!("invalid request JSON: {e}"))?;

    if request.inputs.is_empty() || request.outputs.is_empty() {
        return Err("a settlement PCZT needs at least one real input and one output".to_string());
    }
    if request.expiry_height <= request.target_height {
        return Err("expiry_height must be greater than target_height".to_string());
    }

    let mut rng = rng();
    let mut builder = DeferredPcztBuilder::new::<zip317::FeeError>(
        Network::TestNetwork,
        BlockHeight::from_u32(request.target_height),
        BundlePadding::DEFAULT,
        BundlePadding::DEFAULT,
    )
    .map_err(|e| format!("cannot create a V6/Ironwood PCZT at target height: {e:?}"))?
    .with_expiry_height(BlockHeight::from_u32(request.expiry_height));

    let mut expected_inputs = Vec::with_capacity(request.inputs.len());
    for input in &request.inputs {
        let fvk_bytes = hex_array::<96>(&input.fvk_hex, "input.fvk_hex")?;
        let fvk = FullViewingKey::from_bytes(&fvk_bytes)
            .ok_or_else(|| format!("input {} has an invalid FullViewingKey", input.id))?;
        let note = parse_spending_note(
            &input.raw_address_hex,
            input.value_zat,
            &input.rho_hex,
            &input.rseed_hex,
        )?;

        let cmx = note_commitment(&note);
        validate_expected_hex(&cmx, &input.expected_cmx_hex, "input.expected_cmx_hex")?;
        let nullifier = note.nullifier(&fvk).to_bytes();
        validate_expected_hex(
            &nullifier,
            &input.expected_nullifier_hex,
            "input.expected_nullifier_hex",
        )?;

        if expected_inputs.iter().any(|(nf, _, _): &([u8; 32], String, usize)| nf == &nullifier) {
            return Err(format!("duplicate nullifier supplied for input {}", input.id));
        }

        builder
            .add_ironwood_spend::<zip317::FeeError>(fvk, note)
            .map_err(|e| format!("cannot add input {} to PCZT: {e:?}", input.id))?;
        expected_inputs.push((nullifier, input.id.clone(), 0usize));
    }

    for output in &request.outputs {
        let address = parse_address(&output.raw_address_hex, "output.raw_address_hex")?;
        let amount = checked_value(output.value_zat, "output.value_zat")?;
        builder
            .add_ironwood_output::<zip317::FeeError>(
                None,
                address,
                amount,
                MemoBytes::empty(),
            )
            .map_err(|e| format!("cannot add output {} to PCZT: {e:?}", output.id))?;
    }

    let result = builder
        .build_for_pczt(&mut rng, &zip317::FeeRule::standard())
        .map_err(|e| {
            format!(
                "librustzcash rejected the requested inputs/outputs or fee balance: {e:?}"
            )
        })?;
    let pczt = Creator::build_from_parts(result.pczt_parts)
        .map_err(|e| format!("PCZT creator rejected builder output: {e:?}"))?;
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(&mut rng)
        .map_err(|e| format!("PCZT I/O finalization failed: {e:?}"))?;

    let actions = pczt.ironwood().actions();
    for (nf, id, action_index) in expected_inputs.iter_mut() {
        let found = actions.iter().position(|action| action.spend().nullifier() == nf);
        *action_index = found.ok_or_else(|| {
            format!("input {id}: corresponding Ironwood spend disappeared while building PCZT")
        })?;
    }

    let bytes = pczt
        .serialize()
        .map_err(|e| format!("cannot serialize the private PCZT: {e:?}"))?;
    private_write(output_path, &bytes)?;

    let inputs: Vec<CreatedSpend> = expected_inputs
        .into_iter()
        .map(|(nf, id, action_index)| CreatedSpend {
            id,
            nullifier_hex: hex::encode(nf),
            action_index,
        })
        .collect();

    Ok(json!({
        "status": "PCZT_CREATED_UNSIGNED",
        "output_file": output_path.display().to_string(),
        "target_height": request.target_height,
        "expiry_height": request.expiry_height,
        "inputs": inputs,
        "outputs": request.outputs.len(),
        "pczt_bytes": bytes.len(),
        "note": "Private PCZT created by librustzcash. It is not signed, proven, broadcast, or confirmed. Keep this file and the request local."
    }))
}

/// Adds one participant's spend authorization using a local key file and an explicit nullifier.
/// The key itself is never passed through command-line arguments or sent to the coordinator.
pub fn sign_pczt_file(
    input_path: &Path,
    spending_key_path: &Path,
    nullifier_hex: &str,
    output_path: &Path,
) -> Result<Value, String> {
    if output_path.exists() {
        return Err(format!("refusing to overwrite existing PCZT: {}", output_path.display()));
    }

    let key_text = fs::read_to_string(spending_key_path)
        .map_err(|e| format!("cannot read local spending-key file {}: {e}", spending_key_path.display()))?;
    let key_bytes = hex_array::<32>(key_text.trim(), "spending key file")?;
    let sk = SpendingKey::from_bytes(key_bytes)
        .into_option()
        .ok_or_else(|| "spending-key file is not a valid Orchard spending key".to_string())?;
    let ask = SpendAuthorizingKey::from(&sk);

    let requested_nf = hex_array::<32>(nullifier_hex, "nullifier")?;
    let pczt = parse_pczt(input_path)?;
    let actions = pczt.ironwood().actions();
    let action_index = actions
        .iter()
        .position(|action| action.spend().nullifier() == &requested_nf)
        .ok_or_else(|| "the requested nullifier is not present in this PCZT".to_string())?;

    let mut rng = rng();
    let mut signer = Signer::new(pczt)
        .map_err(|e| format!("cannot initialize official PCZT signer: {e:?}"))?;
    signer
        .sign_ironwood(&mut rng, action_index, &ask)
        .map_err(|e| {
            format!(
                "local spending key did not authorize the requested participant note (or signer validation failed): {e:?}"
            )
        })?;
    let signed = signer.finish();
    let bytes = signed
        .serialize()
        .map_err(|e| format!("cannot serialize signed PCZT: {e:?}"))?;
    private_write(output_path, &bytes)?;

    Ok(json!({
        "status": "PARTICIPANT_SIGNATURE_ADDED",
        "output_file": output_path.display().to_string(),
        "nullifier_hex": hex::encode(requested_nf),
        "action_index": action_index,
        "pczt_bytes": bytes.len(),
        "note": "The local key signed only the requested Ironwood spend. This is not a network transaction."
    }))
}

/// Merges independent signed PCZT contributions from participants.
pub fn combine_pczt_files(output_path: &Path, input_paths: &[PathBuf]) -> Result<Value, String> {
    if output_path.exists() {
        return Err(format!("refusing to overwrite existing PCZT: {}", output_path.display()));
    }
    if input_paths.len() < 2 {
        return Err("PCZT combination requires at least two participant PCZT files".to_string());
    }
    let mut pczts = Vec::with_capacity(input_paths.len());
    for path in input_paths {
        pczts.push(parse_pczt(path)?);
    }
    let combined = Combiner::new(pczts)
        .combine()
        .map_err(|e| format!("participant PCZTs are incompatible or conflict: {e:?}"))?;
    let bytes = combined
        .serialize()
        .map_err(|e| format!("cannot serialize combined PCZT: {e:?}"))?;
    private_write(output_path, &bytes)?;

    Ok(json!({
        "status": "PCZT_CONTRIBUTIONS_COMBINED",
        "output_file": output_path.display().to_string(),
        "contributions": input_paths.len(),
        "pczt_bytes": bytes.len(),
        "note": "Signatures were combined; no Merkle witness, proof, transaction extraction, broadcast, or confirmation has been performed."
    }))
}

fn parse_witness_path(input: &WitnessedSpend) -> Result<(Note, [u8; 32], MerklePath), String> {
    if input.auth_path_hex.len() != 32 {
        return Err(format!(
            "nullifier {}: auth_path_hex must contain exactly 32 siblings",
            input.nullifier_hex
        ));
    }
    let note = parse_spending_note(
        &input.raw_address_hex,
        input.value_zat,
        &input.rho_hex,
        &input.rseed_hex,
    )?;
    let cmx = note_commitment(&note);
    validate_expected_hex(&cmx, &input.expected_cmx_hex, "witness.expected_cmx_hex")?;

    let mut siblings = Vec::with_capacity(32);
    for (index, sibling) in input.auth_path_hex.iter().enumerate() {
        let raw = hex_array::<32>(sibling, &format!("auth_path_hex[{index}]"))?;
        let node = MerkleHashOrchard::from_bytes(&raw)
            .into_option()
            .ok_or_else(|| format!("auth_path_hex[{index}] is not a canonical Merkle node"))?;
        siblings.push(node);
    }
    let auth_path: [MerkleHashOrchard; 32] = siblings
        .try_into()
        .map_err(|_| "auth path must contain 32 siblings".to_string())?;
    let path = MerklePath::from_parts(input.position, auth_path);
    Ok((note, cmx, path))
}

/// Installs the real shared anchor and witnesses, creates and verifies the official Ironwood
/// Halo 2 proof, extracts a fully authorized transaction, and writes its raw bytes privately.
pub fn prove_and_extract_file(
    input_path: &Path,
    witness_path: &Path,
    raw_tx_output_path: &Path,
) -> Result<Value, String> {
    if raw_tx_output_path.exists() {
        return Err(format!(
            "refusing to overwrite existing transaction file: {}",
            raw_tx_output_path.display()
        ));
    }
    let source = fs::read_to_string(witness_path)
        .map_err(|e| format!("cannot read witness manifest {}: {e}", witness_path.display()))?;
    let manifest: WitnessManifest =
        serde_json::from_str(&source).map_err(|e| format!("invalid witness manifest JSON: {e}"))?;
    if manifest.inputs.is_empty() {
        return Err("witness manifest contains no real spends".to_string());
    }

    let pczt = parse_pczt(input_path)?;
    let actions = pczt.ironwood().actions();
    let mut anchor: Option<Anchor> = None;
    let mut witness_updates: Vec<(usize, MerklePath)> = Vec::with_capacity(manifest.inputs.len());
    let mut seen_nullifiers = std::collections::HashSet::<[u8; 32]>::new();

    for input in &manifest.inputs {
        let nullifier = hex_array::<32>(&input.nullifier_hex, "witness.nullifier_hex")?;
        if !seen_nullifiers.insert(nullifier) {
            return Err(format!("duplicate witness for nullifier {}", input.nullifier_hex));
        }
        let action_index = actions
            .iter()
            .position(|action| action.spend().nullifier() == &nullifier)
            .ok_or_else(|| {
                format!(
                    "witness nullifier {} is not present in the combined PCZT",
                    input.nullifier_hex
                )
            })?;

        let (note, cmx, path) = parse_witness_path(input)?;
        let _ = note; // The official Prover checks the PCZT note opening against this path.
        let computed_anchor: Anchor = path.root(ExtractedNoteCommitment::from_bytes(&cmx)
            .into_option()
            .ok_or_else(|| "invalid reconstructed note commitment".to_string())?)
            .into();

        if let Some(expected_anchor) = anchor {
            if expected_anchor != computed_anchor {
                return Err(format!(
                    "witness for nullifier {} roots to a different anchor; all inputs must use one chain state",
                    input.nullifier_hex
                ));
            }
        } else {
            anchor = Some(computed_anchor);
        }
        witness_updates.push((action_index, path));
    }

    let anchor = anchor.ok_or_else(|| "no valid shared anchor was derived".to_string())?;
    let anchored = Updater::new(pczt)
        .set_ironwood_anchor(anchor)
        .map_err(|e| format!("cannot install Ironwood anchor: {e:?}"))?
        .set_ironwood_spend_witnesses(witness_updates)
        .map_err(|e| format!("cannot install Ironwood Merkle witnesses: {e:?}"))?
        .finish();

    let mut rng = rng();
    let proving_key = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let proved = Prover::new(anchored)
        .create_ironwood_proof(&mut rng, &proving_key)
        .map_err(|e| {
            format!(
                "official Ironwood proof generation or witness-root validation failed: {e:?}"
            )
        })?
        .finish();

    let tx = TransactionExtractor::new(proved)
        .extract(&mut rng)
        .map_err(|e| {
            format!(
                "official Zcash transaction extractor rejected the PCZT (signature/proof/anchor failure): {e:?}"
            )
        })?;

    let txid = tx.txid().to_string();
    let mut raw_tx = Vec::<u8>::new();
    tx.write(&mut raw_tx)
        .map_err(|e| format!("cannot serialize extracted Zcash transaction: {e}"))?;
    private_write(raw_tx_output_path, &raw_tx)?;

    Ok(json!({
        "status": "LOCALLY_VERIFIED_TRANSACTION_EXTRACTED",
        "output_file": raw_tx_output_path.display().to_string(),
        "txid": txid,
        "raw_tx_bytes": raw_tx.len(),
        "anchor_hex": hex::encode(anchor.to_bytes()),
        "target_height": tx.expiry_height().to_string(),
        "network": "Zcash Testnet",
        "validation": "librustzcash TransactionExtractor accepted the proof-bearing, fully authorized transaction",
        "broadcast": false,
        "confirmed": false,
        "note": "A locally extracted transaction is not yet a Testnet transaction. It still requires explicit broadcast to a synchronized Zebra Testnet node and subsequent confirmation verification."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_fixed_width_hex_without_truncation() {
        assert!(hex_array::<32>("00", "test").is_err());
        assert!(hex_array::<32>(&"00".repeat(32), "test").is_ok());
        assert!(hex_array::<43>(&"00".repeat(43), "test").is_ok());
    }

    #[test]
    fn rejects_out_of_range_values_before_builder_calls() {
        assert!(checked_value(0, "value").is_err());
        assert!(checked_value(MAX_MONEY_ZAT + 1, "value").is_err());
        assert!(checked_value(100_000_000, "value").is_ok());
    }
}
