//! Official Zcash V6 / NU6.3 transaction construction for local settlement agents.
//!
//! This module replaces transaction-shaped byte assembly with the official
//! zcash_primitives Builder -> PCZT -> participant signing -> Halo 2 proof ->
//! Transaction extraction flow. The build JSON and intermediate PCZT contain sensitive
//! note data and viewing-key material; keep them on a trusted local machine. Spending keys
//! are loaded only by the local signing command, never by the DarkBatch API.
use std::fs;

use orchard::{
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Address,
};
use pczt::{
    Pczt,
    roles::{
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
    consensus::{BlockHeight, Network},
    memo::MemoBytes,
    value::Zatoshis,
};

const TESTNET_NU6_3_HEIGHT: u32 = 4_134_000;

#[derive(Debug, Deserialize)]
pub struct PcztBuildRequest {
    pub target_height: u32,
    pub ironwood_anchor_hex: String,
    pub inputs: Vec<PcztSpendInput>,
    pub outputs: Vec<PcztRecipient>,
    pub change_fvk_hex: String,
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
#[derive(Debug, Clone, Serialize)]
pub struct PcztBuildReport {
    pub status: String,
    pub network: String,
    pub target_height: u32,
    pub expiry_height: u32,
    pub ironwood_anchor_hex: String,
    pub input_count: usize,
    pub recipient_output_count: usize,
    pub input_total_zat: u64,
    pub recipient_total_zat: u64,
    pub fee_zat: u64,
    pub change_zat: u64,
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
    let fvk = FullViewingKey::from_bytes(&fvk_bytes).into_option()
        .ok_or_else(|| "input.fvk_hex is not a valid Zcash FullViewingKey".to_string())?;
    let address_bytes = decode_array::<43>(&input.raw_address_hex, "input.raw_address_hex")?;
    let address = Address::from_raw_address_bytes(&address_bytes).into_option()
        .ok_or_else(|| "input.raw_address_hex is not a valid raw Ironwood address".to_string())?;
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

fn build_pczt(request: &PcztBuildRequest) -> Result<(Pczt, PcztBuildReport), String> {
    if request.target_height < TESTNET_NU6_3_HEIGHT {
        return Err(format!("target_height must be >= Testnet NU6.3 activation height {TESTNET_NU6_3_HEIGHT}"));
    }
    if request.inputs.is_empty() || request.outputs.is_empty() {
        return Err("at least one real spend input and recipient output are required".into());
    }
    let anchor_bytes = decode_array::<32>(&request.ironwood_anchor_hex, "ironwood_anchor_hex")?;
    let anchor = Anchor::from_bytes(anchor_bytes).into_option()
        .ok_or_else(|| "ironwood_anchor_hex is not a canonical Orchard anchor".to_string())?;
    let spends: Vec<PreparedSpend> = request.inputs.iter().map(|i| prepare_spend(i, anchor)).collect::<Result<_,_>>()?;
    let outputs: Vec<PreparedOutput> = request.outputs.iter().enumerate().map(|(i,o)| prepare_output(o,i)).collect::<Result<_,_>>()?;
    let change_fvk_bytes = decode_array::<96>(&request.change_fvk_hex, "change_fvk_hex")?;
    let change_fvk = FullViewingKey::from_bytes(&change_fvk_bytes).into_option()
        .ok_or_else(|| "change_fvk_hex is not a valid FullViewingKey".to_string())?;
    let change_address_bytes = decode_array::<43>(&request.change_address_raw_hex, "change_address_raw_hex")?;
    let change_address = Address::from_raw_address_bytes(&change_address_bytes).into_option()
        .ok_or_else(|| "change_address_raw_hex is not a valid Ironwood address".to_string())?;
    let change_ovk = change_fvk.to_ovk(Scope::Internal);

    let input_total = spends.iter().try_fold(0u64, |sum, input| sum.checked_add(input.value_zat).ok_or_else(|| "input sum overflowed".to_string()))?;
    let output_total = outputs.iter().try_fold(0u64, |sum, output| sum.checked_add(output.value_zat).ok_or_else(|| "output sum overflowed".to_string()))?;
    zatoshis(input_total, "input total")?;
    zatoshis(output_total, "recipient output total")?;

    // Probe and final transaction use identical action counts, including the change action.
    // Consequently the standard ZIP 317 fee must remain unchanged when the change value is replaced.
    macro_rules! make_builder {
        ($change_value:expr) => {{
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
            builder.add_ironwood_output::<zip317::FeeRule>(Some(change_ovk.clone()), change_address.clone(), zatoshis($change_value, "change amount")?, MemoBytes::empty())
                .map_err(|e| format!("invalid Ironwood change output: {e:?}"))?;
            builder
        }};
    }

    let fee = make_builder!(1u64).get_fee(&zip317::FeeRule::standard())
        .map_err(|e| format!("ZIP 317 fee calculation failed: {e:?}"))?.into_u64();
    let change = input_total.checked_sub(output_total.checked_add(fee).ok_or_else(|| "fee sum overflowed".to_string())?)
        .ok_or_else(|| format!("insufficient input: {input_total} zat in, {output_total} zat to recipients, ZIP 317 fee {fee} zat"))?;
    if change == 0 { return Err("change output would be zero; adjust inputs or recipient values".into()); }
    let builder = make_builder!(change);
    let final_fee = builder.get_fee(&zip317::FeeRule::standard())
        .map_err(|e| format!("final ZIP 317 fee calculation failed: {e:?}"))?.into_u64();
    if fee != final_fee || output_total + change + fee != input_total {
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
        ironwood_anchor_hex: hex::encode(anchor.to_bytes()),
        input_count: spends.len(),
        recipient_output_count: outputs.len(),
        input_total_zat: input_total,
        recipient_total_zat: output_total,
        fee_zat: fee,
        change_zat: change,
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
fn prove_and_extract(pczt: Pczt) -> Result<Vec<u8>, String> {
    let proving_key = orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let mut rng = rand::rng();
    let proved = Prover::new(pczt)
        .create_ironwood_proof(&mut rng, &proving_key)
        .map_err(|e| format!("official Ironwood Halo 2 proof failed: {e:?}"))?
        .finish();
    let tx = TransactionExtractor::new(proved).extract(&mut rng)
        .map_err(|e| format!("TransactionExtractor rejected the transaction: {e:?}"))?;
    let mut raw = Vec::new();
    tx.write(&mut raw).map_err(|e| format!("transaction serialization failed: {e}"))?;
    if raw.len() < 1_000 { return Err(format!("extracted transaction is unexpectedly short: {} bytes", raw.len())); }
    let version = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if version != 0x8000_0006 { return Err(format!("expected transaction v6, got 0x{version:08x}")); }
    Ok(raw)
}
pub fn prove_extract_pczt_to_hex_file(pczt_input_path: &str, tx_hex_output_path: &str, report_output_path: &str) -> Result<(), String> {
    let bytes = fs::read(pczt_input_path).map_err(|e| format!("could not read signed PCZT: {e}"))?;
    let pczt = Pczt::parse(&bytes).map_err(|e| format!("input is not a valid PCZT: {e:?}"))?;
    let raw = prove_and_extract(pczt)?;
    fs::write(tx_hex_output_path, hex::encode(&raw)).map_err(|e| format!("could not write raw transaction hex: {e}"))?;
    let report = serde_json::json!({
        "status": "PROOF_GENERATED_AND_TRANSACTION_EXTRACTED",
        "network": "Zcash Testnet",
        "transaction_version": 6,
        "raw_transaction_bytes": raw.len(),
        "broadcast_ready": true,
        "network_confirmed": false,
        "warning": "This is a V6 transaction extracted by official Zcash Rust libraries. This tool has not proved the note remains unspent or that Zebra will accept the transaction. Broadcast to activated Testnet Zebra and verify its txid and block confirmation before recording an FBA epoch."
    });
    fs::write(report_output_path, serde_json::to_vec_pretty(&report).map_err(|e| format!("report serialization failed: {e}"))?)
        .map_err(|e| format!("could not write transaction report: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let raw = prove_and_extract(signed).expect("prove and extract real v6 transaction");
        assert!(raw.len() > 1_000);
        assert_eq!(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]), 0x8000_0006);
    }
}
