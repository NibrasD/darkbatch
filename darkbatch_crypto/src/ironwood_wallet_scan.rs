//! Local Ironwood V3 wallet scanner for the Testnet coordinator flow.
//!
//! This is a wallet-side component, not an RPC server feature. The spending key is
//! read from one request on stdin and is never returned or written into wallet state.
//! It starts from an authenticated Zebra treestate snapshot and tracks notes received
//! after that checkpoint, together with incremental Merkle witnesses.

use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, Note, NoteVersion, Rho, RandomSeed},
    note_encryption::IronwoodDomain,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Address,
};
use incrementalmerkletree::{
    frontier::{CommitmentTree, PathFiller},
    witness::IncrementalWitness,
    Hashable,
};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::{
    block::Block,
    merkle_tree::{
        read_commitment_tree, read_incremental_witness, write_commitment_tree,
        write_incremental_witness,
    },
    transaction::Transaction,
};
use zcash_protocol::{
    consensus::Network,
    value::Zatoshis,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IronwoodScanRequest {
    pub network: String,
    pub expected_height: u32,
    pub expected_block_hash: String,
    pub expected_prev_block_hash: String,
    pub raw_block_hex: String,
    /// Zebra z_gettreestate(...).ironwood.commitments.finalState as hex.
    /// Must exactly match the local tree state from the previously processed block.
    pub expected_final_state_hex: String,
    pub tree_state_hex: String,
    /// Supplied at runtime by the local wallet process; never persisted in the scan state.
    pub spending_key_hex: String,
    #[serde(default)]
    pub tracked_notes: Vec<IronwoodTrackedNote>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct IronwoodTrackedNote {
    pub note_id: String,
    pub received_height: u32,
    pub txid: String,
    pub action_index: u32,
    pub raw_address_hex: String,
    pub value_zat: u64,
    pub rho_hex: String,
    pub rseed_hex: String,
    pub cmx_hex: String,
    pub nullifier_hex: String,
    pub memo_hex: String,
    /// UN SPENT notes carry a serialized IncrementalWitness. SPENT notes do not.
    pub status: String,
    #[serde(default)]
    pub witness_state_hex: Option<String>,
    #[serde(default)]
    pub witness_position: Option<u32>,
    #[serde(default)]
    pub witness_auth_path_hex: Vec<String>,
    #[serde(default)]
    pub witness_root_hex: Option<String>,
}

#[derive(serde::Serialize)]
pub struct IronwoodScanResult {
    pub status: &'static str,
    pub network: &'static str,
    pub height: u32,
    pub block_hash: String,
    pub prev_block_hash: String,
    pub tree_root_hex: String,
    pub tree_state_hex: String,
    pub tracked_notes: Vec<IronwoodTrackedNote>,
    pub new_note_ids: Vec<String>,
    pub spent_note_ids: Vec<String>,
    pub ironwood_actions_processed: usize,
}

/// One block is processed against one prior tree snapshot. The caller must query
/// the same canonical block's Zebra treestate and compare finalState byte-for-byte
/// before committing this result to disk.
pub fn scan_ironwood_block_json(input_json: &str) -> Result<IronwoodScanResult, String> {
    let request: IronwoodScanRequest = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid Ironwood scan request JSON: {e}"))?;
    if request.network != "testnet" {
        return Err("The local wallet scanner currently permits Testnet only.".into());
    }

    let key_bytes: [u8; 32] = parse_fixed_hex(&request.spending_key_hex, "spending_key_hex")?;
    let spending_key = SpendingKey::from_bytes(key_bytes)
        .into_option()
        .ok_or_else(|| "Invalid Ironwood spending key encoding.".to_owned())?;
    let fvk = FullViewingKey::from(&spending_key);
    // Wallet scans must cover both scopes. External is for received funds;
    // Internal is commonly used for change outputs. Missing the latter can
    // silently hide a wallet's own spendable change notes from later batches.
    let external_ivk = fvk.to_ivk(Scope::External);
    let prepared_external_ivk = PreparedIncomingViewingKey::new(&external_ivk);
    let internal_ivk = fvk.to_ivk(Scope::Internal);
    let prepared_internal_ivk = PreparedIncomingViewingKey::new(&internal_ivk);

    let tree_bytes = hex::decode(&request.tree_state_hex)
        .map_err(|_| "tree_state_hex must be valid hexadecimal.".to_owned())?;
    let mut tree: CommitmentTree<MerkleHashOrchard, 32> =
        read_commitment_tree::<MerkleHashOrchard, _, 32>(tree_bytes.as_slice())
            .map_err(|e| format!("Could not decode the Zebra Ironwood finalState: {e}"))?;

    // Refuse mismatched states before updating any note. This prevents silently
    // appending a block twice or applying it to a different treestate checkpoint.
    if request.expected_final_state_hex.to_lowercase() != request.tree_state_hex.to_lowercase() {
        return Err("Provided pre-block tree state differs from expected_final_state_hex.".into());
    }

    let raw_block = hex::decode(&request.raw_block_hex)
        .map_err(|_| "raw_block_hex must be valid hexadecimal.".to_owned())?;
    let block = Block::read(raw_block.as_slice(), &Network::TestNetwork)
        .map_err(|e| format!("Could not parse the serialized Testnet block: {e}"))?;
    let claimed_height = u32::from(block.claimed_height());
    if claimed_height != request.expected_height {
        return Err(format!(
            "Block height mismatch: Zebra requested {}, serialized block claims {}.",
            request.expected_height, claimed_height
        ));
    }
    let (header, transactions) = block.into_parts();
    let block_hash = header.hash().to_string().to_lowercase();
    let prev_block_hash = header.prev_block.to_string().to_lowercase();
    if block_hash != request.expected_block_hash.to_lowercase() {
        return Err("Serialized block hash does not match the canonical hash from Zebra.".into());
    }
    if prev_block_hash != request.expected_prev_block_hash.to_lowercase() {
        return Err("Serialized block parent hash does not match the expected chain parent.".into());
    }

    let mut tracked_notes = request.tracked_notes;
    let mut witnesses: Vec<Option<IncrementalWitness<MerkleHashOrchard, 32>>> =
        Vec::with_capacity(tracked_notes.len());

    for note in &tracked_notes {
        if note.status == "UNSPENT" {
            let encoded = note.witness_state_hex.as_ref().ok_or_else(|| {
                format!("Unspent note {} has no serialized witness.", note.note_id)
            })?;
            let witness_bytes = hex::decode(encoded)
                .map_err(|_| format!("Note {} witness is not valid hex.", note.note_id))?;
            let witness =
                read_incremental_witness::<MerkleHashOrchard, _, 32>(witness_bytes.as_slice())
                    .map_err(|e| format!("Could not restore witness for {}: {e}", note.note_id))?;
            witnesses.push(Some(witness));
        } else if note.status == "SPENT" {
            witnesses.push(None);
        } else {
            return Err(format!("Note {} has an unknown state {:?}.", note.note_id, note.status));
        }
    }

    let mut new_note_ids = Vec::new();
    let mut spent_note_ids = Vec::new();
    let mut ironwood_actions_processed = 0usize;

    for tx in transactions.iter() {
        let txid = tx.txid().to_string().to_lowercase();
        if let Some(bundle) = tx.ironwood_bundle() {
            for (action_index, action) in bundle.actions().iter().enumerate() {
                ironwood_actions_processed += 1;
                let nullifier_hex = hex::encode(action.nullifier().to_bytes());

                // A tracked note's nullifier appearing in this action means that the
                // note was spent on-chain. It is removed from the spendable witness set.
                for (index, note) in tracked_notes.iter_mut().enumerate() {
                    if note.status == "UNSPENT" && note.nullifier_hex == nullifier_hex {
                        note.status = "SPENT".to_owned();
                        note.witness_state_hex = None;
                        note.witness_position = None;
                        note.witness_auth_path_hex.clear();
                        note.witness_root_hex = None;
                        witnesses[index] = None;
                        spent_note_ids.push(note.note_id.clone());
                    }
                }

                let leaf = MerkleHashOrchard::from_cmx(action.cmx());

                // Every Ironwood action adds a note commitment, whether or not the
                // output belongs to this wallet. Update existing witnesses first.
                for witness in witnesses.iter_mut().flatten() {
                    witness
                        .append(leaf)
                        .map_err(|_| "A tracked witness could not append an Ironwood leaf; rescan from a trusted checkpoint.".to_owned())?;
                }
                tree.append(leaf)
                    .map_err(|_| "Ironwood commitment tree could not append a leaf.".to_owned())?;

                let domain = IronwoodDomain::for_action(action);
                // Try the external receiver first, then the internal receiver
                // used by ordinary wallet change. Both are controlled by the
                // same spending key but derive distinct incoming viewing keys.
                let decrypted = try_note_decryption(&domain, &prepared_external_ivk, action)
                    .or_else(|| try_note_decryption(&domain, &prepared_internal_ivk, action));
                if let Some((note, recipient, memo)) = decrypted {
                    if note.version() != NoteVersion::V3 {
                        return Err("Ironwood decryption returned a non-V3 note; refusing to track it.".into());
                    }
                    let cmx = ExtractedNoteCommitment::from(note.commitment());
                    if cmx.to_bytes() != action.cmx().to_bytes() {
                        return Err("Decrypted note commitment does not match the action's cmx.".into());
                    }

                    let witness = IncrementalWitness::from_tree(tree.clone())
                        .ok_or_else(|| "Could not construct a witness for the new Ironwood note.".to_owned())?;
                    let note_id = format!("{}:{}:{}", claimed_height, txid, action_index);
                    let raw_address = recipient.to_raw_address_bytes();
                    let value_zat = note.value().inner();
                    let nullifier_hex = hex::encode(note.nullifier(&fvk).to_bytes());

                    tracked_notes.push(IronwoodTrackedNote {
                        note_id: note_id.clone(),
                        received_height: claimed_height,
                        txid: txid.clone(),
                        action_index: action_index as u32,
                        raw_address_hex: hex::encode(raw_address),
                        value_zat,
                        rho_hex: hex::encode(note.rho().to_bytes()),
                        rseed_hex: hex::encode(note.rseed().as_bytes()),
                        cmx_hex: hex::encode(cmx.to_bytes()),
                        nullifier_hex,
                        memo_hex: hex::encode(memo),
                        status: "UNSPENT".to_owned(),
                        witness_state_hex: None,
                        witness_position: None,
                        witness_auth_path_hex: Vec::new(),
                        witness_root_hex: None,
                    });
                    witnesses.push(Some(witness));
                    new_note_ids.push(note_id);
                }
            }
        }
    }

    let tree_root = tree.root_at_depth(32, PathFiller::empty()).to_bytes();

    // Persist both the advancing witness state and its compact path for transaction
    // building. The path is re-derived from the canonical incremental witness at
    // the new chain tip; it is never synthesized from a claimed note position.
    for (index, note) in tracked_notes.iter_mut().enumerate() {
        if note.status != "UNSPENT" {
            continue;
        }
        let witness = witnesses[index]
            .as_ref()
            .ok_or_else(|| format!("Unspent note {} lost its witness.", note.note_id))?;
        let mut witness_bytes = Vec::new();
        write_incremental_witness(witness, &mut witness_bytes)
            .map_err(|e| format!("Could not serialize witness for {}: {e}", note.note_id))?;
        note.witness_state_hex = Some(hex::encode(witness_bytes));

        let path = witness
            .path()
            .ok_or_else(|| format!("Could not derive current Merkle path for {}.", note.note_id))?;
        let orchard_path: MerklePath = path.into();
        let cmx_bytes: [u8; 32] = parse_fixed_hex(&note.cmx_hex, "cmx_hex")?;
        let cmx = ExtractedNoteCommitment::from_bytes(&cmx_bytes)
            .into_option()
            .ok_or_else(|| format!("Note {} has a noncanonical cmx.", note.note_id))?;
        let witness_root = orchard_path.root(cmx).to_bytes();
        if witness_root != tree_root {
            return Err(format!(
                "Witness for {} no longer matches the current local tree root; refusing to persist stale note state.",
                note.note_id
            ));
        }
        note.witness_position = Some(orchard_path.position());
        note.witness_auth_path_hex = orchard_path
            .auth_path()
            .iter()
            .map(|node| hex::encode(node.to_bytes()))
            .collect();
        note.witness_root_hex = Some(hex::encode(witness_root));
    }

    let mut updated_tree_bytes = Vec::new();
    write_commitment_tree(&tree, &mut updated_tree_bytes)
        .map_err(|e| format!("Could not serialize the updated Ironwood tree: {e}"))?;

    Ok(IronwoodScanResult {
        status: "SCANNED_BLOCK",
        network: "testnet",
        height: claimed_height,
        block_hash,
        prev_block_hash,
        tree_root_hex: hex::encode(tree_root),
        tree_state_hex: hex::encode(updated_tree_bytes),
        tracked_notes,
        new_note_ids,
        spent_note_ids,
        ironwood_actions_processed,
    })
}

fn parse_fixed_hex<const N: usize>(hex_value: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(hex_value).map_err(|_| format!("{field} must be valid hexadecimal."))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!("{field} must be exactly {N} bytes; got {}.", bytes.len())
    })
}


/// Derive the official Ironwood anchor from Zebra's serialized finalState.
/// This permits initial checkpoints to be validated without inventing an anchor.
pub fn ironwood_tree_root_json(input_json: &str) -> Result<serde_json::Value, String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        tree_state_hex: String,
    }
    let request: Request = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid tree-root request JSON: {e}"))?;
    let bytes = hex::decode(&request.tree_state_hex)
        .map_err(|_| "tree_state_hex must be valid hexadecimal.".to_owned())?;
    let tree: CommitmentTree<MerkleHashOrchard, 32> =
        read_commitment_tree::<MerkleHashOrchard, _, 32>(bytes.as_slice())
            .map_err(|e| format!("Could not decode Ironwood finalState: {e}"))?;
    let root = tree.root_at_depth(32, PathFiller::empty()).to_bytes();
    Ok(serde_json::json!({
        "status": "TREE_ROOT",
        "tree_root_hex": hex::encode(root),
    }))
}


/// Derive a standard Zcash Testnet Unified Address using the shared Orchard key
/// material that authorizes both the old Orchard pool and the new Ironwood pool.
/// The spending key is read from stdin by the caller and is never returned.
pub fn derive_ironwood_address_json(input_json: &str) -> Result<serde_json::Value, String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        network: String,
        spending_key_hex: String,
        address_index: u32,
        #[serde(default)]
        scope: Option<String>,
    }
    let request: Request = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid address request JSON: {e}"))?;
    if request.network != "testnet" {
        return Err("Address derivation is restricted to Testnet.".into());
    }
    let key_bytes: [u8; 32] = parse_fixed_hex(&request.spending_key_hex, "spending_key_hex")?;
    let spending_key = SpendingKey::from_bytes(key_bytes)
        .into_option()
        .ok_or_else(|| "Invalid raw Orchard-protocol spending key.".to_owned())?;
    let fvk = FullViewingKey::from(&spending_key);
    let scope_name = request.scope.as_deref().unwrap_or("external");
    let scope = match scope_name {
        "external" => Scope::External,
        "internal" => Scope::Internal,
        _ => return Err("scope must be either 'external' or 'internal'.".into()),
    };
    let address = fvk.address_at(request.address_index, scope);
    let raw_address = address.to_raw_address_bytes();
    let unified_address = zcash_keys::address::UnifiedAddress::from_receivers(
        Some(address),
        None,
        None,
        None,
        None,
    )
    .ok_or_else(|| "Could not encode the Ironwood-capable receiver as a Unified Address.".to_owned())?;
    let encoded = unified_address.encode(&Network::TestNetwork);
    Ok(serde_json::json!({
        "status": "DERIVED_TESTNET_ADDRESS",
        "network": "testnet",
        "address_index": request.address_index,
        "scope": scope_name,
        "unified_address": encoded,
        "raw_ironwood_receiver_hex": hex::encode(raw_address),
        "note": "The Orchard-protocol receiver format is shared; NU6.3 sends to the Ironwood pool in v6 transactions. The spending key was not returned."
    }))
}


/// Export the full viewing key for a trusted local collaborative-PCZT workflow.
/// This is intentionally separate from address derivation because a full viewing key
/// reveals wallet history and must not be sent to the public coordinator.
pub fn export_ironwood_fvk_json(input_json: &str) -> Result<serde_json::Value, String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        network: String,
        spending_key_hex: String,
    }
    let request: Request = serde_json::from_str(input_json)
        .map_err(|e| format!("Invalid local FVK export request JSON: {e}"))?;
    if request.network != "testnet" {
        return Err("Full-viewing-key export is restricted to Testnet in this tool.".into());
    }
    let key_bytes: [u8; 32] = parse_fixed_hex(&request.spending_key_hex, "spending_key_hex")?;
    let spending_key = SpendingKey::from_bytes(key_bytes)
        .into_option()
        .ok_or_else(|| "Invalid raw Ironwood spending key.".to_owned())?;
    let fvk = FullViewingKey::from(&spending_key);
    let ivk = fvk.to_ivk(Scope::External);
    let address = fvk.address_at(0u32, Scope::External);
    let unified = zcash_keys::address::UnifiedAddress::from_receivers(
        Some(address),
        None,
        None,
        None,
        None,
    )
    .ok_or_else(|| "Could not construct the wallet Unified Address.".to_owned())?;

    Ok(serde_json::json!({
        "status": "LOCAL_FVK_EXPORTED",
        "network": "testnet",
        "full_viewing_key_hex": hex::encode(fvk.to_bytes()),
        "incoming_viewing_key_hex": hex::encode(ivk.to_bytes()),
        "unified_address": unified.encode(&Network::TestNetwork),
        "warning": "The full viewing key reveals wallet history. Keep this output local and do not send it to the public coordinator. The spending key is not returned."
    }))
}

#[cfg(test)]
mod address_tests {
    use super::derive_ironwood_address_json;

    #[test]
    fn derives_a_standard_testnet_unified_address_without_returning_key_material() {
        let request = serde_json::json!({
            "network": "testnet",
            "spending_key_hex": hex::encode([0u8; 32]),
            "address_index": 0,
            "scope": "external"
        });
        let result = derive_ironwood_address_json(&request.to_string()).unwrap();
        assert_eq!(result["status"], "DERIVED_TESTNET_ADDRESS");
        assert_eq!(result["network"], "testnet");
        assert_eq!(result["scope"], "external");
        assert!(result["unified_address"].as_str().unwrap().len() > 20);
        assert_eq!(result["raw_ironwood_receiver_hex"].as_str().unwrap().len(), 86);
        assert!(result.get("spending_key_hex").is_none());
        assert!(result.get("ivk_hex").is_none());

        let internal_request = serde_json::json!({
            "network": "testnet",
            "spending_key_hex": hex::encode([0u8; 32]),
            "address_index": 1,
            "scope": "internal"
        });
        let internal = derive_ironwood_address_json(&internal_request.to_string()).unwrap();
        assert_eq!(internal["scope"], "internal");
        assert_ne!(
            result["raw_ironwood_receiver_hex"],
            internal["raw_ironwood_receiver_hex"]
        );
    }
}
