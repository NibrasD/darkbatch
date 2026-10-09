use darkbatch_crypto::memo::{encrypt_512_memo, decrypt_512_memo};
use darkbatch_crypto::pallas_ops::{pedersen_commit, random_scalar};
use group::GroupEncoding;
use pasta_curves::pallas::Scalar;
use ff::PrimeField;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("DarkBatch Rust Cryptographic Engine v2.0 (Ironwood / Pallas)");
        println!("Usage: darkbatch_crypto [commit | test-memo | scan-ironwood-block-stdin | build-ironwood-transaction-stdin]");
        return;
    }

    match args[1].as_str() {
        "commit" => {
            let val: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100_000_000);
            let r = if let Some(r_hex) = args.get(3) {
                let bytes = hex::decode(r_hex).unwrap_or_default();
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Scalar::from_repr(arr).unwrap_or_else(|| random_scalar())
                } else {
                    random_scalar()
                }
            } else {
                random_scalar()
            };
            let c = pedersen_commit(val, &r);
            println!("{}", serde_json::json!({
                "value_zat": val,
                "scalar_r": hex::encode(r.to_repr()),
                "commitment_point": hex::encode(c.to_bytes())
            }));
        }
        "test-memo" => {
            let key = [77u8; 32];
            let msg = b"DarkBatch Confidential Execution Receipt: 25.0 ZEC @ $42.60";
            let memo = encrypt_512_memo(msg, &key).expect("Encrypt failed");
            println!("Memo Length: {} bytes (strictly 512 bytes)", memo.len());
            let decrypted = decrypt_512_memo(&memo, &key).expect("Decrypt failed");
            println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
        }
        "scan-ironwood-block-stdin" => {
            // The spending key is passed only through stdin and is not emitted in output.
            use std::io::Read;
            let mut input_json = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut input_json) {
                eprintln!("Could not read scan request from stdin: {e}");
                std::process::exit(2);
            }
            match darkbatch_crypto::scan_ironwood_block_json(&input_json) {
                Ok(result) => println!("{}", serde_json::to_string(&result).expect("scan result serializes")),
                Err(e) => {
                    eprintln!("Ironwood wallet scan failed closed: {e}");
                    std::process::exit(2);
                }
            }
        }
        "build-ironwood-transaction-stdin" => {
            // Raw secret keys are read from stdin, not command-line arguments or logs.
            // Input must contain real note data and witnesses from a wallet + live Zebra treestate.
            use std::io::Read;
            let mut input_json = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut input_json) {
                eprintln!("Could not read build request from stdin: {e}");
                std::process::exit(2);
            }
            match darkbatch_crypto::build_ironwood_transaction_from_json(&input_json) {
                Ok(tx) => {
                    println!("{}", serde_json::json!({
                        "status": "BUILT_NOT_BROADCAST",
                        "consensus_ready": true,
                        "broadcast": false,
                        "network": "testnet",
                        "txid": tx.txid_hex,
                        "raw_tx_hex": tx.raw_tx_hex,
                        "raw_tx_bytes_len": tx.raw_tx_bytes_len,
                        "target_height": tx.target_height,
                        "consensus_branch_id": format!("0x{:08x}", tx.consensus_branch_id),
                        "transaction_version": tx.transaction_version,
                        "version_group_id": format!("0x{:08x}", tx.version_group_id),
                        "note": "Built by the official zcash_primitives v6 builder from caller-supplied notes and Merkle witnesses. Not broadcast or confirmed."
                    }));
                }
                Err(e) => {
                    eprintln!("Ironwood transaction build refused: {e}");
                    std::process::exit(2);
                }
            }
        }
        "build-demo-v6" => {
            eprintln!("build-demo-v6 is disabled: this path is not verified against authoritative Ironwood consensus vectors and must not emit protocol-shaped data.");
            std::process::exit(2);
        }
        "sign-bundle" | "sign-bundle-with-keys" | "generate-spend-keys" | "derive-spend-auth" => {
            eprintln!("Standalone spend/binding signing is disabled: signatures must be produced by the official Zcash transaction builder for the exact funded Ironwood bundle.");
            std::process::exit(2);
        }
        "encrypt-orchard-note" => {
            eprintln!("encrypt-orchard-note is disabled: this path is not verified against authoritative Ironwood consensus vectors and must not emit protocol-shaped data.");
            std::process::exit(2);
        }
        "decrypt-orchard-note" => {
            eprintln!("decrypt-orchard-note is disabled: this path is not verified against authoritative Ironwood consensus vectors and must not emit protocol-shaped data.");
            std::process::exit(2);
        }
        "compute-txid" => {
            eprintln!("compute-txid is disabled: this path is not verified against authoritative Ironwood consensus vectors and must not emit protocol-shaped data.");
            std::process::exit(2);
        }
        "derive-pk-d" => {
            eprintln!("derive-pk-d is disabled: this path is not verified against authoritative Ironwood consensus vectors and must not emit protocol-shaped data.");
            std::process::exit(2);
        }
        "derive-orchard-keys" => {
            let seed_hex = args.get(2).cloned().unwrap_or_default();
            let div_hex = args.get(3).cloned().unwrap_or_default();

            let mut seed = [0u8; 32];
            let s_bytes = hex::decode(&seed_hex).unwrap_or_default();
            if s_bytes.len() >= 32 { seed.copy_from_slice(&s_bytes[..32]); }

            let mut d = [0u8; 11];
            let d_bytes = hex::decode(&div_hex).unwrap_or_default();
            if d_bytes.len() >= 11 { d.copy_from_slice(&d_bytes[..11]); }

            match darkbatch_crypto::derive_orchard_keys_and_address(&seed, &d) {
                Ok(val) => println!("{}", val),
                Err(e) => println!("{}", serde_json::json!({ "error": e })),
            }
        }
        "derive-note-commitments" => {
            let addr_hex = args.get(2).cloned().unwrap_or_default();
            let val_zat: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100_000_000);
            let rseed_hex = args.get(4).cloned().unwrap_or_default();
            let rho_hex = args.get(5).cloned().unwrap_or_default();
            let fvk_hex = args.get(6).cloned().unwrap_or_default();

            let mut raw_addr = [0u8; 43];
            let a_bytes = hex::decode(&addr_hex).unwrap_or_default();
            if a_bytes.len() >= 43 { raw_addr.copy_from_slice(&a_bytes[..43]); }

            let mut rseed = [0u8; 32];
            let r_bytes = hex::decode(&rseed_hex).unwrap_or_default();
            if r_bytes.len() >= 32 { rseed.copy_from_slice(&r_bytes[..32]); }

            let mut rho = [0u8; 32];
            let rho_bytes = hex::decode(&rho_hex).unwrap_or_default();
            if rho_bytes.len() >= 32 { rho.copy_from_slice(&rho_bytes[..32]); }

            let mut fvk = [0u8; 96];
            let f_bytes = hex::decode(&fvk_hex).unwrap_or_default();
            if f_bytes.len() >= 96 { fvk.copy_from_slice(&f_bytes[..96]); }

            match darkbatch_crypto::derive_orchard_note_commitments(&raw_addr, val_zat, &rseed, &rho, &fvk) {
                Ok((cmx, nf)) => println!("{}", serde_json::json!({
                    "cmx_hex": hex::encode(cmx),
                    "nullifier_hex": hex::encode(nf)
                })),
                Err(e) => println!("{}", serde_json::json!({ "error": e })),
            }
        }
        "generate-ironwood-proof" => {
            let addr_hex = args.get(2).cloned().unwrap_or_default();
            let val_zat: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100_000_000);
            let memo_hex = args.get(4).cloned().unwrap_or_default();
            let anchor_hex = args.get(5).cloned().unwrap_or_default();
            let sighash_hex = args.get(6).cloned().unwrap_or_default();

            let mut raw_addr = [0u8; 43];
            let a_bytes = hex::decode(&addr_hex).unwrap_or_default();
            if a_bytes.len() >= 43 { raw_addr.copy_from_slice(&a_bytes[..43]); }

            let mut memo = [0u8; 512];
            let m_bytes = hex::decode(&memo_hex).unwrap_or_default();
            let copy_len = m_bytes.len().min(512);
            memo[..copy_len].copy_from_slice(&m_bytes[..copy_len]);

            let mut anchor = [0u8; 32];
            let an_bytes = hex::decode(&anchor_hex).unwrap_or_default();
            if an_bytes.len() >= 32 { anchor.copy_from_slice(&an_bytes[..32]); }

            let mut sighash = [0u8; 32];
            let s_bytes = hex::decode(&sighash_hex).unwrap_or_default();
            if s_bytes.len() >= 32 { sighash.copy_from_slice(&s_bytes[..32]); }

            match darkbatch_crypto::build_and_prove_ironwood_bundle(&raw_addr, val_zat, &memo, &anchor, &sighash) {
                Ok((proof, anchor_used, n_actions)) => println!("{}", serde_json::json!({
                    "status": "STANDALONE_OUTPUT_BUNDLE_PROOF_VERIFIED_NOT_SETTLEMENT_TX",
                    "settlement_transaction": false,
                    "proof_hex": hex::encode(proof),
                    "anchor_hex": hex::encode(anchor_used),
                    "actions_count": n_actions
                })),
                Err(e) => println!("{}", serde_json::json!({ "status": "ERROR", "error": e })),
            }
        }
        _ => {
            eprintln!("Unknown command");
        }
    }
}
