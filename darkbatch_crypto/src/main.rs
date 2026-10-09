use darkbatch_crypto::memo::{encrypt_512_memo, decrypt_512_memo, MEMO_SIZE};
use darkbatch_crypto::pallas_ops::{pedersen_commit, random_scalar};
use darkbatch_crypto::zip228::{DesiredOutput, FeeAction, ProposedInput, SwapAction, SwapActionGroup, SwapBundle, SwapOrder};
use darkbatch_crypto::v6_tx::TransactionV6;
use group::GroupEncoding;
use pasta_curves::pallas::Scalar;
use ff::PrimeField;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("DarkBatch Rust Cryptographic Engine v2.0 (Ironwood / Pallas)");
        println!("Usage: darkbatch_crypto [commit | test-memo | build-demo-v6]");
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
        "build-demo-v6" => {
            let r = random_scalar();
            let memo = [0u8; MEMO_SIZE];

            let order1 = SwapOrder {
                order_id: [1u8; 32],
                proposed_input: ProposedInput {
                    asset_id: [0u8; 32],
                    value_zat: 100_000_000,
                    nullifier: [10u8; 32],
                    note_commitment: [11u8; 32],
                },
                desired_output: DesiredOutput {
                    asset_id: [1u8; 32],
                    min_value_zat: 4_250_000_000,
                    recipient_address: "u1ironwood_buyer_alice".into(),
                },
                action_group: SwapActionGroup {
                    anchor: [99u8; 32],
                    swap_action: SwapAction {
                        cv_net: [20u8; 32],
                        nullifier: [10u8; 32],
                        rk: [21u8; 32],
                        cm_star: [22u8; 32],
                        encrypted_memo_hex: hex::encode(memo),
                    },
                    fee_action: FeeAction {
                        cv_fee: [30u8; 32],
                        matcher_fee_zat: 100_000,
                        miner_fee_zat: 10_000,
                    },
                    expiry_height: 4134100,
                    bsk_share_hex: hex::encode(r.to_repr()),
                },
            };

            let order2 = SwapOrder {
                order_id: [2u8; 32],
                proposed_input: ProposedInput {
                    asset_id: [1u8; 32],
                    value_zat: 4_250_000_000,
                    nullifier: [12u8; 32],
                    note_commitment: [13u8; 32],
                },
                desired_output: DesiredOutput {
                    asset_id: [0u8; 32],
                    min_value_zat: 100_000_000,
                    recipient_address: "u1ironwood_seller_bob".into(),
                },
                action_group: SwapActionGroup {
                    anchor: [99u8; 32],
                    swap_action: SwapAction {
                        cv_net: [25u8; 32],
                        nullifier: [12u8; 32],
                        rk: [26u8; 32],
                        cm_star: [27u8; 32],
                        encrypted_memo_hex: hex::encode(memo),
                    },
                    fee_action: FeeAction {
                        cv_fee: [31u8; 32],
                        matcher_fee_zat: 100_000,
                        miner_fee_zat: 10_000,
                    },
                    expiry_height: 4134100,
                    bsk_share_hex: hex::encode(r.to_repr()),
                },
            };

            let bundle = SwapBundle::new(vec![order1, order2], 42.50, 100_000_000).expect("Bundle failed");
            let tx = TransactionV6::from_swap_bundle(bundle, 4134100, [99u8; 32]);
            println!("{}", serde_json::json!({
                "tx_id": hex::encode(tx.tx_id()),
                "header_version": format!("0x{:08x}", tx.header),
                "raw_bytes_len": tx.raw_tx_bytes.len(),
                "raw_tx_hex": tx.to_hex()
            }));
        }
        "sign-bundle" => {
            let sighash_hex = args.get(2).cloned().unwrap_or_default();
            let bsk_hex = args.get(3).cloned().unwrap_or_default();
            let n_actions: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);

            let sighash_bytes = hex::decode(&sighash_hex).unwrap_or_else(|_| vec![0u8; 32]);
            let mut sighash_arr = [0u8; 32];
            if sighash_bytes.len() >= 32 {
                sighash_arr.copy_from_slice(&sighash_bytes[..32]);
            }

            let bsk_bytes = hex::decode(&bsk_hex).unwrap_or_else(|_| vec![0u8; 32]);
            let mut bsk_arr = [0u8; 32];
            if bsk_bytes.len() >= 32 {
                bsk_arr.copy_from_slice(&bsk_bytes[..32]);
            }

            let mut rng = rand::rng();
            let mut spend_sigs = Vec::new();
            let mut rk_list = Vec::new();

            for _ in 0..n_actions {
                let ask = reddsa::SigningKey::<reddsa::orchard::SpendAuth>::new(&mut rng);
                let alpha = darkbatch_crypto::random_scalar();
                let (rsk, rk) = darkbatch_crypto::derive_randomized_spend_auth(&ask, &alpha);
                let sig = rsk.sign(&mut rng, &sighash_arr);
                let sig_bytes: [u8; 64] = sig.into();
                let rk_bytes: [u8; 32] = rk.clone().into();
                assert!(rk.verify(&sighash_arr, &sig).is_ok());

                spend_sigs.push(hex::encode(sig_bytes));
                rk_list.push(hex::encode(rk_bytes));
            }

            let bsk_sk = reddsa::SigningKey::<reddsa::orchard::Binding>::from_bytes(&bsk_arr)
                .unwrap_or_else(|_| reddsa::SigningKey::new(&mut rng));
            let binding_sig = bsk_sk.sign(&mut rng, &sighash_arr);
            let binding_sig_bytes: [u8; 64] = binding_sig.into();

            println!("{}", serde_json::json!({
                "spend_auth_sigs": spend_sigs,
                "rk_list": rk_list,
                "binding_sig": hex::encode(binding_sig_bytes)
            }));
        }
        "generate-spend-keys" => {
            let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
            let mut rng = rand::rng();
            let mut key_pairs = Vec::new();
            for _ in 0..n {
                let ask = reddsa::SigningKey::<reddsa::orchard::SpendAuth>::new(&mut rng);
                let alpha = darkbatch_crypto::random_scalar();
                let (rsk, rk) = darkbatch_crypto::derive_randomized_spend_auth(&ask, &alpha);
                let rsk_bytes: [u8; 32] = rsk.to_bytes();
                let rk_bytes: [u8; 32] = rk.into();
                key_pairs.push(serde_json::json!({
                    "rsk_hex": hex::encode(rsk_bytes),
                    "rk_hex": hex::encode(rk_bytes)
                }));
            }
            println!("{}", serde_json::json!({ "keys": key_pairs }));
        }
        "sign-bundle-with-keys" => {
            let sighash_hex = args.get(2).cloned().unwrap_or_default();
            let bsk_hex = args.get(3).cloned().unwrap_or_default();
            let rsks_csv = args.get(4).cloned().unwrap_or_default();

            let sighash_bytes = hex::decode(&sighash_hex).unwrap_or_else(|_| vec![0u8; 32]);
            let mut sighash_arr = [0u8; 32];
            if sighash_bytes.len() >= 32 { sighash_arr.copy_from_slice(&sighash_bytes[..32]); }

            let bsk_bytes = hex::decode(&bsk_hex).unwrap_or_else(|_| vec![0u8; 32]);
            let mut bsk_arr = [0u8; 32];
            if bsk_bytes.len() >= 32 { bsk_arr.copy_from_slice(&bsk_bytes[..32]); }

            let mut rng = rand::rng();
            let mut spend_sigs = Vec::new();
            let mut rk_list = Vec::new();

            for rsk_hex in rsks_csv.split(',').filter(|s| !s.is_empty()) {
                let rsk_raw = hex::decode(rsk_hex).unwrap_or_default();
                let mut rsk_arr = [0u8; 32];
                if rsk_raw.len() >= 32 { rsk_arr.copy_from_slice(&rsk_raw[..32]); }
                let rsk = reddsa::SigningKey::<reddsa::orchard::SpendAuth>::from_bytes(&rsk_arr)
                    .unwrap_or_else(|_| reddsa::SigningKey::new(&mut rng));
                let rk = reddsa::VerificationKey::from(&rsk);
                let sig = rsk.sign(&mut rng, &sighash_arr);
                let sig_bytes: [u8; 64] = sig.into();
                let rk_bytes: [u8; 32] = rk.clone().into();
                assert!(rk.verify(&sighash_arr, &sig).is_ok());

                spend_sigs.push(hex::encode(sig_bytes));
                rk_list.push(hex::encode(rk_bytes));
            }

            let bsk_sk = reddsa::SigningKey::<reddsa::orchard::Binding>::from_bytes(&bsk_arr)
                .unwrap_or_else(|_| reddsa::SigningKey::new(&mut rng));
            let binding_sig = bsk_sk.sign(&mut rng, &sighash_arr);
            let binding_sig_bytes: [u8; 64] = binding_sig.into();

            println!("{}", serde_json::json!({
                "spend_auth_sigs": spend_sigs,
                "rk_list": rk_list,
                "binding_sig": hex::encode(binding_sig_bytes)
            }));
        }
        "derive-spend-auth" => {
            let sighash_hex = args.get(2).cloned().unwrap_or_default();
            let sighash_bytes = hex::decode(&sighash_hex).unwrap_or_else(|_| vec![0u8; 32]);
            let mut sighash_arr = [0u8; 32];
            if sighash_bytes.len() >= 32 {
                sighash_arr.copy_from_slice(&sighash_bytes[..32]);
            }

            let mut rng = rand::rng();
            let ask = reddsa::SigningKey::<reddsa::orchard::SpendAuth>::new(&mut rng);
            let alpha = darkbatch_crypto::random_scalar();
            let (rsk, rk) = darkbatch_crypto::derive_randomized_spend_auth(&ask, &alpha);
            let sig = rsk.sign(&mut rng, &sighash_arr);
            let sig_bytes: [u8; 64] = sig.into();
            let rk_bytes: [u8; 32] = rk.clone().into();
            assert!(rk.verify(&sighash_arr, &sig).is_ok());

            println!("{}", serde_json::json!({
                "rk_hex": hex::encode(rk_bytes),
                "sig_hex": hex::encode(sig_bytes),
                "alpha_hex": hex::encode(alpha.to_repr())
            }));
        }
        "encrypt-orchard-note" => {
            let diversifier_hex = args.get(2).cloned().unwrap_or_default();
            let pk_d_hex = args.get(3).cloned().unwrap_or_default();
            let val_zat: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(100_000_000);
            let memo_text = args.get(5).cloned().unwrap_or_default();
            let ovk_hex = args.get(6).cloned().unwrap_or_default();
            let cv_hex = args.get(7).cloned().unwrap_or_default();
            let cmx_hex = args.get(8).cloned().unwrap_or_default();

            let mut d = [0u8; 11];
            let d_bytes = hex::decode(&diversifier_hex).unwrap_or_default();
            if d_bytes.len() >= 11 { d.copy_from_slice(&d_bytes[..11]); }

            let mut pk_d = [0u8; 32];
            let pk_d_bytes = hex::decode(&pk_d_hex).unwrap_or_default();
            if pk_d_bytes.len() >= 32 { pk_d.copy_from_slice(&pk_d_bytes[..32]); }

            let mut memo = [0u8; 512];
            let memo_bytes = memo_text.as_bytes();
            let copy_len = memo_bytes.len().min(512);
            memo[..copy_len].copy_from_slice(&memo_bytes[..copy_len]);

            let mut ovk = [0u8; 32];
            let ovk_bytes = hex::decode(&ovk_hex).unwrap_or_default();
            if ovk_bytes.len() >= 32 { ovk.copy_from_slice(&ovk_bytes[..32]); }

            let mut cv = [0u8; 32];
            let cv_bytes = hex::decode(&cv_hex).unwrap_or_default();
            if cv_bytes.len() >= 32 { cv.copy_from_slice(&cv_bytes[..32]); }

            let mut cmx = [0u8; 32];
            let cmx_bytes = hex::decode(&cmx_hex).unwrap_or_default();
            if cmx_bytes.len() >= 32 { cmx.copy_from_slice(&cmx_bytes[..32]); }

            let rseed = [0x42u8; 32];
            let esk = darkbatch_crypto::random_scalar();

            let (enc_ct, out_ct, epk) = darkbatch_crypto::orchard_encrypt_note(
                &d,
                &pk_d,
                val_zat,
                &rseed,
                &memo,
                &ovk,
                &cv,
                &cmx,
                &esk,
            );

            println!("{}", serde_json::json!({
                "enc_ciphertext_hex": hex::encode(&enc_ct),
                "out_ciphertext_hex": hex::encode(&out_ct),
                "epk_hex": hex::encode(&epk),
                "enc_len": enc_ct.len(),
                "out_len": out_ct.len()
            }));
        }
        "decrypt-orchard-note" => {
            let enc_hex = args.get(2).cloned().unwrap_or_default();
            let ivk_hex = args.get(3).cloned().unwrap_or_default();
            let epk_hex = args.get(4).cloned().unwrap_or_default();

            let enc_bytes = hex::decode(&enc_hex).unwrap_or_default();
            let ivk_bytes = hex::decode(&ivk_hex).unwrap_or_default();
            let mut ivk_arr = [0u8; 32];
            if ivk_bytes.len() >= 32 { ivk_arr.copy_from_slice(&ivk_bytes[..32]); }
            let ivk = darkbatch_crypto::scalar_from_bytes(&ivk_arr);

            let epk_bytes = hex::decode(&epk_hex).unwrap_or_default();
            let mut epk_arr = [0u8; 32];
            if epk_bytes.len() >= 32 { epk_arr.copy_from_slice(&epk_bytes[..32]); }

            match darkbatch_crypto::orchard_decrypt_note(&enc_bytes, &ivk, &epk_arr) {
                Ok((val, memo)) => {
                    let text = String::from_utf8_lossy(&memo).trim_end_matches('\0').to_string();
                    println!("{}", serde_json::json!({
                        "status": "SUCCESS",
                        "value_zat": val,
                        "memo_hex": hex::encode(&memo),
                        "memo_text": text
                    }));
                }
                Err(e) => {
                    println!("{}", serde_json::json!({
                        "status": "ERROR",
                        "error": e
                    }));
                }
            }
        }
        "compute-txid" => {
            let header: u32 = 0x80000006;
            let version_group_id: u32 = 0xD884B698;
            let consensus_branch_id: u32 = 0x37A5165B;
            let expiry_height: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4134100);
            let actions_hex_str = args.get(3).cloned().unwrap_or_default();

            let mut actions = Vec::new();
            if !actions_hex_str.is_empty() {
                for act_hex in actions_hex_str.split(',') {
                    if let Ok(b) = hex::decode(act_hex) {
                        actions.push(b);
                    }
                }
            }

            let txid = darkbatch_crypto::compute_zip244_v6_txid(
                header,
                version_group_id,
                consensus_branch_id,
                0,
                expiry_height,
                &actions,
                0x03,
                0,
            );

            let sighash = darkbatch_crypto::compute_v6_sighash(
                header,
                version_group_id,
                consensus_branch_id,
                0,
                expiry_height,
                &actions,
                0x03,
                0,
            );

            println!("{}", serde_json::json!({
                "txid_hex": hex::encode(txid),
                "sighash_hex": hex::encode(sighash)
            }));
        }
        "derive-pk-d" => {
            let ivk_hex = args.get(2).cloned().unwrap_or_default();
            let div_hex = args.get(3).cloned().unwrap_or_default();

            let ivk_bytes = hex::decode(&ivk_hex).unwrap_or_default();
            let mut ivk_arr = [0u8; 32];
            if ivk_bytes.len() >= 32 { ivk_arr.copy_from_slice(&ivk_bytes[..32]); }
            let ivk = darkbatch_crypto::scalar_from_bytes(&ivk_arr);

            let mut d = [0u8; 11];
            let d_bytes = hex::decode(&div_hex).unwrap_or_default();
            if d_bytes.len() >= 11 { d.copy_from_slice(&d_bytes[..11]); }

            let pk_d = darkbatch_crypto::derive_pk_d(&ivk, &d);
            println!("{}", serde_json::json!({
                "pk_d_hex": hex::encode(pk_d)
            }));
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
                    "status": "PROVEN_AND_VERIFIED",
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
