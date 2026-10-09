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
            eprintln!("build-demo-v6 is disabled: this path is not verified against authoritative Ironwood consensus vectors and must not emit protocol-shaped data.");
            std::process::exit(2);
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
