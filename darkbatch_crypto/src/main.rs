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
            for _ in 0..n_actions {
                let sk = reddsa::SigningKey::<reddsa::orchard::SpendAuth>::new(&mut rng);
                let sig = sk.sign(&mut rng, &sighash_arr);
                let sig_bytes: [u8; 64] = sig.into();
                spend_sigs.push(hex::encode(sig_bytes));
            }

            let bsk_sk = reddsa::SigningKey::<reddsa::orchard::Binding>::from_bytes(&bsk_arr)
                .unwrap_or_else(|_| reddsa::SigningKey::new(&mut rng));
            let binding_sig = bsk_sk.sign(&mut rng, &sighash_arr);
            let binding_sig_bytes: [u8; 64] = binding_sig.into();

            println!("{}", serde_json::json!({
                "spend_auth_sigs": spend_sigs,
                "binding_sig": hex::encode(binding_sig_bytes)
            }));
        }
        _ => {
            eprintln!("Unknown command");
        }
    }
}
