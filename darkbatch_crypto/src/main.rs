use darkbatch_crypto::memo::{decrypt_512_memo, encrypt_512_memo, MEMO_SIZE};
use darkbatch_crypto::pallas_ops::pedersen_commit;
use ff::PrimeField;
use group::GroupEncoding;
use pasta_curves::pallas::Scalar;
use serde::Deserialize;
use std::io::Read;
use std::env;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitRequest {
    value_zat: u64,
    randomness_hex: String,
}

fn read_stdin_json<T: for<'de> Deserialize<'de>>() -> Result<T, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("Could not read request from stdin: {e}"))?;
    serde_json::from_str(&input).map_err(|e| format!("Invalid request JSON: {e}"))
}

fn run_commit_stdin() -> Result<(), String> {
    let request: CommitRequest = read_stdin_json()?;
    let scalar_bytes: [u8; 32] = hex::decode(&request.randomness_hex)
        .map_err(|_| "randomness_hex must be valid hexadecimal.".to_owned())?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("randomness_hex must be 32 bytes, got {}.", bytes.len()))?;
    let scalar = Option::<Scalar>::from(Scalar::from_repr(scalar_bytes))
        .ok_or_else(|| "randomness_hex is not a canonical Pallas scalar.".to_owned())?;
    let commitment = pedersen_commit(request.value_zat, &scalar);
    println!("{}", serde_json::json!({
        "value_zat": request.value_zat,
        "scalar_r": hex::encode(scalar.to_repr()),
        "commitment_point": hex::encode(commitment.to_bytes())
    }));
    Ok(())
}

fn print_usage() {
    println!("DarkBatch Ironwood local wallet engine");
    println!("Safe commands (secret material is read from stdin):");
    println!("  commit-stdin");
    println!("  derive-ironwood-address-stdin");
    println!("  ironwood-tree-root-stdin");
    println!("  scan-ironwood-block-stdin");
    println!("  build-ironwood-transaction-stdin");
    println!("  inspect-ironwood-transaction-stdin");
    println!("  create-ironwood-pczt-stdin");
    println!("  inspect-ironwood-pczt-stdin");
    println!("  sign-ironwood-pczt-stdin");
    println!("  finalize-ironwood-pczt-stdin");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("");
    let result = match command {
        "commit-stdin" => run_commit_stdin(),
        "derive-ironwood-address-stdin" => read_stdin_json_string()
            .and_then(|input| darkbatch_crypto::derive_ironwood_address_json(&input))
            .map(|value| println!("{}", value)),
        "ironwood-tree-root-stdin" => read_stdin_json_string()
            .and_then(|input| darkbatch_crypto::ironwood_tree_root_json(&input))
            .map(|value| println!("{}", value)),
        "scan-ironwood-block-stdin" => read_stdin_json_string()
            .and_then(|input| darkbatch_crypto::scan_ironwood_block_json(&input))
            .map(|value| println!("{}", serde_json::to_string(&value).expect("scan result serializes"))),
        "build-ironwood-transaction-stdin" => read_stdin_json_string()
            .and_then(|input| darkbatch_crypto::build_ironwood_transaction_from_json(&input))
            .map(|tx| println!("{}", serde_json::json!({
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
                "note": "Built by the official zcash_primitives v6 builder from wallet inputs. Not broadcast or confirmed."
            }))),
        "inspect-ironwood-transaction-stdin" => read_stdin_json_string()
            .and_then(|input| darkbatch_crypto::inspect_ironwood_transaction_json(&input))
            .map(|value| println!("{}", value)),
        "create-ironwood-pczt-stdin" => read_stdin_json_string()
            .and_then(|input| darkbatch_crypto::create_ironwood_pczt_json(&input))
            .map(|value| println!("{}", value)),
        "inspect-ironwood-pczt-stdin" => read_stdin_json_string()
            .and_then(|input| darkbatch_crypto::inspect_ironwood_pczt_json(&input))
            .map(|value| println!("{}", value)),
        "sign-ironwood-pczt-stdin" => read_stdin_json_string()
            .and_then(|input| darkbatch_crypto::sign_ironwood_pczt_json(&input))
            .map(|value| println!("{}", value)),
        "finalize-ironwood-pczt-stdin" => read_stdin_json_string()
            .and_then(|input| darkbatch_crypto::finalize_ironwood_pczt_json(&input))
            .map(|value| println!("{}", value)),
        _ => {
            print_usage();
            return;
        }
    };
    if let Err(error) = result {
        eprintln!("DarkBatch operation failed closed: {error}");
        std::process::exit(2);
    }
}

fn read_stdin_json_string() -> Result<String, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("Could not read request from stdin: {e}"))?;
    if input.trim().is_empty() {
        return Err("Request body is empty.".to_owned());
    }
    Ok(input)
}
