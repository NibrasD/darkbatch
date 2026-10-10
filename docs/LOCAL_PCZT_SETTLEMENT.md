# DarkBatch local PCZT and Testnet workflow

## What this adds

The Rust crypto CLI now has a separate path backed by the official Zcash transaction builder and PCZT roles pinned to the same upstream librustzcash revision. It validates that each supplied Ironwood note's receiver address belongs to the supplied FullViewingKey, and that its 32-level Merkle witness resolves to the specified Ironwood anchor. It then constructs a V6 PCZT, calculates the standard ZIP 317 fee, checks value conservation, and supports local participant signing, Halo 2 proof generation, and official V6 transaction extraction.

This is **not yet the automated FBA settlement path**. The private build JSON must come from a trusted local wallet/scanner and include real unspent Note data and current witnesses. The tool does not scan Zebra for spendable notes, guarantee a note remains unspent, or resolve the USDC side. Never send this JSON, viewing keys, Note plaintext, PCZT files, or spending-key files to the public coordinator.

## Build

From the repository root, with Rust/Cargo installed:

~~~bash
cargo build --release --manifest-path darkbatch_crypto/Cargo.toml
cargo test --release --manifest-path darkbatch_crypto/Cargo.toml
~~~

## Private build JSON

Hex fields are byte encodings without a 0x prefix.

~~~json
{
  "target_height": 4135000,
  "ironwood_anchor_hex": "<32-byte canonical Ironwood anchor>",
  "inputs": [
    {
      "fvk_hex": "<96-byte FullViewingKey>",
      "raw_address_hex": "<43-byte receiver address for this note>",
      "value_zat": 100000000,
      "rho_hex": "<32-byte rho>",
      "rseed_hex": "<32-byte rseed>",
      "merkle_position": 123,
      "merkle_path_hex": ["<32-byte sibling>", "... exactly 32 siblings total ..."]
    }
  ],
  "outputs": [
    {
      "address_raw_hex": "<43-byte Ironwood recipient address>",
      "value_zat": 97000000,
      "memo_hex": ""
    }
  ],
  "change_fvk_hex": "<same 96-byte FVK as the single input owner>",
  "change_address_raw_hex": "<43-byte change address derived from that FVK>",
  "change_outputs": []
}
~~~

For a multi-owner transaction, do not use the single change fallback. Supply change_outputs with explicit outputs for each participant receiving change:

~~~json
"change_outputs": [
  {
    "fvk_hex": "<seller A's FullViewingKey>",
    "address_raw_hex": "<change address derived from seller A's FVK>",
    "value_zat": 19000000
  },
  {
    "fvk_hex": "<seller B's FullViewingKey>",
    "address_raw_hex": "<change address derived from seller B's FVK>",
    "value_zat": 9000000
  }
]
~~~

The total change outputs must equal input total minus recipient outputs minus the calculated ZIP 317 fee. The builder checks this conservation equation. The numeric values above are examples only. Each change FVK must match an owner of an input note, and every change address must derive from that FVK. Multi-owner settlement rejects the common-wallet fallback.

## Create, sign, prove, extract

~~~bash
# Create the PCZT locally. The report remains not broadcast-ready.
target/release/darkbatch_crypto build-pczt-local private-build.json unsigned.pczt pczt-build-report.json

# Sign one Ironwood spend action locally using that participant's secret key.
# Repeat for each spend action with the matching local key and action index.
target/release/darkbatch_crypto sign-pczt-local unsigned.pczt seller-a-spending-key.hex 0 signed-0.pczt

# After every spend action is signed and PCZT contributions have been safely combined:
target/release/darkbatch_crypto prove-extract-pczt-local signed-all.pczt raw-transaction.hex extraction-report.json
~~~

Each signing invocation outputs a new PCZT; do not overwrite the unsigned file. The CLI can sign locally, but the participant keys must match the inputs and all participants must supply their own signatures. For genuine cooperative signing across independent users, use a protocol-compatible PCZT combiner; do not place everyone’s spending keys on one coordinator.

Successful local proof/extraction does not prove the note remains unspent at broadcast time or that Zebra accepts the transaction.

## Optional live Testnet submission

Run only on a trusted machine connected to an activated Zebra Testnet node. Configure credentials locally, never in the repo or browser:

~~~powershell
$env:ZCASH_TESTNET_RPC_URL = "http://127.0.0.1:18232"
$env:ZCASH_TESTNET_RPC_USER = "<local-rpc-user>"
$env:ZCASH_TESTNET_RPC_PASS = "<local-rpc-password>"
python -m darkbatch.settlement.broadcast_raw raw-transaction.hex --wait-for-confirmation 120
~~~

The submitter checks the RPC endpoint identifies itself as Zebra on Testnet at/after the NU6.3 activation height, validates that the bytes start with the V6 header, submits via sendrawtransaction, and optionally polls for a block confirmation. A sendrawtransaction response is only a broadcast result. MEMPOOL or BROADCAST_PENDING_CONFIRMATION is not a confirmed transaction.

This raw transaction tool does not record an FBA epoch, update simulated balances, or settle the USDC leg. The legacy API path remains blocked from using its experimental assembler for live settlement.
