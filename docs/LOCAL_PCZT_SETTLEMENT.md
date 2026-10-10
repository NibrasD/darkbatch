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

## Map an FBA result to a ZEC-only PCZT

If the FBA matching engine has already produced buyer fills and seller fills, a trusted local program can build the input JSON for `build-fba-pczt-local`. The JSON's `outputs` array contains the **ZEC received by each buyer**; each output value must match the corresponding buyer fill in zatoshis. In `change_outputs`, include exactly one entry for each distinct seller input owner:
- `fvk_hex`: the FVK for that seller's real spend input notes.
- `address_raw_hex`: that seller's own change receiver.
- `value_zat`: `null`, so the builder can calculate change after the ZIP 317 fee.
- `seller_fill_zat`: the sum of that owner's matched sell fills, in zatoshis.

Example of a single seller's allocation:

~~~json
"change_outputs": [
  {
    "fvk_hex": "<seller FVK>",
    "address_raw_hex": "<seller-owned raw Ironwood change address>",
    "value_zat": null,
    "seller_fill_zat": 97000000
  }
]
~~~

The builder rejects the plan unless total buyer ZEC outputs equal total seller fill ZEC, each seller fill is covered by that owner's input notes, every input owner has a change allocation, the ownership/address check passes, each witness resolves to the shared anchor, and the final outputs plus network fee balance the input value. The ZIP 317 network fee is allocated deterministically over sellers' residual value; if an owner cannot cover their share or would receive zero change, use different input notes rather than silently shifting their change to another wallet. If the local FBA result has a non-zero solver fee, the preparer converts that fee to zatoshis, adds a separate output to the configured solver receiver, and allocates that amount across the seller owners. Seller change allocations in the generated request therefore include both each seller's matched ZEC fill and that seller's fee share.

Before invoking the command, buyer receiver addresses must be resolved to actual 43-byte Ironwood receiver encodings and the seller input notes and witnesses must be taken from a trusted local wallet/scanner. The local preparer solves the pending orders in the local SQLite epoch when no fill JSON is supplied, maps buyer intent IDs to the raw receivers supplied in the private wallet file, groups seller fills by FVK, and allocates the configured solver fee to its explicit receiver. It requires the wallet file to supply real spendable notes and current witnesses. The Rust builder then verifies that buyer outputs plus solver-fee output equal seller fills plus the solver fee and enforces input/change/network-fee conservation.

Run it with:

~~~bash
# Read the current local SQLite FBA epoch, or supply a local JSON fill result explicitly.
python -m darkbatch.settlement.prepare_fba_pczt --wallet-data private-wallet-notes.json --request-output private-fba-settlement.json --pczt-output unsigned-fba.pczt --report-output fba-pczt-report.json

# To use an already exported local result instead:
python -m darkbatch.settlement.prepare_fba_pczt --fills-json local-fba-fills.json --wallet-data private-wallet-notes.json --request-output private-fba-settlement.json --pczt-output unsigned-fba.pczt --report-output fba-pczt-report.json

# Lower-level builder command if the request JSON has already been prepared:
target/release/darkbatch_crypto build-fba-pczt-local private-fba-settlement.json unsigned-fba.pczt fba-pczt-report.json
~~~

This creates the ZEC side from a supplied FBA fill plan only. It does not automatically invoke the FBA engine or create the fill plan itself, and it does not pay USDC to sellers or collect USDC from buyers. The Rust PCZT builder includes the configured solver fee as a ZEC output when the fill result reports a non-zero fee. This fee is charged on the ZEC leg; it does not settle or replace the buyer/seller USDC quote leg. The output PCZT contains transaction-wide Note metadata for all inputs; until a redaction step is implemented and tested, do **not** distribute these PCZT files to a public coordinator or other participants. The official Combiner merges contributions, but that alone does not make their contents private.

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

Each signing invocation outputs a new PCZT; do not overwrite the unsigned file. Combine signed contributions with the official Combiner, for example: target/release/darkbatch_crypto combine-pczts-local combined.pczt signed-a.pczt signed-b.pczt. Important: the current PCZTs have not had other participants' Note metadata redacted. Keep all files private on one trusted machine; this is not yet a privacy-preserving multi-party protocol.

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
