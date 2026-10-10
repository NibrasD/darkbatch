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
- `seller_fill_zat`: the sum of that owner's matched sell fills plus any solver-fee share allocated to them, in zatoshis. When the solver fee is zero, this equals the matched sell-fill total.

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

Before invoking the command, buyer receiver addresses must be resolved to actual 43-byte Ironwood receiver encodings and the seller input notes and witnesses must be taken from a trusted local wallet/scanner. The local preparer solves the pending orders in the local SQLite epoch when no fill JSON is supplied, maps buyer intent IDs to the raw receivers supplied in the private wallet file, groups seller fills by FVK, and allocates the configured solver fee to its explicit receiver. If the local solver fee is non-zero, this workflow charges it as an additional ZEC output from seller inputs; it is not the USDC quote-asset fee. It requires the wallet file to supply real spendable notes and current witnesses. The Rust builder then verifies that buyer outputs plus solver-fee output equal seller fills plus the solver fee and enforces input/change/network-fee conservation.

Run it with:

~~~bash
# Read the current local SQLite FBA epoch, or supply a local JSON fill result explicitly.
python -m darkbatch.settlement.prepare_fba_pczt --wallet-data private-wallet-notes.json --request-output private-fba-settlement.json --pczt-output unsigned-fba.pczt --report-output fba-pczt-report.json

# To use an already exported local result instead:
python -m darkbatch.settlement.prepare_fba_pczt --fills-json local-fba-fills.json --wallet-data private-wallet-notes.json --request-output private-fba-settlement.json --pczt-output unsigned-fba.pczt --report-output fba-pczt-report.json

# Lower-level builder command if the request JSON has already been prepared:
target/release/darkbatch_crypto build-fba-pczt-local private-fba-settlement.json unsigned-fba.pczt fba-pczt-report.json
~~~

This creates the ZEC side from a supplied FBA fill plan only. It does not automatically invoke the FBA engine or create the fill plan itself, and it does not pay USDC to sellers or collect USDC from buyers. The Rust PCZT builder includes the configured solver fee as a ZEC output when the fill result reports a non-zero fee. This fee is charged on the ZEC leg; it does not settle or replace the buyer/seller USDC quote leg.

The PCZT contribution flow now has a **local redaction step**. Keep the complete original unsigned PCZT and its private build JSON on the trusted local wallet/settlement machine. Never distribute that full PCZT: it contains transaction-wide note-opening metadata and Merkle witnesses.

## Create, redact, sign, combine, prove, extract

~~~bash
# 1. Build the full PCZT on the trusted local machine.
target/release/darkbatch_crypto build-fba-pczt-local private-fba-settlement.json private-original-unsigned.pczt fba-pczt-report.json

# 2. For each participant, prepare a separate redacted copy from the private original.
# Use the Ironwood action index reported by the builder. Distribute only this file to that owner.
target/release/darkbatch_crypto redact-pczt-local private-original-unsigned.pczt 0 participant-a-redacted.pczt

# 3. The participant signs only their redacted copy with their local spending key.
# The CLI strips note openings from the signed contribution before writing it.
target/release/darkbatch_crypto sign-pczt-local participant-a-redacted.pczt participant-a-spending-key.hex 0 participant-a-signed-redacted.pczt

# 4. Return signed-redacted contributions. Combine them with the private original as the FIRST input.
# One signer is sufficient for a single-spender batch; add one signed-redacted file per real spender.
target/release/darkbatch_crypto combine-pczts-local combined.pczt private-original-unsigned.pczt participant-a-signed-redacted.pczt participant-b-signed-redacted.pczt

# 5. Generate the official Ironwood proof and extract the fully authorized V6 transaction.
target/release/darkbatch_crypto prove-extract-pczt-local combined.pczt raw-transaction.hex extraction-report.json
~~~

The redaction step removes the anchor and all Merkle witnesses from participant copies. It retains the selected owner's note data only until that owner signs; the signed contribution then strips the note opening/FVK, witnesses, output wallet metadata, and value-commitment randomness. Public transaction effects, encrypted output ciphertexts, and spend signatures remain so the official Combiner can merge each contribution into the private original. The original unsigned PCZT restores the anchor, witnesses, and proving metadata only on the trusted local machine.

Do not send the private original, build JSON, wallet data, spending keys, or raw witnesses to a public coordinator. Keep participant contributions local/private too; they expose public transaction effects and must be associated with the exact same PCZT/action indexes. The local redaction stage is not a replacement for an external security audit of the protocol.

Each output file is new; do not overwrite the original unsigned PCZT. The combiner requires the private original as its first input and at least one signed-redacted participant contribution. Successful local proof/extraction does not prove the note remains unspent at broadcast time or that Zebra accepts the transaction.



## Trusted-local FBA agent (automated PCZT handoff)

The repository includes `darkbatch.settlement.local_pczt_agent`. It takes a **private, fresh, synchronized Testnet wallet inventory** from a real wallet/scanner provider, fetches the current FBA plan through the token-protected API, selects spendable Ironwood notes for sellers, verifies the funded USDC escrow before proving when broadcasting is requested, and calls the official Rust builder.

The inventory schema is `darkbatch.ironwood-wallet-inventory.v1`; it includes the current Testnet tip/anchor, each wallet's real spendable Ironwood notes and 32-level witnesses, raw receiver addresses, FVKs, and paths to local spending-key files. When the FBA plan has a non-zero ZEC solver fee, the inventory must also contain a top-level `solver_fee_receiver` object with an `address_raw_hex` field and optional `memo_hex`. The agent includes this as an explicit ZEC output and allocates the fee across seller inputs; it is separate from the USDC quote amount. The agent rejects demo/mock inventory. It never uploads that inventory or keys to the API. This mode is a **trusted-local key agent**: the same local process can access every configured seller key file. For separate participant-controlled signing, use the redacted-PCZT/CLI workflow above instead of providing all owners' key files to one agent.

First build the Rust tool and prepare a fresh, empty private work directory. Set the settlement token in the local process environment; do not put it in the repository, wallet inventory, command history, or browser.

~~~powershell
cargo build --release --manifest-path darkbatch_crypto/Cargo.toml
$env:DARKBATCH_SETTLEMENT_TOKEN = "<locally provisioned settlement token>"

# Build, sign from the local key files, prove and extract. No network transaction is sent.
python -m darkbatch.settlement.local_pczt_agent --api-base http://127.0.0.1:8000 --epoch-id 12 --wallet-inventory .\private\wallet-inventory.json --workdir .\private\epoch-12 --quote-batch-id 0x<64-hex-escrow-batch-id>

# Only after the previous proof/report is reviewed, the same private workdir can submit it.
# The agent rechecks the current FBA commitment, fully funded USDC escrow, target branch,
# transaction expiry and raw-byte length before asking the API to broadcast.
python -m darkbatch.settlement.local_pczt_agent --api-base http://127.0.0.1:8000 --epoch-id 12 --workdir .\private\epoch-12 --quote-batch-id 0x<64-hex-escrow-batch-id> --submit-existing --wait-for-confirmation 120
~~~

The second command does not rerun proof generation. It submits the previously extracted V6 transaction only if the same epoch/quote commitment is still active, the on-chain USDC batch is fully funded, and the transaction has not expired. It reports ZEC confirmation separately; it does not sign or release USDC. The settlement token must authorize both API calls, and a public/remote coordinator should only be used over HTTPS.

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
