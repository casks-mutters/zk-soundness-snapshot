# zk-soundness-snapshot

# Overview
A tiny CLI that takes a quick “soundness snapshot” of smart contracts by computing their on-chain bytecode hash. It can optionally follow EIP-1967 proxies to the implementation and compare the result with an expected hash. Built on web3.py, useful for monitoring or auditing L1 contracts in ecosystems like Aztec, Zama, and general Web3 deployments.

# Key features
1) Finality-aware lookups using a configurable block tag (default: finalized)
2) Optional EIP-1967 proxy following to the implementation address
3) Single address or manifest mode
4) Parallel requests for faster checks
5) Machine-readable JSON output for CI, plus quiet mode for clean logs
6) POA middleware enabled so common L2s and testnets work out of the box

# Installation
1) Install Python 3.9 or newer
2) Install dependencies:
   pip install web3
3) Provide an RPC endpoint:
   set environment variable RPC_URL or pass --rpc

# Usage
Single address, informational hash:
   python app.py --address 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

Single address with expected hash:
   python app.py --address 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --expected 0xabc123...

Follow EIP-1967 proxy and check implementation:
   python app.py --address 0xYourProxy --expected 0xdeadbeef... --follow-proxy

Use a manifest for many contracts:
   python app.py --manifest manifest.json

Emit JSON for CI systems:
   python app.py --manifest manifest.json --json --quiet

Select a specific block tag or number:
   python app.py --manifest manifest.json --block finalized
   python app.py --manifest manifest.json --block safe
   python app.py --manifest manifest.json --block 21000000
   
   Arguments
--rpc       EVM RPC URL (default from RPC_URL environment)
--manifest  Path to JSON manifest mapping address -> expected_hash or 'keccak'
--address   Single contract address to check (overrides manifest)
--expected  Expected 0x-hash for --address; if omitted, prints only the computed hash
--block     Block tag or number (e.g., latest, safe, finalized, or a number). Default: finalized
--timeout   HTTP timeout in seconds (default: 30)
--concurrency  Max parallel requests (default: up to 8)
--follow-proxy Follow EIP-1967 proxy to implementation before hashing
--json      Print a JSON summary to stdout
--quiet, -q Suppress normal output; only mismatches and errors are printed

# Manifest format
A JSON object mapping each contract address to either:
- A 0x-prefixed keccak hash to compare against
- The word keccak to only compute and print the hash without comparing

Example:
{
  "0x00000000219ab540356cBB839Cbe05303d7705Fa": "keccak",
  "0xYourContractHere": "0xEXPECTED_HASH_HERE"
}

# Expected output
Informational run:
🔍 0x... -> code hash: 0x...

With comparison:
🔍 0x... -> code hash: 0x... | ✅ MATCH
or
🔍 0x... -> code hash: 0x... | ❌ MISMATCH

# Notes
- For proxy architectures, enabling --follow-proxy helps by hashing the implementation address stored at the EIP-1967 slot. If a different proxy pattern is used, point the tool directly at the implementation.
- Default block tag is finalized to reduce reorg risk. You can switch to safe or latest depending on your operational needs.
- Works with mainnet, common testnets, L2s, and private devnets; just point --rpc accordingly.
- For best reproducibility in CI, pin a specific block number.
- This tool validates only deployed bytecode. It does not verify ABI compatibility, storage layout, or other invariants.
