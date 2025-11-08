# app.py
import os
import sys
import json
import argparse
from typing import Dict, Tuple, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from web3 import Web3
from web3.middleware import geth_poa_middleware

DEFAULT_RPC = os.environ.get("RPC_URL", "https://mainnet.infura.io/v3/YOUR_INFURA_KEY")

# New random built-in sample manifest (addresses are examples; replace as needed)
BUILTIN_MANIFEST: Dict[str, str] = {
    # Example: Ethereum Beacon Deposit Contract (hash only, informational)
    "0x00000000219ab540356cBB839Cbe05303d7705Fa": "keccak",
    # Example: WETH9 mainnet (informational)
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": "keccak"
}

# EIP-1967 implementation slot: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
EIP1967_IMPL_SLOT = Web3.to_int(
    hexstr="0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)

def load_manifest(path: Optional[str]) -> Dict[str, str]:
    if not path:
        return BUILTIN_MANIFEST
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Manifest must be a JSON object mapping address -> expected_hash or 'keccak'")
    return {str(k): str(v) for k, v in data.items()}

def normalize_expected(expected: str) -> str:
    if expected == "keccak":
        return expected
    h = expected.lower()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) != 64:
        raise ValueError("Expected hash must be a 32-byte hex string (64 hex chars)")
    return "0x" + h

def checksum(w3: Web3, address: str) -> str:
    try:
        return w3.to_checksum_address(address)
    except ValueError as e:
        raise ValueError(f"Invalid address: {address}") from e

def get_code(w3: Web3, address: str, block_identifier: Any) -> bytes:
    return w3.eth.get_code(checksum(w3, address), block_identifier=block_identifier)

def get_code_hash(w3: Web3, address: str, block_identifier: Any) -> str:
    code = get_code(w3, address, block_identifier)
    return Web3.keccak(code).hex()

def is_contract(w3: Web3, address: str, block_identifier: Any) -> bool:
    return len(get_code(w3, address, block_identifier)) > 0

def read_eip1967_impl(w3: Web3, proxy_addr: str, block_identifier: Any) -> Optional[str]:
    try:
        raw = w3.eth.get_storage_at(checksum(w3, proxy_addr), EIP1967_IMPL_SLOT, block_identifier=block_identifier)
        if len(raw) != 32:
            return None
        # last 20 bytes are the address
        impl_bytes = raw[-20:]
        impl_addr = Web3.to_checksum_address("0x" + impl_bytes.hex())
        # filter zero address
        if impl_addr.lower() == "0x0000000000000000000000000000000000000000":
            return None
        return impl_addr
    except Exception:
        return None

def verify_target(
    w3: Web3,
    address: str,
    expected: str,
    block: Any,
    follow_proxy: bool
) -> Tuple[str, Optional[str], str, Optional[bool], Optional[str]]:
    """
    Returns (target_address, implementation_address_if_any, computed_hash, is_match, error)
    is_match is None when expected == 'keccak' (informational)
    """
    try:
        target = checksum(w3, address)
        impl = None
        if follow_proxy:
            impl = read_eip1967_impl(w3, target, block)
        effective = impl or target

        if not is_contract(w3, effective, block):
            return effective, impl, "", False if expected != "keccak" else None, "No bytecode at target (EOA or selfdestructed)."

        computed = get_code_hash(w3, effective, block)
        if expected == "keccak":
            return effective, impl, computed, None, None
        expected_norm = normalize_expected(expected)
        return effective, impl, computed, (computed.lower() == expected_norm.lower()), None
    except Exception as e:
        return address, None, "", None, str(e)

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="zk-soundness-snapshot — compute on-chain bytecode hashes, optionally follow EIP-1967 proxies, and compare with expected hashes (useful for Aztec, Zama, and general Web3)."
    )
    p.add_argument("--rpc", default=DEFAULT_RPC, help="EVM-compatible RPC URL (default: env RPC_URL)")
    p.add_argument("--manifest", help="Path to JSON manifest {address: expected_hash|'keccak'}")
    p.add_argument("--address", help="Single contract address to check (overrides manifest if provided)")
    p.add_argument("--expected", help="Expected 0x… hash for --address; if omitted, prints computed hash only")
    p.add_argument("--block", default="finalized", help="Block tag or number (default: finalized)")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    p.add_argument("--concurrency", type=int, default=min(8, os.cpu_count() or 4), help="Parallel requests (default: up to 8)")
    p.add_argument("--follow-proxy", action="store_true", help="Attempt to follow EIP-1967 proxy to implementation")
    p.add_argument("--json", action="store_true", help="Print machine-readable JSON summary to stdout")
    p.add_argument("--quiet", "-q", action="store_true", help="Only print mismatches and errors (human output)")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": args.timeout}))
    # Enable POA compatibility for some testnets/L2s
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    if not w3.is_connected():
        print("❌ RPC connection failed. Check --rpc or RPC_URL.")
        sys.exit(1)

    human_logs = []
    json_rows = []

    if not args.quiet:
        print("🔧 zk-soundness-snapshot")
        print(f"🔗 RPC: {args.rpc}")
        try:
            print(f"🧭 Chain ID: {w3.eth.chain_id}")
        except Exception:
            pass
        print(f"🧱 Block: {args.block}")

    # Build targets
    if args.address:
        targets = {args.address: (args.expected if args.expected else "keccak")}
    else:
        try:
            targets = load_manifest(args.manifest)
        except Exception as e:
            print(f"❌ Failed to load manifest: {e}")
            sys.exit(1)

    if not targets:
        if not args.quiet:
            print("⚠️ No targets to verify.")
        sys.exit(0)

    # Run in parallel
    all_ok = True
    with ThreadPoolExecutor(max_workers=max(1, min(args.concurrency, len(targets)))) as pool:
        futures = {
            pool.submit(
                verify_target, w3, addr, expected, args.block, args.follow_proxy
            ): (addr, expected)
            for addr, expected in targets.items()
        }

        for fut in as_completed(futures):
            addr, expected = futures[fut]
            effective, impl, computed, is_match, error = fut.result()

            row = {
                "input_address": addr,
                "effective_address": effective,
                "implementation_address": impl,
                "expected": expected,
                "computed": computed,
                "block": args.block,
                "follow_proxy": args.follow_proxy,
                "ok": None if is_match is None else bool(is_match),
                "error": error,
            }
            json_rows.append(row)

            if error:
                if not args.quiet:
                    print(f"❌ {addr} -> error: {error}")
                all_ok = False
                continue

            if is_match is None:
                if not args.quiet:
                    print(f"🔍 {addr} -> code hash: {computed}" + (f" (impl: {impl})" if impl else ""))
            else:
                status = "✅ MATCH" if is_match else "❌ MISMATCH"
                if not is_match:
                    all_ok = False
                if not args.quiet or not is_match:
                    print(
                        f"🔍 {addr} -> code hash: {computed} | {status}"
                        + (f" | impl: {impl}" if impl else "")
                    )

    if not args.quiet:
        if all_ok:
            print("🎯 Soundness verified for all targets (no mismatches).")
        else:
            print("🚨 Soundness check failed (one or more mismatches).")

    if args.json:
        print(json.dumps({"results": json_rows}, ensure_ascii=False, indent=2))

    sys.exit(0 if all_ok else 2)

if __name__ == "__main__":
    main()
