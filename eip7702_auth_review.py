#!/usr/bin/env python3
"""Review visible EIP-7702 authorization tuple fields without signing anything."""

import argparse
import json
import re
import sys
from pathlib import Path

MAX_UINT256 = 1 << 256
MAX_UINT64 = 1 << 64
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_N = SECP256K1_N // 2
ADDRESS_BYTES = 20
ZERO_ADDRESS = "0x" + "0" * 40


class InputError(ValueError):
    pass


def parse_uint(value, label, limit):
    if isinstance(value, bool):
        raise InputError(f"{label} must be an integer")
    try:
        if isinstance(value, int):
            number = value
        elif isinstance(value, str):
            number = int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        else:
            raise ValueError
    except ValueError:
        raise InputError(f"{label} must be a decimal or 0x-prefixed integer") from None
    if number < 0 or number >= limit:
        raise InputError(f"{label} must be between 0 and {limit - 1}")
    return number


def parse_address(value, index):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise InputError(f"authorization {index}: address must start with 0x")
    raw = value[2:]
    if len(raw) != ADDRESS_BYTES * 2:
        raise InputError(f"authorization {index}: address must contain 20 bytes")
    if re.fullmatch(r"[0-9a-fA-F]{40}", raw) is None:
        raise InputError(f"authorization {index}: address contains non-hex characters") from None
    return "0x" + raw.lower()


def review(document):
    if not isinstance(document, dict):
        raise InputError("input must be a JSON object")
    tx_chain_value = document.get("transaction_chain_id", document.get("chainId"))
    if tx_chain_value is None:
        raise InputError("missing transaction_chain_id")
    tx_chain = parse_uint(tx_chain_value, "transaction_chain_id", MAX_UINT256)
    auths = document.get("authorization_list", document.get("authorizationList"))
    if not isinstance(auths, list) or not auths:
        raise InputError("authorization_list/authorizationList must be a non-empty array")

    notes = []
    authorization_list_issues = []
    chain_id_issues = []
    signature_issues = []
    reviewed = []
    seen = set()
    for index, entry in enumerate(auths, start=1):
        if isinstance(entry, list) and len(entry) == 6:
            values = entry
        elif isinstance(entry, dict):
            names = ("chainId", "address", "nonce", "yParity", "r", "s")
            if any(name not in entry for name in names):
                raise InputError(f"authorization {index}: RPC object must include chainId, address, nonce, yParity, r, and s")
            values = [entry[name] for name in names]
        else:
            raise InputError(f"authorization {index}: expected a six-field tuple or an RPC authorization object")
        chain = parse_uint(values[0], f"authorization {index} chain_id", MAX_UINT256)
        address = parse_address(values[1], index)
        nonce = parse_uint(values[2], f"authorization {index} nonce", MAX_UINT64 - 1)
        parity = parse_uint(values[3], f"authorization {index} y_parity", 1 << 8)
        r = parse_uint(values[4], f"authorization {index} r", MAX_UINT256)
        s = parse_uint(values[5], f"authorization {index} s", MAX_UINT256)
        item = {"chain_id": chain, "address": address, "nonce": nonce, "y_parity": parity, "r": r, "s": s}

        if parity not in (0, 1):
            signature_issues.append(f"Authorization {index}: y_parity must be 0 or 1 for signature recovery.")
        if not 1 <= r < SECP256K1_N:
            signature_issues.append(f"Authorization {index}: r is outside the valid secp256k1 scalar range.")
        if not 1 <= s <= SECP256K1_HALF_N:
            signature_issues.append(f"Authorization {index}: s is outside the valid low-s secp256k1 range.")
        if chain == 0:
            notes.append(f"Authorization {index}: chain_id 0 is valid across chains; review whether that scope is intended.")
        elif chain != tx_chain:
            chain_id_issues.append(f"Authorization {index}: chain_id {chain} differs from transaction chain {tx_chain}; this tuple will not apply on that chain.")
        if address == ZERO_ADDRESS:
            notes.append(f"Authorization {index}: zero address clears the authority's existing delegation.")
        fingerprint = tuple(item.values())
        if fingerprint in seen:
            authorization_list_issues.append(f"Authorization {index}: exact duplicate tuple; the second copy cannot apply after the first valid copy advances its authority nonce.")
        seen.add(fingerprint)
        reviewed.append(item)

    return {"transaction_chain_id": tx_chain, "authorization_count": len(reviewed), "authorizations": reviewed, "review_notes": notes,
            "authorization_list_issues": authorization_list_issues, "chain_id_issues": chain_id_issues,
            "signature_field_issues": signature_issues,
            "limitations": ["Signatures and recovered authorities are not verified.", "Delegate bytecode and transaction execution are not inspected."]}


def main():
    parser = argparse.ArgumentParser(description="Review EIP-7702 authorization tuple fields offline.")
    parser.add_argument("input", type=Path, help="JSON file with authorization_list tuples or an RPC authorizationList")
    args = parser.parse_args()
    try:
        document = json.loads(args.input.read_text(encoding="utf-8"))
        report = review(document)
        print(json.dumps(report, indent=2))
        return 1 if report["authorization_list_issues"] or report["chain_id_issues"] or report["signature_field_issues"] else 0
    except (OSError, json.JSONDecodeError, InputError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
