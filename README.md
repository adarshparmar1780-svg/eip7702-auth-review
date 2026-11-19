# EIP-7702 authorization review

A small offline command-line tool for reviewing the authorization list from an EIP-7702 set-code transaction before signing.

It checks the supplied chain ID and tuple field bounds, checks `y_parity` and the secp256k1 `r`/low-`s` ranges used for authorization recovery, and calls out two details that are easy to miss while reviewing a raw list: a chain ID of `0` is valid across chains, and a zero delegate address clears the authority's existing delegation. It also reports byte-for-byte duplicate tuples as a review note.

## Run

Requires Python 3.10 or newer. No third-party packages are needed.

```powershell
py .\eip7702_auth_review.py .\examples\authorization-list.json
```

The input may use the compact form with `transaction_chain_id` and `authorization_list` tuples. Each tuple is `[chain_id, address, nonce, y_parity, r, s]`; integer fields may be JSON integers or decimal/`0x` strings.

It also accepts the object form returned by `eth_getTransactionByHash`: top-level `chainId` and `authorizationList`, with each authorization containing `chainId`, `address`, `nonce`, `yParity`, `r`, and `s`. RPC quantities are hexadecimal strings. Other transaction fields from the RPC response are ignored.

The included example uses synthetic values for demonstration; it is not a signed authorization.

The command prints a JSON review report. It exits with `0` when no authorization-list, chain-ID, or signature-field issue was detected, `1` for an exact duplicate tuple, a chain ID that does not match the transaction, or a signature field outside the recovery ranges, and `2` for malformed input or fields outside their encoded bounds. Notes about chain ID `0` do not change the exit code.

## Scope and limits

This is a static input checker, not a wallet or transaction simulator. Range checks can identify impossible signature fields but do not recover the authority from `y_parity`, `r`, and `s` or verify a signature. It also does not check the target contract's bytecode, model execution, or establish that a delegation is safe. Review the target code and the wallet's transaction preview before signing. A valid signature can authorize code with broad access to the account.

The implementation is based on [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) and [EIP-2](https://eips.ethereum.org/EIPS/eip-2). This project was prepared with AI assistance; the maintainer should review and understand changes before relying on it.
