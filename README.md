# Algovoi-recurr

The open **format and method** for AlgoVoi **Recurr Tier 2 standing authorities**: the way a
recurring, capped, revocable on-chain payment authorization is described, signed, disclosed, and
revoked. Apache-2.0, Python + Node, byte-identical output.

Recurr Tier 2 is a PSD2-aligned **standing authority**: the customer signs **one** on-chain
authorization that caps how much a named party may pull, and on what schedule; the operator then
pulls autonomously within that cap until the customer revokes it. This package is the *format and
method* for that authorization. It is deliberately **not the engine**:

- **Is:** a chain-agnostic, content-addressed standing-authority **descriptor** (`authority_ref`);
  the per-chain **customer-signing payload** shapes, built only on standard public primitives
  (ERC-20 `approve`, SPL `Approve`, HTS allowance, Soroban `approve`, and the Algorand spending-cap
  vault **parameters**); the per-chain **revocation** method; and an informed-consent **disclosure**
  model.
- **Is not:** an executor, a pull scheduler, a signing key, a facilitator, a ledger, a sanctions
  engine, or the Algorand vault **contract source**. Those stay in the commercial rail. You supply
  the spender / facilitator and merchant-payout addresses; how a pull is submitted and settled
  on-chain is out of scope here.

Every content-addressed reference is `"sha256:" + SHA-256(JCS(RFC 8785)(fields))`, the same byte
discipline as [`algovoi-compliance-gate-a2a`](https://github.com/chopmob-cloud/algovoi-compliance-gate-a2a),
and the Python and Node builders emit byte-identical JSON (same `authority_ref` / `payload_ref`).

## The standing-authority descriptor

```
asset, canon_version, cap_amount_minor, cap_period_seconds, chain,
customer_wallet_address, decimals, expires_at, merchant_ref,
per_cycle_amount_minor, revocation_method
```

`cap_amount_minor` is the total cap over the authority's life; `per_cycle_amount_minor` the
per-cycle (per-pull) cap; `cap_period_seconds` the cycle length (at least one day). `expires_at`
is caller-supplied (never derived from wall-clock) so the descriptor stays recomputable. No address
beyond the customer's wallet is recorded.

```python
from algovoi_recurr import standing_authority, authority_ref

d = standing_authority(
    merchant_ref="acme-subscriptions:sub_123", chain="base",
    customer_wallet_address="0xCUSTOMER",
    cap_amount_minor=120_000_000, per_cycle_amount_minor=10_000_000,  # 120 / 10 USDC (6-decimal)
    cap_period_seconds=2_592_000, asset="USDC", decimals=6,
    expires_at="2027-05-08T00:00:00Z",
)
print(authority_ref(d))  # "sha256:..." recomputable, byte-identical in Node
```

## What the customer signs (per chain)

One builder per chain family, each returning the version-tagged payload the rail emits, built on a
standard public primitive:

| Chain | Version | Primitive | Revoke by |
|---|---|---|---|
| EVM (Base / Tempo / ARC) | `evm_erc20_approve_v1` | ERC-20 `approve(spender, cap)` | `approve(spender, 0)` |
| Solana | `solana_spl_approve_v1` | SPL Token `Approve(delegate, cap)` | SPL Token `revoke` |
| Hedera | `hedera_hts_allowance_v1` | HTS `AccountAllowanceApproveTransaction` | allowance approve `0` |
| Stellar | `stellar_soroban_auth_v2` | Soroban asset-contract `approve` | approve `0` / expired ledger |
| Algorand / VOI | `algorand_spending_cap_vault_v1` | spending-cap vault **parameters** (6-action group) | `owner_withdraw` + `remove_agent` |

`build_evm_approve` takes a `chain_scale` so ARC's 18-decimal USDC (scale `10**12`) stays exact;
the scaled `approve_amount` is computed with big integers so Python and Node agree byte-for-byte.

```python
from algovoi_recurr import build_evm_approve, signing_payload_ref
payload = build_evm_approve(
    chain="base", chain_id=8453, asset_contract="0x8335...2913",
    spender="0xYOUR_FACILITATOR", merchant_payout_address="0xYOUR_MERCHANT",
    customer_address="0xCUSTOMER", cap_amount_atomic=120_000_000,
    per_cycle_amount_atomic=10_000_000, decimals=6,
)
print(signing_payload_ref(payload))
```

The Node build is byte-identical (`@algovoi/recurr`, `standingAuthority` / `authorityRef` /
`buildEvmApprove` / `signingPayloadRef`).

## Informed-consent disclosure

`disclosure_card(descriptor, merchant_name=..., cycle_label=...)` produces the pre-sign summary a
customer sees before any wallet prompt (cap, cycle, per-cycle cap, expiry, chain, revocation), with
the honest UK line that a crypto standing authority is outside the Payment Services Regulations'
chargeback regime. All disclosure copy is dash-checked (no em/en dashes).

## Known drift (pinned honestly)

The Stellar lane is pinned to the **server-emitted** `stellar_soroban_auth_v2` (function `approve`).
The older `@algovoi/sdk` emits `stellar_soroban_auth_v1` (`soroban_authorize_entry` / `transfer`).
Verify against the live rail before relying on either. This package documents what
`pay.algovoi.co.uk` returns today.

## Run it

```bash
PYTHONPATH=python python examples/standing_authority.py
```

Byte-parity is pinned in [`tests/test_parity.py`](tests/test_parity.py) and
[`tests/parity.mjs`](tests/parity.mjs): a fixed descriptor and an ARC EVM payload (18-decimal,
`10**12` scale) must produce the same `authority_ref` and `payload_ref` in both languages.

## Install

Published as source (Apache-2.0), not to PyPI/npm:

```bash
pip install "git+https://github.com/chopmob-cloud/algovoi-recurr.git#subdirectory=python"
```

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
