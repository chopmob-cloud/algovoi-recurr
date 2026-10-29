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

## Verify inside a Keystone chain

A recurr authority does not stand alone: each cycle pull is an *execution* that must stay inside the
one authority the customer signed, which must in turn stay inside the operator's policy. That whole
relationship composes into a single, offline-verifiable **Keystone chain**, and recurr emits it.

```python
from algovoi_recurr import standing_authority, authority_ref, keystone_chain, sha256_jcs

authority = standing_authority(
    merchant_ref="acme-sub-1", chain="base", customer_wallet_address="0xCUST",
    cap_amount_minor=120_000_000, per_cycle_amount_minor=10_000_000,
    cap_period_seconds=2592000, expires_at="2027-05-08T00:00:00Z",
)
policy = {"policy_id": "aml.recurring", "version": 1, "max_amount": 10_000_000}

chain = keystone_chain(
    authority,
    policy=policy,
    executions=[{"amount_minor": 10_000_000, "cycle_index": 3, "executed_at_ms": 1789000000000}],
)

# The standing_authority link is the descriptor VERBATIM, so its Keystone reference is exactly the
# recurr authority_ref, byte for byte. The recurr authority_ref IS the Keystone link ref.
assert "sha256:" + sha256_jcs(chain["chain"][0]["preimage"]) == authority_ref(authority)
```

`keystoneChain(descriptor, { policy, executions })` in Node emits the byte-identical chain (the whole
composition recomputes to the same `"sha256:" + SHA-256(JCS(chain))` reference in both languages).
This is **format and method** only, in keeping with the rest of recurr: it emits the composition, it
is not the engine.

## Check the chain with the Keystone verifier

The cap semantics (per-cycle pull <= policy max, each pull <= the per-cycle cap, each pull inside the
authority window, cumulative pulls <= the period cap) are enforced by the Keystone verifier's
`recurring_cap` assertion, not by recurr. Install the umbrella and verify the chain offline:

```bash
# from source, until 0.6.0 is on the index
pip install "git+https://github.com/chopmob-cloud/algovoi-keystone.git#subdirectory=packages/algovoi-keystone"
keystone verify chain.json
```

```
keystone chain: standing_authority  ->  policy_bound  ->  execution_0  ->  execution_1
------------------------------------------------------------
  OK  standing_authority
      sha256:69ab6fe324fd020790ed291328125add4d737d9fe7be51dca9b4a57325b57ec8
  OK  policy_bound
      sha256:30d49f629fc22b246f09684c75ff2b0b7f41626e7b2fb14a99a01a3f82e42572
  OK  execution_0
      sha256:d18fcfe4...  binds standing_authority, policy_bound
assertions:
  OK  recurring_cap
------------------------------------------------------------
KEYSTONE VALID: 4/4 links compose, recompute byte-for-byte, no issuer contact + recurring-cap hold.
```

Exit codes are deliberate: `0` composes, `1` a well-formed chain that does not prove what it claims
(per-cycle cap exceeded, past expiry, over the period cap), `2` bad input or invocation. An over-cap
chain fails closed:

```
KEYSTONE BROKEN: recurring_cap failed -- execution.amount_minor 11000000 exceeds per_cycle cap 10000000.
```

The same check is importable. The verdict is a pure function of the bytes — every reference recomputes
with any RFC 8785 implementation — so a third party can reproduce it without trusting either package:

```python
from algovoi_keystone import verify_chain

result = verify_chain(chain)
assert result.ok, result.failed_assertion
```

Canonicalisation comes from the independent `rfc8785` library, so verifying needs no AlgoVoi software
in the trust base; when `algovoi-substrate` is installed as well, the two canonicalisers are
cross-checked byte-for-byte and a divergence fails closed.

### Pin the authority the customer signed

A chain recomputes from its own bytes, so on its own it proves internal consistency only: raise
`cap_amount_minor` in the descriptor and the chain still recomputes — including past the cap the
customer approved on-chain. Pin the `standing_authority` link to the `authority_ref` that was signed
and a widened authority is caught:

```bash
keystone verify chain.json --expect standing_authority=sha256:69ab6fe3...   # the signed authority_ref
```

```
KEYSTONE BROKEN: ref_pinned failed -- standing_authority recomputed sha256:0643cec3... != pinned sha256:69ab6fe3...
```

```python
from algovoi_keystone import verify_chain

assert verify_chain(chain, expect={"standing_authority": authority_ref(authority)}).ok
```

### Revocation

`keystone_chain()` emits the authority, the operator's policy and each cycle's execution under one
`recurring_cap` assertion. Revocation is a separate link, not something recurr emits today: a chain
that carries a `revocation` link (binding the revoked authority by `@reference` and carrying
`revoked_at_ms`) is checked by the verifier's `not_revoked` assertion, so any execution at or after
the revocation fails closed. See `revocation-golden.json` and `recurr-broken-revoked.json` in the
Keystone vector set for the shape, and add that link from the revocation envelope you already use
(for example `algovoi-revocation-ref`) before relying on the `not_revoked` guarantee.

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
[`tests/parity.mjs`](tests/parity.mjs): a fixed descriptor, an ARC EVM payload (18-decimal, `10**12`
scale), and the Keystone-chain composition must produce the same `authority_ref`, `payload_ref`, and
chain reference in both languages.

## Install

Published as source (Apache-2.0), not to PyPI/npm:

```bash
pip install "git+https://github.com/chopmob-cloud/algovoi-recurr.git#subdirectory=python"
```

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
