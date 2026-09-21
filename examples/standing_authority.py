#!/usr/bin/env python3
"""Build a Recurr Tier 2 standing-authority descriptor, its content-addressed authority_ref, an
EVM customer-signing payload, an informed-consent disclosure card, and show revocation. Pure
format/method: no executor, no keys, no settlement. Run:
    PYTHONPATH=python python examples/standing_authority.py
"""
from __future__ import annotations

import json

from algovoi_recurr import (
    standing_authority,
    authority_ref,
    build_evm_approve,
    daily_cap_atomic,
    disclosure_card,
    revocation_method,
)

# A chain-agnostic standing authority: up to 10 USDC per month, 120 USDC total, on Base.
descriptor = standing_authority(
    merchant_ref="acme-subscriptions:sub_123",
    chain="base",
    customer_wallet_address="0xYOUR_CUSTOMER_WALLET",
    cap_amount_minor=120_000_000,       # 120.00 USDC total (6-decimal)
    per_cycle_amount_minor=10_000_000,  # 10.00 USDC per cycle
    cap_period_seconds=2_592_000,       # 30 days
    asset="USDC",
    decimals=6,
    expires_at="2027-05-08T00:00:00Z",
)
print("== standing-authority descriptor ==")
print(json.dumps(descriptor, indent=2))
print("authority_ref:", authority_ref(descriptor))

print("\n== what the customer signs on Base (single ERC-20 approve) ==")
# spender / merchant payout are OPERATOR addresses, supplied by the caller (never baked in).
payload = build_evm_approve(
    chain="base", chain_id=8453,
    asset_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # Circle USDC on Base (public)
    spender="0xYOUR_FACILITATOR_ADDRESS",
    merchant_payout_address="0xYOUR_MERCHANT_PAYOUT",
    customer_address="0xYOUR_CUSTOMER_WALLET",
    cap_amount_atomic=120_000_000,
    per_cycle_amount_atomic=10_000_000,
    decimals=6,
)
print(json.dumps(payload, indent=2))

print("\n== informed-consent disclosure card (rendered before any wallet prompt) ==")
card = disclosure_card(descriptor, merchant_name="ACME", cycle_label="monthly")
for line in card["lines"]:
    print("  -", line)

print("\n== revocation ==")
print("  Base:    ", revocation_method("base"))
print("  Algorand:", revocation_method("algorand"))
print("  Stellar: ", revocation_method("stellar"))

print("\n== derived vault daily cap (Algorand/VOI) ==")
print("  daily_cap_atomic:", daily_cap_atomic(10_000_000, 120_000_000, 2_592_000))
