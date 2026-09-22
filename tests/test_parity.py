"""Byte-parity: the standing-authority descriptor's authority_ref and an ARC EVM signing payload's
payload_ref must equal pinned golden values, and the Node reference implementation must reproduce
the same bytes (see tests/parity.mjs). The ARC case (18-decimal, 10**12 scale) exercises the
BigInt path that keeps the scaled approve_amount exact. Run standalone or under pytest."""
from algovoi_recurr import (
    standing_authority,
    authority_ref,
    verify_authority_ref,
    build_evm_approve,
    build_stellar_soroban,
    signing_payload_ref,
    daily_cap_atomic,
    revocation_method,
    keystone_chain,
    sha256_jcs,
    RecurrError,
    PAYLOAD_VERSION,
)

GOLDEN_AUTHORITY_REF = "sha256:69ab6fe324fd020790ed291328125add4d737d9fe7be51dca9b4a57325b57ec8"
GOLDEN_ARC_PAYLOAD_REF = "sha256:dea6cbdcad08cf83b8f21fd819bbbc404248da44c218078f42f65e15d5bedb34"
GOLDEN_KEYSTONE_CHAIN_REF = "sha256:903af3449c0f8dc4aae4dc3447294bd5afc65668fb7d0b854808ebd01a2a88a5"

_POLICY_BOUND = {"policy_id": "aml.recurring", "version": 1, "max_amount": 10_000_000,
                 "deny_jurisdictions": ["XX"]}
_EXECUTION = {"amount_minor": 10_000_000, "cycle_index": 3, "executed_at_ms": 1789000000000}


def _fixture_descriptor():
    return standing_authority(
        merchant_ref="acme-sub-1", chain="base", customer_wallet_address="0xCUST",
        cap_amount_minor=120_000_000, per_cycle_amount_minor=10_000_000,
        cap_period_seconds=2592000, asset="USDC", decimals=6, expires_at="2027-05-08T00:00:00Z",
    )


def _fixture_arc_payload():
    return build_evm_approve(
        chain="arc", chain_id=5042, asset_contract="0xUSDC_ARC", spender="0xFAC",
        merchant_payout_address="0xMERCH", customer_address="0xCUST",
        cap_amount_atomic=120_000_000, per_cycle_amount_atomic=10_000_000, decimals=6, chain_scale=10 ** 12,
    )


def test_authority_ref_matches_golden():
    d = _fixture_descriptor()
    assert d["revocation_method"].startswith("approve(spender, 0)")
    assert authority_ref(d) == GOLDEN_AUTHORITY_REF
    assert verify_authority_ref(d, GOLDEN_AUTHORITY_REF)


def test_arc_payload_ref_and_bigint_exactness():
    p = _fixture_arc_payload()
    # 120 USDC (120000000 atomic) at 10**12 scale must stay exact (BigInt in Node).
    assert p["approve_amount"] == "120000000000000000000"
    assert p["version"] == PAYLOAD_VERSION["evm"]
    assert signing_payload_ref(p) == GOLDEN_ARC_PAYLOAD_REF


def test_keystone_chain_composition_matches_golden():
    d = _fixture_descriptor()
    chain = keystone_chain(d, policy=_POLICY_BOUND, executions=[_EXECUTION])
    # the standing_authority link preimage is the recurr descriptor VERBATIM, so its keystone link
    # reference is exactly authority_ref(descriptor) -- the recurr authority_ref IS the keystone ref.
    sa = chain["chain"][0]
    assert sa["name"] == "standing_authority"
    assert sa["preimage"] == d
    assert "sha256:" + sha256_jcs(sa["preimage"]) == authority_ref(d) == GOLDEN_AUTHORITY_REF
    # the whole composition canonicalizes to a pinned golden reference (Node must reproduce it).
    assert "sha256:" + sha256_jcs(chain) == GOLDEN_KEYSTONE_CHAIN_REF
    assert chain["schema"] == "algovoi-keystone-chain/v2"
    assert chain["assertions"][0]["kind"] == "recurring_cap"


def test_keystone_chain_rejects_non_descriptor():
    try:
        keystone_chain({"not": "a descriptor"}, policy=_POLICY_BOUND, executions=[_EXECUTION])
    except RecurrError:
        pass
    else:
        raise AssertionError("expected RecurrError composing from a non-descriptor")


def test_keystone_chain_rejects_partial_descriptor():
    # a fabricated mapping carrying only the cap-relevant fields is NOT a recurr descriptor;
    # the composition requires the whole standing-authority shape.
    partial = {"per_cycle_amount_minor": 500, "cap_amount_minor": 1000,
               "expires_at": "2027-06-01T00:00:00Z", "canon_version": "jcs-rfc8785-v1"}
    try:
        keystone_chain(partial, policy=_POLICY_BOUND, executions=[_EXECUTION])
    except RecurrError:
        pass
    else:
        raise AssertionError("expected RecurrError from a partial (fabricated) descriptor")


def test_keystone_chain_rejects_unsafe_integer():
    # an amount above 2**53 rounds in Node while Python keeps it exact; both emitters must refuse it
    # so they stay byte-parity (mirrors the Keystone verifier's safe-integer bound).
    d = _fixture_descriptor()
    try:
        keystone_chain(d, policy=_POLICY_BOUND,
                       executions=[{"amount_minor": 2 ** 53 + 1, "executed_at_ms": 1789000000000}])
    except RecurrError:
        pass
    else:
        raise AssertionError("expected RecurrError from an amount above the JS-safe integer range")


def test_per_cycle_must_not_exceed_cap():
    try:
        standing_authority(merchant_ref="m", chain="base", customer_wallet_address="0xC",
                           cap_amount_minor=100, per_cycle_amount_minor=200, cap_period_seconds=86400)
    except RecurrError:
        pass
    else:
        raise AssertionError("expected RecurrError when per_cycle > cap")


def test_cap_period_floor():
    try:
        standing_authority(merchant_ref="m", chain="base", customer_wallet_address="0xC",
                           cap_amount_minor=100, per_cycle_amount_minor=10, cap_period_seconds=3600)
    except RecurrError:
        pass
    else:
        raise AssertionError("expected RecurrError below the one-day cap-period floor")


def test_stellar_pinned_to_v2():
    p = build_stellar_soroban(asset_contract_id="CUSDC", spender_address="GFAC",
                              merchant_payout_address="GMERCH", customer_address="GCUST",
                              network_passphrase="Public Global Stellar Network ; September 2015",
                              cap_amount_atomic=1200000000, per_cycle_amount_atomic=100000000, decimals=7)
    assert p["version"] == "stellar_soroban_auth_v2"
    assert p["function_name"] == "approve"
    assert p["actions"][0]["kind"] == "soroban_invoke"


def test_revocation_methods():
    assert revocation_method("base").startswith("approve(spender, 0)")
    assert "SPL Token revoke" in revocation_method("solana")
    assert revocation_method("algorand").startswith("owner_withdraw")


def test_daily_cap_derivation():
    assert daily_cap_atomic(10_000_000, 120_000_000, 2592000) == 10_000_000


if __name__ == "__main__":
    test_authority_ref_matches_golden()
    test_arc_payload_ref_and_bigint_exactness()
    test_keystone_chain_composition_matches_golden()
    test_keystone_chain_rejects_non_descriptor()
    test_keystone_chain_rejects_partial_descriptor()
    test_keystone_chain_rejects_unsafe_integer()
    test_per_cycle_must_not_exceed_cap()
    test_cap_period_floor()
    test_stellar_pinned_to_v2()
    test_revocation_methods()
    test_daily_cap_derivation()
    print("python OK", GOLDEN_AUTHORITY_REF, GOLDEN_ARC_PAYLOAD_REF, GOLDEN_KEYSTONE_CHAIN_REF)
