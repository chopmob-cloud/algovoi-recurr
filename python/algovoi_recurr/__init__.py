"""algovoi-recurr -- the open format and method for AlgoVoi Recurr Tier 2 standing authorities.

Recurr Tier 2 is a PSD2-aligned standing authority: a customer signs ONE on-chain authorization
that caps how much a named party may pull, on a schedule, and the operator then pulls
autonomously within that cap until it is revoked. This package is the openly-licensed
(Apache-2.0) *format and method* for that authorization: a chain-agnostic, content-addressed
**standing-authority descriptor**, the per-chain **customer-signing payload** shapes (all built on
standard public primitives), the per-chain **revocation** method, and an informed-consent
**disclosure** model.

It is deliberately NOT the engine. There is no executor, no pull scheduler, no signing key, no
facilitator, no ledger, and no vault contract source here. The operator supplies the spender /
facilitator and merchant-payout addresses; how a pull is submitted and settled on-chain, and how
the Algorand spending-cap vault program is implemented, stay in the commercial rail.

Every content-addressed reference is "sha256:" + SHA-256(JCS(RFC 8785)(fields)), the same byte
discipline as algovoi-compliance-gate-a2a, and the Python and Node (@algovoi/recurr) builders
emit byte-identical JSON (same authority_ref / payload_ref).

The per-chain payload versions and fields mirror what pay.algovoi.co.uk actually returns and what
the shipped @algovoi/sdk builds. One known drift is pinned here: the Stellar lane uses the
server-emitted ``stellar_soroban_auth_v2`` (function ``approve``); the older SDK ``_v1`` shape
(``soroban_authorize_entry`` / ``transfer``) is documented as drift. Verify against the live rail.
"""
from __future__ import annotations

import hashlib
from typing import Any, Mapping

import rfc8785

__version__ = "0.1.0"

SHA256_PREFIX = "sha256:"
CANON_VERSION = "jcs-rfc8785-v1"

# The minimum standing-authority cycle (the rail rejects anything under a day).
MIN_CAP_PERIOD_SECONDS = 86400

# Lifecycle states (server: AuthorityStatus).
AUTHORITY_STATES = ("pending", "active", "depleted", "revoked", "paused", "errored")

# Per-chain customer-signing payload versions (as the live rail emits them).
PAYLOAD_VERSION = {
    "algorand": "algorand_spending_cap_vault_v1",
    "voi": "algorand_spending_cap_vault_v1",
    "evm": "evm_erc20_approve_v1",
    "solana": "solana_spl_approve_v1",
    "hedera": "hedera_hts_allowance_v1",
    "stellar": "stellar_soroban_auth_v2",
}

# Em dash, en dash, figure dash, horizontal bar, minus sign, non-breaking hyphen.
_DASH_CHARS = "—–‒―−‑"

_EVM_CHAINS = frozenset({"base", "tempo", "arc"})
_VAULT_CHAINS = frozenset({"algorand", "voi"})


class RecurrError(ValueError):
    """Raised when an input violates the standing-authority format discipline."""


def sha256_jcs(obj) -> str:
    """SHA-256 over the JCS (RFC 8785) canonical bytes of ``obj`` (hex, no prefix)."""
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def assert_ascii_dashes_only(text: str, *, field: str = "text") -> str:
    """Reject em/en/figure dashes in customer-facing disclosure copy; return ``text`` when clean."""
    if not isinstance(text, str):
        raise RecurrError(f"{field} must be a string")
    bad = [c for c in _DASH_CHARS if c in text]
    if bad:
        raise RecurrError(
            f"{field} contains a non-ASCII dash ({', '.join(hex(ord(c)) for c in bad)}); "
            "use a plain ASCII hyphen, comma, or parentheses in disclosure copy"
        )
    return text


# ── chain family + revocation ─────────────────────────────────────────────────
def chain_family(chain: str) -> str:
    """Map a chain id to its authorization family: 'vault' (Algorand/VOI), 'evm', 'solana',
    'hedera', or 'stellar'."""
    c = chain.lower()
    if c in _VAULT_CHAINS:
        return "vault"
    if c in _EVM_CHAINS:
        return "evm"
    if c in {"solana", "hedera", "stellar"}:
        return c
    raise RecurrError(f"unknown chain {chain!r}")


REVOCATION_METHOD = {
    "vault": "owner_withdraw + remove_agent on the spending-cap vault (unspent funds return to the owner)",
    "evm": "approve(spender, 0) from any EVM wallet",
    "solana": "SPL Token revoke on the delegated token account",
    "hedera": "AccountAllowanceApproveTransaction with amount 0",
    "stellar": "invoke the asset contract approve with amount 0 / an already-expired ledger",
}


def revocation_method(chain: str) -> str:
    """The customer-side revocation method for a chain, in plain terms."""
    return REVOCATION_METHOD[chain_family(chain)]


# ── the chain-agnostic standing-authority descriptor ──────────────────────────
def standing_authority(
    *,
    merchant_ref: str,
    chain: str,
    customer_wallet_address: str,
    cap_amount_minor: int,
    per_cycle_amount_minor: int,
    cap_period_seconds: int,
    asset: str = "USDC",
    decimals: int = 6,
    expires_at: str | None = None,
    canon_version: str = CANON_VERSION,
) -> dict:
    """Build the validated, chain-agnostic standing-authority descriptor.

    ``cap_amount_minor`` is the total cap over the authority's life; ``per_cycle_amount_minor`` the
    per-cycle (per-pull) cap; ``cap_period_seconds`` the cycle length (>= one day). Amounts are in
    the asset's minor units at ``decimals``. ``expires_at`` is an optional ISO-8601 string; it is
    supplied (not derived from wall-clock) so the descriptor stays recomputable. ``revocation_method``
    is filled from the chain family. No addresses beyond the customer's wallet are recorded here."""
    for name, val in (("merchant_ref", merchant_ref), ("chain", chain),
                      ("customer_wallet_address", customer_wallet_address), ("asset", asset)):
        if not isinstance(val, str) or not val:
            raise RecurrError(f"{name} must be a non-empty string")
    for name, val in (("cap_amount_minor", cap_amount_minor),
                      ("per_cycle_amount_minor", per_cycle_amount_minor)):
        if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
            raise RecurrError(f"{name} must be a positive integer (minor units)")
    if per_cycle_amount_minor > cap_amount_minor:
        raise RecurrError("per_cycle_amount_minor must not exceed cap_amount_minor")
    if isinstance(cap_period_seconds, bool) or not isinstance(cap_period_seconds, int) \
            or cap_period_seconds < MIN_CAP_PERIOD_SECONDS:
        raise RecurrError(f"cap_period_seconds must be an integer >= {MIN_CAP_PERIOD_SECONDS} (one day)")
    if isinstance(decimals, bool) or not isinstance(decimals, int) or decimals < 0:
        raise RecurrError("decimals must be a non-negative integer")
    if expires_at is not None and (not isinstance(expires_at, str) or not expires_at):
        raise RecurrError("expires_at must be a non-empty ISO-8601 string or None")
    return {
        "asset": asset,
        "canon_version": canon_version,
        "cap_amount_minor": cap_amount_minor,
        "cap_period_seconds": cap_period_seconds,
        "chain": chain,
        "customer_wallet_address": customer_wallet_address,
        "decimals": decimals,
        "expires_at": expires_at,
        "merchant_ref": merchant_ref,
        "per_cycle_amount_minor": per_cycle_amount_minor,
        "revocation_method": revocation_method(chain),
    }


def authority_ref(descriptor: Mapping[str, Any]) -> str:
    """authority_ref = "sha256:" + SHA-256(JCS(descriptor)). Recomputable from the descriptor alone,
    byte-identical in Node."""
    return SHA256_PREFIX + sha256_jcs(dict(descriptor))


def verify_authority_ref(descriptor: Mapping[str, Any], claimed: str) -> bool:
    try:
        return authority_ref(descriptor) == claimed
    except Exception:
        return False


# ── per-chain customer-signing payloads (standard public primitives only) ─────
def _scaled_str(amount_atomic: int, chain_scale: int) -> str:
    if isinstance(amount_atomic, bool) or not isinstance(amount_atomic, int) or amount_atomic <= 0:
        raise RecurrError("amount_atomic must be a positive integer")
    if isinstance(chain_scale, bool) or not isinstance(chain_scale, int) or chain_scale < 1:
        raise RecurrError("chain_scale must be a positive integer")
    return str(amount_atomic * chain_scale)


def build_evm_approve(
    *, chain: str, chain_id: int, asset_contract: str, spender: str, merchant_payout_address: str,
    customer_address: str, cap_amount_atomic: int, per_cycle_amount_atomic: int,
    decimals: int = 6, chain_scale: int = 1,
) -> dict:
    """EVM (Base/Tempo/ARC) customer-signing payload: a single ERC-20 ``approve(spender, cap)``.
    ``chain_scale`` rescales to the chain's on-chain decimals (ARC 18-dp USDC uses 10**12)."""
    approve_amount = _scaled_str(cap_amount_atomic, chain_scale)
    return {
        "version": PAYLOAD_VERSION["evm"],
        "chain": chain,
        "chain_id": chain_id,
        "asset_contract": asset_contract,
        "decimals": decimals,
        "spender": spender,
        "merchant_payout_address": merchant_payout_address,
        "customer_address": customer_address,
        "amount_atomic": cap_amount_atomic,
        "approve_amount": approve_amount,
        "per_cycle_amount_atomic": per_cycle_amount_atomic,
        "actions": [{
            "kind": "erc20_approve",
            "args": {"asset_contract": asset_contract, "spender": spender, "amount": approve_amount},
        }],
    }


def build_solana_approve(
    *, asset_mint: str, spl_token_program: str, ata_program: str, delegate: str,
    merchant_payout_address: str, customer_address: str, cap_amount_atomic: int,
    per_cycle_amount_atomic: int, decimals: int = 6,
) -> dict:
    """Solana customer-signing payload: a single SPL Token ``Approve(delegate, cap)`` (u64)."""
    approve_amount = _scaled_str(cap_amount_atomic, 1)
    return {
        "version": PAYLOAD_VERSION["solana"],
        "chain": "solana",
        "asset_mint": asset_mint,
        "spl_token_program": spl_token_program,
        "ata_program": ata_program,
        "decimals": decimals,
        "delegate": delegate,
        "merchant_payout_address": merchant_payout_address,
        "customer_address": customer_address,
        "amount_atomic": cap_amount_atomic,
        "approve_amount": approve_amount,
        "per_cycle_amount_atomic": per_cycle_amount_atomic,
        "actions": [{
            "kind": "spl_token_approve",
            "args": {"asset_mint": asset_mint, "delegate": delegate, "amount": approve_amount},
        }],
    }


def build_hedera_allowance(
    *, token_id: str, owner_account_id: str, spender_account_id: str,
    merchant_payout_account_id: str, cap_amount_atomic: int, per_cycle_amount_atomic: int,
    decimals: int = 6,
) -> dict:
    """Hedera customer-signing payload: an HTS ``AccountAllowanceApproveTransaction`` (int64)."""
    approve_amount = _scaled_str(cap_amount_atomic, 1)
    return {
        "version": PAYLOAD_VERSION["hedera"],
        "chain": "hedera",
        "token_id": token_id,
        "decimals": decimals,
        "owner_account_id": owner_account_id,
        "spender_account_id": spender_account_id,
        "merchant_payout_account_id": merchant_payout_account_id,
        "amount_atomic": cap_amount_atomic,
        "approve_amount": approve_amount,
        "per_cycle_amount_atomic": per_cycle_amount_atomic,
        "actions": [{
            "kind": "hts_allowance_approve",
            "args": {"token_id": token_id, "owner_account_id": owner_account_id,
                     "spender_account_id": spender_account_id, "amount": approve_amount},
        }],
    }


# Soroban's max ledger sentinel used when the authority itself carries the expiry.
STELLAR_MAX_EXPIRATION_LEDGER = 4294967295


def build_stellar_soroban(
    *, asset_contract_id: str, spender_address: str, merchant_payout_address: str,
    customer_address: str, network_passphrase: str, cap_amount_atomic: int,
    per_cycle_amount_atomic: int, decimals: int = 7,
    expiration_ledger: int = STELLAR_MAX_EXPIRATION_LEDGER,
) -> dict:
    """Stellar customer-signing payload: a Soroban asset-contract ``approve`` auth entry (i128).

    Pinned to the server-emitted ``stellar_soroban_auth_v2`` shape (function ``approve``). NOTE: the
    older @algovoi/sdk emits ``stellar_soroban_auth_v1`` (``soroban_authorize_entry`` / ``transfer``);
    that is a known drift. Verify against the live rail before relying on either. Stellar USDC is
    7-decimal, hence the default ``decimals=7``."""
    approve_amount = _scaled_str(cap_amount_atomic, 1)
    return {
        "version": PAYLOAD_VERSION["stellar"],
        "chain": "stellar",
        "asset_contract_id": asset_contract_id,
        "decimals": decimals,
        "spender_address": spender_address,
        "merchant_payout_address": merchant_payout_address,
        "customer_address": customer_address,
        "network_passphrase": network_passphrase,
        "function_name": "approve",
        "amount_atomic": cap_amount_atomic,
        "approve_amount": approve_amount,
        "per_cycle_amount_atomic": per_cycle_amount_atomic,
        "actions": [{
            "kind": "soroban_invoke",
            "args": {"asset_contract_id": asset_contract_id, "function_name": "approve",
                     "from": customer_address, "spender": spender_address,
                     "amount": approve_amount, "expiration_ledger": expiration_ledger},
        }],
    }


def build_algorand_vault(
    *, asa_id: int, facilitator_address: str, merchant_payout_address: str, customer_address: str,
    cap_amount_atomic: int, per_cycle_amount_atomic: int, daily_cap_atomic: int,
    vault_funding_micro_algo: int, vault_funding_asa_units: int,
    global_max_per_txn: int, global_daily_cap: int, global_max_asa_per_txn: int,
    allowlist_enabled: bool = True,
) -> dict:
    """Algorand / VOI customer-signing payload: the spending-cap-vault PARAMETERS and the 6-action
    atomic group the customer signs. This describes how to interact with the vault; it does NOT
    include the vault contract's source or bytecode (that enforcement program stays proprietary)."""
    return {
        "version": PAYLOAD_VERSION["algorand"],
        "vault_template": {"create_args": {
            "global_max_per_txn": global_max_per_txn,
            "global_daily_cap": global_daily_cap,
            "global_max_asa_per_txn": global_max_asa_per_txn,
            "allowlist_enabled": allowlist_enabled,
        }},
        "vault_funding_micro_algo": vault_funding_micro_algo,
        "vault_funding_asa_units": vault_funding_asa_units,
        "asa_id": asa_id,
        "facilitator_address": facilitator_address,
        "merchant_payout_address": merchant_payout_address,
        "customer_address": customer_address,
        "per_cycle_amount_atomic": per_cycle_amount_atomic,
        "daily_cap_atomic": daily_cap_atomic,
        "cap_amount_atomic": cap_amount_atomic,
        "actions": [
            {"name": "deploy_vault", "kind": "create"},
            {"name": "fund_vault_algo", "kind": "payment", "args": {"amount": vault_funding_micro_algo}},
            {"name": "vault_opt_in_asa", "kind": "opt_in_asa", "args": {"asset": asa_id}},
            {"name": "register_agent", "kind": "add_agent",
             "args": {"agent": facilitator_address, "max_per_txn": per_cycle_amount_atomic, "daily_cap": daily_cap_atomic}},
            {"name": "register_recipient", "kind": "add_recipient",
             "args": {"recipient": merchant_payout_address, "max_per_txn": per_cycle_amount_atomic, "daily_cap": daily_cap_atomic}},
            {"name": "fund_vault_usdc", "kind": "asset_transfer", "args": {"asset": asa_id, "amount": vault_funding_asa_units}},
        ],
    }


def daily_cap_atomic(per_cycle_amount_atomic: int, cap_amount_atomic: int, cap_period_seconds: int) -> int:
    """The vault's derived daily cap: max(per-cycle, total cap / cycles-in-period). Mirrors the rail."""
    if cap_period_seconds < MIN_CAP_PERIOD_SECONDS:
        raise RecurrError(f"cap_period_seconds must be >= {MIN_CAP_PERIOD_SECONDS}")
    cycles = max(1, cap_period_seconds // MIN_CAP_PERIOD_SECONDS)
    return max(per_cycle_amount_atomic, cap_amount_atomic // cycles)


def signing_payload_ref(payload: Mapping[str, Any]) -> str:
    """payload_ref = "sha256:" + SHA-256(JCS(payload)); byte-identical in Node."""
    return SHA256_PREFIX + sha256_jcs(dict(payload))


# ── informed-consent disclosure model ─────────────────────────────────────────
def disclosure_card(
    descriptor: Mapping[str, Any], *, merchant_name: str, cycle_label: str,
    not_psr_covered: bool = True,
) -> dict:
    """The pre-sign, human-readable Authority Summary Card model (dash-clean). Renders the cap,
    cycle, per-cycle cap, expiry, chain, and revocation before any wallet prompt. ``not_psr_covered``
    adds the honest UK disclosure that crypto standing authorities are outside the Payment Services
    Regulations' chargeback regime."""
    dec = int(descriptor["decimals"])
    asset = str(descriptor["asset"])
    total = int(descriptor["cap_amount_minor"]) / 10 ** dec
    per_cycle = int(descriptor["per_cycle_amount_minor"]) / 10 ** dec
    lines = [
        assert_ascii_dashes_only(f"You are authorising {merchant_name} to pull payments from your wallet.",
                                 field="summary"),
        f"Per cycle: up to {per_cycle:.2f} {asset} ({cycle_label}).",
        f"Total cap: {total:.2f} {asset}.",
        f"Chain: {descriptor['chain']}.",
        f"You sign a one-time on-chain authorization; {merchant_name} then pulls automatically within the cap.",
        f"Revoke any time: {descriptor['revocation_method']}.",
    ]
    if descriptor.get("expires_at"):
        lines.insert(3, f"Authority expires: {descriptor['expires_at']}.")
    if not_psr_covered:
        lines.append(assert_ascii_dashes_only(
            "This standing authority is not covered by the Payment Services Regulations' chargeback "
            f"provisions. For disputes contact {merchant_name} directly.", field="legal"))
    return {
        "merchant_name": assert_ascii_dashes_only(merchant_name, field="merchant_name"),
        "authority_ref": authority_ref(descriptor),
        "lines": lines,
    }


__all__ = [
    "__version__", "SHA256_PREFIX", "CANON_VERSION", "MIN_CAP_PERIOD_SECONDS", "AUTHORITY_STATES",
    "PAYLOAD_VERSION", "STELLAR_MAX_EXPIRATION_LEDGER", "RecurrError", "sha256_jcs",
    "assert_ascii_dashes_only", "chain_family", "REVOCATION_METHOD", "revocation_method",
    "standing_authority", "authority_ref", "verify_authority_ref",
    "build_evm_approve", "build_solana_approve", "build_hedera_allowance", "build_stellar_soroban",
    "build_algorand_vault", "daily_cap_atomic", "signing_payload_ref", "disclosure_card",
]
