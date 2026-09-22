/**
 * @algovoi/recurr -- the open format and method for AlgoVoi Recurr Tier 2 standing authorities.
 *
 * Recurr Tier 2 is a PSD2-aligned standing authority: a customer signs ONE on-chain authorization
 * that caps how much a named party may pull, on a schedule, and the operator then pulls
 * autonomously within that cap until it is revoked. This package is the openly-licensed
 * (Apache-2.0) format and method for that authorization: a chain-agnostic, content-addressed
 * standing-authority descriptor, per-chain customer-signing payload shapes (all standard public
 * primitives), per-chain revocation, and an informed-consent disclosure model.
 *
 * NOT the engine: no executor, no pull scheduler, no signing key, no facilitator, no ledger, no
 * vault contract source. The operator supplies the spender/facilitator and merchant-payout
 * addresses; submission, settlement, and the Algorand vault program stay in the commercial rail.
 *
 * Byte-identical to the Python `algovoi_recurr` module: same JCS (RFC 8785) + SHA-256 discipline,
 * same snake_case output keys, same authority_ref / payload_ref. Scaled amounts use BigInt so ARC
 * 18-decimal scaling (10**12) stays exact.
 */
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

export const SHA256_PREFIX = 'sha256:' as const;
export const CANON_VERSION = 'jcs-rfc8785-v1' as const;
export const MIN_CAP_PERIOD_SECONDS = 86400 as const;
export const AUTHORITY_STATES = ['pending', 'active', 'depleted', 'revoked', 'paused', 'errored'] as const;
export const STELLAR_MAX_EXPIRATION_LEDGER = 4294967295 as const;

export const PAYLOAD_VERSION: Record<string, string> = {
  algorand: 'algorand_spending_cap_vault_v1',
  voi: 'algorand_spending_cap_vault_v1',
  evm: 'evm_erc20_approve_v1',
  solana: 'solana_spl_approve_v1',
  hedera: 'hedera_hts_allowance_v1',
  stellar: 'stellar_soroban_auth_v2',
};

const DASH_CHARS = ['—', '–', '‒', '―', '−', '‑'];
const EVM_CHAINS = new Set(['base', 'tempo', 'arc']);
const VAULT_CHAINS = new Set(['algorand', 'voi']);

export class RecurrError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RecurrError';
  }
}

export function sha256Jcs(obj: unknown): string {
  const s = canonicalize(obj);
  if (s === undefined) throw new RecurrError('not JCS-canonicalisable');
  return createHash('sha256').update(s).digest('hex');
}

export function assertAsciiDashesOnly(text: string, field = 'text'): string {
  if (typeof text !== 'string') throw new RecurrError(`${field} must be a string`);
  const bad = DASH_CHARS.filter((c) => text.includes(c));
  if (bad.length) {
    const hexes = bad.map((c) => '0x' + c.codePointAt(0)!.toString(16)).join(', ');
    throw new RecurrError(
      `${field} contains a non-ASCII dash (${hexes}); use a plain ASCII hyphen, comma, or parentheses in disclosure copy`,
    );
  }
  return text;
}

// ── chain family + revocation ─────────────────────────────────────────────────
export function chainFamily(chain: string): string {
  const c = chain.toLowerCase();
  if (VAULT_CHAINS.has(c)) return 'vault';
  if (EVM_CHAINS.has(c)) return 'evm';
  if (c === 'solana' || c === 'hedera' || c === 'stellar') return c;
  throw new RecurrError(`unknown chain ${chain}`);
}

export const REVOCATION_METHOD: Record<string, string> = {
  vault: 'owner_withdraw + remove_agent on the spending-cap vault (unspent funds return to the owner)',
  evm: 'approve(spender, 0) from any EVM wallet',
  solana: 'SPL Token revoke on the delegated token account',
  hedera: 'AccountAllowanceApproveTransaction with amount 0',
  stellar: 'invoke the asset contract approve with amount 0 / an already-expired ledger',
};

export function revocationMethod(chain: string): string {
  return REVOCATION_METHOD[chainFamily(chain)];
}

// ── the chain-agnostic standing-authority descriptor ──────────────────────────
export interface StandingAuthorityInput {
  merchantRef: string;
  chain: string;
  customerWalletAddress: string;
  capAmountMinor: number;
  perCycleAmountMinor: number;
  capPeriodSeconds: number;
  asset?: string;
  decimals?: number;
  expiresAt?: string | null;
  canonVersion?: string;
}

export function standingAuthority(o: StandingAuthorityInput): Record<string, unknown> {
  const asset = o.asset ?? 'USDC';
  const decimals = o.decimals ?? 6;
  const expiresAt = o.expiresAt ?? null;
  for (const [name, val] of [['merchant_ref', o.merchantRef], ['chain', o.chain],
    ['customer_wallet_address', o.customerWalletAddress], ['asset', asset]] as const) {
    if (typeof val !== 'string' || !val) throw new RecurrError(`${name} must be a non-empty string`);
  }
  for (const [name, val] of [['cap_amount_minor', o.capAmountMinor],
    ['per_cycle_amount_minor', o.perCycleAmountMinor]] as const) {
    if (!Number.isInteger(val) || val <= 0) throw new RecurrError(`${name} must be a positive integer (minor units)`);
  }
  if (o.perCycleAmountMinor > o.capAmountMinor) {
    throw new RecurrError('per_cycle_amount_minor must not exceed cap_amount_minor');
  }
  if (!Number.isInteger(o.capPeriodSeconds) || o.capPeriodSeconds < MIN_CAP_PERIOD_SECONDS) {
    throw new RecurrError(`cap_period_seconds must be an integer >= ${MIN_CAP_PERIOD_SECONDS} (one day)`);
  }
  if (!Number.isInteger(decimals) || decimals < 0) throw new RecurrError('decimals must be a non-negative integer');
  if (expiresAt !== null && (typeof expiresAt !== 'string' || !expiresAt)) {
    throw new RecurrError('expires_at must be a non-empty ISO-8601 string or null');
  }
  return {
    asset,
    canon_version: o.canonVersion ?? CANON_VERSION,
    cap_amount_minor: o.capAmountMinor,
    cap_period_seconds: o.capPeriodSeconds,
    chain: o.chain,
    customer_wallet_address: o.customerWalletAddress,
    decimals,
    expires_at: expiresAt,
    merchant_ref: o.merchantRef,
    per_cycle_amount_minor: o.perCycleAmountMinor,
    revocation_method: revocationMethod(o.chain),
  };
}

export function authorityRef(descriptor: Record<string, unknown>): string {
  return SHA256_PREFIX + sha256Jcs(descriptor);
}

export function verifyAuthorityRef(descriptor: Record<string, unknown>, claimed: string): boolean {
  try {
    return authorityRef(descriptor) === claimed;
  } catch {
    return false;
  }
}

// ── per-chain customer-signing payloads (standard public primitives only) ─────
function scaledStr(amountAtomic: number, chainScale: number): string {
  if (!Number.isInteger(amountAtomic) || amountAtomic <= 0) throw new RecurrError('amount_atomic must be a positive integer');
  if (!Number.isInteger(chainScale) || chainScale < 1) throw new RecurrError('chain_scale must be a positive integer');
  // BigInt so ARC 18-decimal scaling (10**12) stays exact and matches Python's arbitrary int.
  return (BigInt(amountAtomic) * BigInt(chainScale)).toString();
}

export function buildEvmApprove(o: {
  chain: string; chainId: number; assetContract: string; spender: string; merchantPayoutAddress: string;
  customerAddress: string; capAmountAtomic: number; perCycleAmountAtomic: number; decimals?: number; chainScale?: number;
}): Record<string, unknown> {
  const approveAmount = scaledStr(o.capAmountAtomic, o.chainScale ?? 1);
  return {
    version: PAYLOAD_VERSION.evm,
    chain: o.chain,
    chain_id: o.chainId,
    asset_contract: o.assetContract,
    decimals: o.decimals ?? 6,
    spender: o.spender,
    merchant_payout_address: o.merchantPayoutAddress,
    customer_address: o.customerAddress,
    amount_atomic: o.capAmountAtomic,
    approve_amount: approveAmount,
    per_cycle_amount_atomic: o.perCycleAmountAtomic,
    actions: [{ kind: 'erc20_approve', args: { asset_contract: o.assetContract, spender: o.spender, amount: approveAmount } }],
  };
}

export function buildSolanaApprove(o: {
  assetMint: string; splTokenProgram: string; ataProgram: string; delegate: string; merchantPayoutAddress: string;
  customerAddress: string; capAmountAtomic: number; perCycleAmountAtomic: number; decimals?: number;
}): Record<string, unknown> {
  const approveAmount = scaledStr(o.capAmountAtomic, 1);
  return {
    version: PAYLOAD_VERSION.solana,
    chain: 'solana',
    asset_mint: o.assetMint,
    spl_token_program: o.splTokenProgram,
    ata_program: o.ataProgram,
    decimals: o.decimals ?? 6,
    delegate: o.delegate,
    merchant_payout_address: o.merchantPayoutAddress,
    customer_address: o.customerAddress,
    amount_atomic: o.capAmountAtomic,
    approve_amount: approveAmount,
    per_cycle_amount_atomic: o.perCycleAmountAtomic,
    actions: [{ kind: 'spl_token_approve', args: { asset_mint: o.assetMint, delegate: o.delegate, amount: approveAmount } }],
  };
}

export function buildHederaAllowance(o: {
  tokenId: string; ownerAccountId: string; spenderAccountId: string; merchantPayoutAccountId: string;
  capAmountAtomic: number; perCycleAmountAtomic: number; decimals?: number;
}): Record<string, unknown> {
  const approveAmount = scaledStr(o.capAmountAtomic, 1);
  return {
    version: PAYLOAD_VERSION.hedera,
    chain: 'hedera',
    token_id: o.tokenId,
    decimals: o.decimals ?? 6,
    owner_account_id: o.ownerAccountId,
    spender_account_id: o.spenderAccountId,
    merchant_payout_account_id: o.merchantPayoutAccountId,
    amount_atomic: o.capAmountAtomic,
    approve_amount: approveAmount,
    per_cycle_amount_atomic: o.perCycleAmountAtomic,
    actions: [{ kind: 'hts_allowance_approve', args: { token_id: o.tokenId, owner_account_id: o.ownerAccountId, spender_account_id: o.spenderAccountId, amount: approveAmount } }],
  };
}

export function buildStellarSoroban(o: {
  assetContractId: string; spenderAddress: string; merchantPayoutAddress: string; customerAddress: string;
  networkPassphrase: string; capAmountAtomic: number; perCycleAmountAtomic: number; decimals?: number; expirationLedger?: number;
}): Record<string, unknown> {
  const approveAmount = scaledStr(o.capAmountAtomic, 1);
  const expirationLedger = o.expirationLedger ?? STELLAR_MAX_EXPIRATION_LEDGER;
  return {
    version: PAYLOAD_VERSION.stellar,
    chain: 'stellar',
    asset_contract_id: o.assetContractId,
    decimals: o.decimals ?? 7,
    spender_address: o.spenderAddress,
    merchant_payout_address: o.merchantPayoutAddress,
    customer_address: o.customerAddress,
    network_passphrase: o.networkPassphrase,
    function_name: 'approve',
    amount_atomic: o.capAmountAtomic,
    approve_amount: approveAmount,
    per_cycle_amount_atomic: o.perCycleAmountAtomic,
    actions: [{ kind: 'soroban_invoke', args: { asset_contract_id: o.assetContractId, function_name: 'approve', from: o.customerAddress, spender: o.spenderAddress, amount: approveAmount, expiration_ledger: expirationLedger } }],
  };
}

export function buildAlgorandVault(o: {
  asaId: number; facilitatorAddress: string; merchantPayoutAddress: string; customerAddress: string;
  capAmountAtomic: number; perCycleAmountAtomic: number; dailyCapAtomic: number;
  vaultFundingMicroAlgo: number; vaultFundingAsaUnits: number;
  globalMaxPerTxn: number; globalDailyCap: number; globalMaxAsaPerTxn: number; allowlistEnabled?: boolean;
}): Record<string, unknown> {
  return {
    version: PAYLOAD_VERSION.algorand,
    vault_template: { create_args: {
      global_max_per_txn: o.globalMaxPerTxn,
      global_daily_cap: o.globalDailyCap,
      global_max_asa_per_txn: o.globalMaxAsaPerTxn,
      allowlist_enabled: o.allowlistEnabled ?? true,
    } },
    vault_funding_micro_algo: o.vaultFundingMicroAlgo,
    vault_funding_asa_units: o.vaultFundingAsaUnits,
    asa_id: o.asaId,
    facilitator_address: o.facilitatorAddress,
    merchant_payout_address: o.merchantPayoutAddress,
    customer_address: o.customerAddress,
    per_cycle_amount_atomic: o.perCycleAmountAtomic,
    daily_cap_atomic: o.dailyCapAtomic,
    cap_amount_atomic: o.capAmountAtomic,
    actions: [
      { name: 'deploy_vault', kind: 'create' },
      { name: 'fund_vault_algo', kind: 'payment', args: { amount: o.vaultFundingMicroAlgo } },
      { name: 'vault_opt_in_asa', kind: 'opt_in_asa', args: { asset: o.asaId } },
      { name: 'register_agent', kind: 'add_agent', args: { agent: o.facilitatorAddress, max_per_txn: o.perCycleAmountAtomic, daily_cap: o.dailyCapAtomic } },
      { name: 'register_recipient', kind: 'add_recipient', args: { recipient: o.merchantPayoutAddress, max_per_txn: o.perCycleAmountAtomic, daily_cap: o.dailyCapAtomic } },
      { name: 'fund_vault_usdc', kind: 'asset_transfer', args: { asset: o.asaId, amount: o.vaultFundingAsaUnits } },
    ],
  };
}

export function dailyCapAtomic(perCycleAmountAtomic: number, capAmountAtomic: number, capPeriodSeconds: number): number {
  if (capPeriodSeconds < MIN_CAP_PERIOD_SECONDS) throw new RecurrError(`cap_period_seconds must be >= ${MIN_CAP_PERIOD_SECONDS}`);
  const cycles = Math.max(1, Math.floor(capPeriodSeconds / MIN_CAP_PERIOD_SECONDS));
  return Math.max(perCycleAmountAtomic, Math.floor(capAmountAtomic / cycles));
}

export function signingPayloadRef(payload: Record<string, unknown>): string {
  return SHA256_PREFIX + sha256Jcs(payload);
}

// ── informed-consent disclosure model ─────────────────────────────────────────
export function disclosureCard(
  descriptor: Record<string, unknown>,
  o: { merchantName: string; cycleLabel: string; notPsrCovered?: boolean },
): Record<string, unknown> {
  const dec = Number(descriptor.decimals);
  const asset = String(descriptor.asset);
  const total = Number(descriptor.cap_amount_minor) / 10 ** dec;
  const perCycle = Number(descriptor.per_cycle_amount_minor) / 10 ** dec;
  const notPsr = o.notPsrCovered ?? true;
  const lines: string[] = [
    assertAsciiDashesOnly(`You are authorising ${o.merchantName} to pull payments from your wallet.`, 'summary'),
    `Per cycle: up to ${perCycle.toFixed(2)} ${asset} (${o.cycleLabel}).`,
    `Total cap: ${total.toFixed(2)} ${asset}.`,
    `Chain: ${descriptor.chain}.`,
    `You sign a one-time on-chain authorization; ${o.merchantName} then pulls automatically within the cap.`,
    `Revoke any time: ${descriptor.revocation_method}.`,
  ];
  if (descriptor.expires_at) lines.splice(3, 0, `Authority expires: ${descriptor.expires_at}.`);
  if (notPsr) {
    lines.push(assertAsciiDashesOnly(
      "This standing authority is not covered by the Payment Services Regulations' chargeback " +
      `provisions. For disputes contact ${o.merchantName} directly.`, 'legal'));
  }
  return {
    merchant_name: assertAsciiDashesOnly(o.merchantName, 'merchant_name'),
    authority_ref: authorityRef(descriptor),
    lines,
  };
}

// ── compose into a Keystone chain (verify offline with the external Keystone verifier) ─────────
export const KEYSTONE_SCHEMA = 'algovoi-keystone-chain/v2' as const;
export const KEYSTONE_COMPOSITION = 'recurring-standing-authority/v1' as const;
// Every field a recurr standing-authority descriptor carries (see standingAuthority()); the
// composition requires the whole shape so a fabricated partial object cannot pose as an authority.
const DESCRIPTOR_FIELDS = [
  'asset', 'canon_version', 'cap_amount_minor', 'cap_period_seconds', 'chain',
  'customer_wallet_address', 'decimals', 'expires_at', 'merchant_ref',
  'per_cycle_amount_minor', 'revocation_method',
] as const;

function execLink(
  index: number, only: boolean, execution: Record<string, unknown>,
  authorityName: string, policyName: string,
): Record<string, unknown> {
  const amt = execution.amount_minor;
  const ts = execution.executed_at_ms;
  // Number.isSafeInteger (not isInteger): reject a value above 2**53 that Node would round while
  // Python keeps exact, so the two emitters stay byte-parity and fail closed on an out-of-range one.
  for (const [name, val] of [['amount_minor', amt], ['executed_at_ms', ts]] as const) {
    if (typeof val !== 'number' || !Number.isSafeInteger(val) || val <= 0) {
      throw new RecurrError(`execution ${name} must be a positive integer within the JS-safe range`);
    }
  }
  const preimage: Record<string, unknown> = {
    authority_ref: '@' + authorityName,
    policy_ref: '@' + policyName,
    amount_minor: amt,
  };
  if ('cycle_index' in execution) {
    const ci = execution.cycle_index;
    if (typeof ci !== 'number' || !Number.isSafeInteger(ci) || ci < 0) {
      throw new RecurrError('execution cycle_index must be a non-negative integer within the JS-safe range');
    }
    preimage.cycle_index = ci;
  }
  preimage.executed_at_ms = ts;
  return { name: only ? 'execution' : `execution_${index}`, preimage };
}

/**
 * Compose a Recurr standing authority into an offline-verifiable Keystone chain.
 *
 * The authority link preimage is the recurr `descriptor` VERBATIM, so that link's Keystone
 * reference is exactly `authorityRef(descriptor)`, byte-for-byte -- the recurr authority_ref IS the
 * keystone link ref. `policy` is the operator's opaque `policy_bound` preimage (recurr does not own
 * policy shape). Each execution (positive-integer `amount_minor` + `executed_at_ms`, optional
 * `cycle_index`) becomes an execution link bound to the authority and policy via `@` alias markers,
 * under one `recurring_cap` assertion.
 *
 * FORMAT and METHOD only: it EMITS the composition. The cap checks are enforced by the external
 * Keystone verifier, not here -- verify the emitted chain offline with `algovoi-keystone`.
 */
export function keystoneChain(
  descriptor: Record<string, unknown>,
  o: {
    policy: Record<string, unknown>;
    executions: ReadonlyArray<Record<string, unknown>>;
    authorityName?: string;
    policyName?: string;
  },
): Record<string, unknown> {
  const authorityName = o.authorityName ?? 'standing_authority';
  const policyName = o.policyName ?? 'policy_bound';
  const missing = DESCRIPTOR_FIELDS.filter((f) => !(f in descriptor));
  if (missing.length > 0) {
    throw new RecurrError(`descriptor is not a recurr standing authority (missing ${JSON.stringify(missing)})`);
  }
  if (descriptor.expires_at === null || descriptor.expires_at === undefined || descriptor.expires_at === '') {
    throw new RecurrError('descriptor.expires_at must be set to compose a Keystone chain');
  }
  if (o.policy === null || typeof o.policy !== 'object' || Object.keys(o.policy).length === 0) {
    throw new RecurrError('policy must be a non-empty object (the operator policy_bound preimage)');
  }
  if (!o.executions || o.executions.length === 0) {
    throw new RecurrError('executions must be a non-empty array');
  }
  const only = o.executions.length === 1;
  const chain: Array<Record<string, unknown>> = [
    { name: authorityName, preimage: { ...descriptor } },
    { name: policyName, preimage: { ...o.policy } },
  ];
  const execNames: string[] = [];
  o.executions.forEach((e, i) => {
    const link = execLink(i, only, e, authorityName, policyName);
    chain.push(link);
    execNames.push(link.name as string);
  });
  return {
    schema: KEYSTONE_SCHEMA,
    canon: CANON_VERSION,
    composition: KEYSTONE_COMPOSITION,
    chain,
    assertions: [{
      kind: 'recurring_cap',
      authority: authorityName,
      policy: policyName,
      executions: execNames,
    }],
  };
}
