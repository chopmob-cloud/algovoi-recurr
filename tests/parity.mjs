// Byte-parity: the Node reference implementation must reproduce the exact authority_ref and ARC
// EVM payload_ref that the Python package produces (see tests/test_parity.py). The ARC case
// (10**12 scale) confirms the BigInt path keeps the scaled approve_amount exact across languages.
import {
  standingAuthority, authorityRef, buildEvmApprove, signingPayloadRef,
  keystoneChain, sha256Jcs,
} from '../typescript/dist/index.js';

const GOLDEN_AUTHORITY_REF = 'sha256:69ab6fe324fd020790ed291328125add4d737d9fe7be51dca9b4a57325b57ec8';
const GOLDEN_ARC_PAYLOAD_REF = 'sha256:dea6cbdcad08cf83b8f21fd819bbbc404248da44c218078f42f65e15d5bedb34';
const GOLDEN_KEYSTONE_CHAIN_REF = 'sha256:903af3449c0f8dc4aae4dc3447294bd5afc65668fb7d0b854808ebd01a2a88a5';

const d = standingAuthority({
  merchantRef: 'acme-sub-1', chain: 'base', customerWalletAddress: '0xCUST',
  capAmountMinor: 120_000_000, perCycleAmountMinor: 10_000_000, capPeriodSeconds: 2592000,
  asset: 'USDC', decimals: 6, expiresAt: '2027-05-08T00:00:00Z',
});
const gotAuth = authorityRef(d);
if (gotAuth !== GOLDEN_AUTHORITY_REF) {
  console.error('MISMATCH authority_ref:', gotAuth, '!=', GOLDEN_AUTHORITY_REF);
  process.exit(1);
}

const p = buildEvmApprove({
  chain: 'arc', chainId: 5042, assetContract: '0xUSDC_ARC', spender: '0xFAC',
  merchantPayoutAddress: '0xMERCH', customerAddress: '0xCUST',
  capAmountAtomic: 120_000_000, perCycleAmountAtomic: 10_000_000, decimals: 6, chainScale: 10 ** 12,
});
if (p.approve_amount !== '120000000000000000000') {
  console.error('MISMATCH arc approve_amount:', p.approve_amount);
  process.exit(1);
}
const gotPayload = signingPayloadRef(p);
if (gotPayload !== GOLDEN_ARC_PAYLOAD_REF) {
  console.error('MISMATCH payload_ref:', gotPayload, '!=', GOLDEN_ARC_PAYLOAD_REF);
  process.exit(1);
}

// Keystone composition: the standing_authority link is the recurr descriptor verbatim (its ref ==
// authority_ref), and the whole chain canonicalizes to the same golden reference as Python.
const chain = keystoneChain(d, {
  policy: { policy_id: 'aml.recurring', version: 1, max_amount: 10_000_000, deny_jurisdictions: ['XX'] },
  executions: [{ amount_minor: 10_000_000, cycle_index: 3, executed_at_ms: 1789000000000 }],
});
const sa = chain.chain[0];
if (('sha256:' + sha256Jcs(sa.preimage)) !== GOLDEN_AUTHORITY_REF) {
  console.error('MISMATCH standing_authority link ref:', 'sha256:' + sha256Jcs(sa.preimage), '!=', GOLDEN_AUTHORITY_REF);
  process.exit(1);
}
const gotChain = 'sha256:' + sha256Jcs(chain);
if (gotChain !== GOLDEN_KEYSTONE_CHAIN_REF) {
  console.error('MISMATCH keystone_chain ref:', gotChain, '!=', GOLDEN_KEYSTONE_CHAIN_REF);
  process.exit(1);
}

// Emitter hardening (must match Python): a fabricated partial mapping is not a descriptor, and an
// amount above the JS-safe integer range is refused so Node and Python never emit different bytes.
const partial = { per_cycle_amount_minor: 500, cap_amount_minor: 1000, expires_at: '2027-06-01T00:00:00Z', canon_version: 'jcs-rfc8785-v1' };
let refusedPartial = false;
try { keystoneChain(partial, { policy: { policy_id: 'p', max_amount: 500 }, executions: [{ amount_minor: 1, executed_at_ms: 1 }] }); }
catch { refusedPartial = true; }
if (!refusedPartial) { console.error('MISMATCH: partial (fabricated) descriptor was accepted'); process.exit(1); }

let refusedUnsafe = false;
try { keystoneChain(d, { policy: { policy_id: 'p', max_amount: 500 }, executions: [{ amount_minor: 2 ** 53 + 1, executed_at_ms: 1789000000000 }] }); }
catch { refusedUnsafe = true; }
if (!refusedUnsafe) { console.error('MISMATCH: amount above the JS-safe range was accepted'); process.exit(1); }

console.log('node OK', gotAuth, gotPayload, gotChain);
