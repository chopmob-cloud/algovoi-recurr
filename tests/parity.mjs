// Byte-parity: the Node reference implementation must reproduce the exact authority_ref and ARC
// EVM payload_ref that the Python package produces (see tests/test_parity.py). The ARC case
// (10**12 scale) confirms the BigInt path keeps the scaled approve_amount exact across languages.
import {
  standingAuthority, authorityRef, buildEvmApprove, signingPayloadRef,
} from '../typescript/dist/index.js';

const GOLDEN_AUTHORITY_REF = 'sha256:69ab6fe324fd020790ed291328125add4d737d9fe7be51dca9b4a57325b57ec8';
const GOLDEN_ARC_PAYLOAD_REF = 'sha256:dea6cbdcad08cf83b8f21fd819bbbc404248da44c218078f42f65e15d5bedb34';

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
console.log('node OK', gotAuth, gotPayload);
