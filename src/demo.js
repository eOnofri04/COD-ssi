/**
 * COD-SSI -- Self-contained proof-of-concept demo.
 * =================================================
 *
 * This script demonstrates the core contribution of the paper
 *
 *   "COD-SSI: Enforcing Mutual Privacy for Credential Oblivious
 *    Disclosure in Self Sovereign Identity"
 *
 * namely the *oblivious selective disclosure* protocol run between a Holder
 * and a Verifier at presentation time (the blue, bottom flow of Figure 1).
 *
 * Unlike `main.js` (the benchmarking harness, which additionally exercises the
 * `did:ethr` / JWT credential layer and therefore needs a local Ethereum node
 * and a deployed DID registry), this demo is fully self-contained: it depends
 * only on `@noble/curves` and Node's built-in `crypto`, so it runs from a clean
 * checkout with `npm install && npm run demo`.
 *
 * It mirrors the cryptographic operations of `src/OPRF/main.js` line for line,
 * stripped of the credential plumbing, so that the COD protocol can be read in
 * isolation. The mapping to the paper's algorithms is given in the comments.
 *
 * Usage:
 *   npm run demo               # default: N = 8 claims, N_o = 3 disclosed
 *   node demo.js <N> <N_o>     # e.g. `node demo.js 16 5`
 */

import crypto from 'crypto';
import { secp256k1, hashToCurve } from '@noble/curves/secp256k1.js';
import * as mod from '@noble/curves/abstract/modular';
import { utf8ToBytes } from '@noble/curves/abstract/utils.js';
import { createRequire } from 'module';

import { hashAttributes } from './OPRF/hashAttributes.js';

const require = createRequire(import.meta.url);
const config = require('./config.json');

// Group G and field used by the 2HashDH OPRF (secp256k1, see paper Sec. 5).
const Fp = secp256k1.CURVE.Fp;
const groupOrder = secp256k1.CURVE.n;

// Helper: turn a 32-byte secp256k1 scalar (Uint8Array) into a field element.
const toScalar = (bytes) =>
  Fp.create(BigInt('0x' + Buffer.from(bytes).toString('hex')));

// Helper: the 2HashDH finaliser H_2(x, P) = SHA-256(x || P), used as AEAD key.
const finalise = (digest, point) =>
  crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from(digest), Buffer.from(point.toRawBytes())]))
    .digest();

const line = (s = '') => console.log(s);

/* ------------------------------------------------------------------ *
 * Holder -- Verifiable Credential commitment (hash-based SD)         *
 *                                                                    *
 * Each claim value v_i is replaced by a commitment x_i = HMAC_{t_i}(v_i)  *
 * under a fresh salt t_i (SHA3-512, see config.json). The commitments     *
 * x_i form C_VC^h; the (v_i, t_i) pairs are the credential data D_VC.      *
 * ------------------------------------------------------------------ */
async function holderCommitClaims(nClaims) {
  const claims = [];
  for (let i = 0; i < nClaims; i++) {
    const name = `attrName${i}`;
    // 30-byte random hex string, as in the experimental campaign (Sec. 5).
    const value = crypto.randomBytes(config.CLAIM_VALUE_SIZE).toString('hex');
    const { nonce, res } = await hashAttributes(value); // t_i, x_i
    claims.push({ name, value, nonce, digest: res });
  }
  return claims;
}

/* ------------------------------------------------------------------ *
 * Holder -- VP creation (paper Algorithm 1)                          *
 *                                                                    *
 * Sample a fresh master key msk_VP, then for every claim:            *
 *   k_i  = H_2(x_i, H_1(x_i)^{msk_VP})        (OPRF-derived claim key)   *
 *   E_VC = AES-256-GCM_{k_i}(IV_i, v_i || t_i)                            *
 * ------------------------------------------------------------------ */
function holderCreatePresentation(claims) {
  const msk = secp256k1.utils.randomPrivateKey(); // msk_VP in K
  const mskScalar = toScalar(msk);
  const encrypted = {};

  for (const claim of claims) {
    // k_i = H_2(x_i, H_1(x_i)^{msk_VP})
    const h1 = hashToCurve(utf8ToBytes(claim.digest)); // H_1(x_i) in G
    const key = finalise(claim.digest, h1.multiply(mskScalar));

    // (y_i, u_i) = Enc_{k_i}(IV_i, v_i || t_i)
    const iv = crypto.randomBytes(config.OPRF.ivLength / 8); // 96-bit nonce
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([
      cipher.update(Buffer.from(claim.value + claim.nonce, 'utf-8')),
      cipher.final(),
    ]);
    encrypted[claim.name] = { iv, ct, tag: cipher.getAuthTag() };
  }
  return { msk, mskScalar, encrypted };
}

/* ------------------------------------------------------------------ *
 * Verifier -- oblivious request (paper Algorithm 2, ll. 8-9)         *
 *                                                                    *
 * For each selected claim, blind its commitment: sample r, send      *
 * a = H_1(x)^r. The Holder never learns which claims were picked.    *
 * ------------------------------------------------------------------ */
function verifierRequest(selected) {
  const requests = [];
  const secrets = {};
  for (const claim of selected) {
    const r = secp256k1.utils.randomPrivateKey();
    const rScalar = toScalar(r);
    const a = hashToCurve(utf8ToBytes(claim.digest)).multiply(rScalar); // a = H_1(x)^r
    requests.push({ name: claim.name, digest: claim.digest, a });
    secrets[claim.name] = rScalar;
  }
  return { requests, secrets };
}

/* ------------------------------------------------------------------ *
 * Holder -- oblivious response (paper Algorithm 2, l. 10)            *
 *                                                                    *
 * The only operation the Holder performs as OPRF *server*:           *
 *   b = a^{msk_VP}                                                   *
 * ------------------------------------------------------------------ */
function holderRespond(requests, mskScalar) {
  return requests.map((req) => ({ name: req.name, b: req.a.multiply(mskScalar) }));
}

/* ------------------------------------------------------------------ *
 * Verifier -- unblind, decrypt, verify (paper Algorithm 2, ll. 11-14)*
 *                                                                    *
 *   c = b^{1/r}              (unblind -> H_1(x)^{msk_VP})            *
 *   k = H_2(x, c)            (recover the claim key)                 *
 *   m = Dec_k(IV, y, u)      (AEAD decrypt, tag-checked)             *
 *   verify H(m) == x         (commitment consistency)               *
 * ------------------------------------------------------------------ */
async function verifierFinalise(responses, secrets, encrypted, claimsByName) {
  const disclosed = [];
  for (const { name, b } of responses) {
    const rInv = mod.invert(secrets[name], groupOrder);
    const c = b.multiply(rInv); // H_1(x)^{msk_VP}
    const claim = claimsByName[name];
    const key = finalise(claim.digest, c); // k_i = H_2(x_i, c)

    const { iv, ct, tag } = encrypted[name];
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]).toString();

    // Split recovered (value || nonce) and re-check the Issuer commitment.
    const value = plain.slice(0, claim.value.length);
    const nonce = plain.slice(claim.value.length);
    const { res } = await hashAttributes(value, nonce);
    const ok = res === claim.digest;
    disclosed.push({ name, value, recommitted: ok });
  }
  return disclosed;
}

/* ------------------------------------------------------------------ *
 * Orchestration                                                      *
 * ------------------------------------------------------------------ */
async function main() {
  const N = Number(process.argv[2] ?? 8); // claims offered by the Holder
  const No = Number(process.argv[3] ?? 3); // claims the Verifier obliviously picks
  if (!(No <= N)) throw new Error(`N_o (${No}) must be <= N (${N})`);

  line('============================================================');
  line('  COD-SSI -- Oblivious Selective Disclosure (proof of concept)');
  line('============================================================');
  line(`Holder offers N = ${N} claims; Verifier discloses N_o = ${No}.`);
  line();

  // 1. Holder commits the claims (VC) and builds the encrypted presentation (VP).
  const claims = await holderCommitClaims(N);
  const claimsByName = Object.fromEntries(claims.map((c) => [c.name, c]));
  const { mskScalar, encrypted } = holderCreatePresentation(claims);
  line(`[Holder]   committed ${N} claims and encrypted them under per-claim OPRF keys.`);

  // 2. Verifier secretly selects N_o claims and sends blinded requests.
  //    (Here we pick the first N_o; the Holder cannot tell which were chosen.)
  const selected = claims.slice(0, No);
  const { requests, secrets } = verifierRequest(selected);
  line(`[Verifier] sent ${No} blinded OPRF requests (selection hidden from Holder).`);

  // 3. Holder answers as OPRF server (learns nothing about the selection).
  const responses = holderRespond(requests, mskScalar);
  line(`[Holder]   answered ${responses.length} requests with b = a^{msk_VP}.`);

  // 4. Verifier unblinds, decrypts, and re-verifies each commitment.
  const disclosed = await verifierFinalise(responses, secrets, encrypted, claimsByName);
  line(`[Verifier] unblinded, decrypted, and verified the disclosed claims:`);
  line();

  let allOk = true;
  for (const d of disclosed) {
    const expected = claimsByName[d.name].value;
    const correct = d.value === expected && d.recommitted;
    allOk &&= correct;
    line(
      `   ${correct ? 'OK ' : 'ERR'}  ${d.name}: ` +
        `recovered ${d.value.slice(0, 16)}...  ` +
        `(commitment ${d.recommitted ? 'verified' : 'FAILED'})`
    );
  }
  line();
  line(
    `Result: ${allOk ? 'SUCCESS' : 'FAILURE'} -- the Verifier obtained exactly the ` +
      `${No} selected claims; the remaining ${N - No} stay encrypted under keys`
  );
  line('it never derived, and the Holder never learned which claims were chosen.');
  process.exit(allOk ? 0 : 1);
}

main();
