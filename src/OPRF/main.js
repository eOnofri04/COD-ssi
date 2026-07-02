/**
 * COD-SSI -- reference implementation of the oblivious selective-disclosure
 * protocol (paper Algorithms 1 and 2).
 *
 * This module is imported by the benchmarking harness (`../main.js`) which wraps
 * it in the full `did:ethr` / JWT credential layer to collect the timings in
 * `performancesData/`. For a self-contained, chain-free walkthrough of the same
 * protocol see `../demo.js`.
 *
 * Crypto choices (paper Sec. 5):
 *   - OPRF: 2HashDH over secp256k1; H_1 = noble hash-to-curve, H_2 = SHA-256.
 *   - Commitment: x_i = HMAC-SHA3-512_{t_i}(v_i)   (see hashAttributes.js).
 *   - AEAD: AES-256-GCM with a fresh 96-bit IV per claim.
 *
 * Implementation note: this is a proof of concept. Two simplifications w.r.t.
 * the formal description are worth flagging: (i) AES-GCM is used without the
 * associated data x_i that the algorithms specify; and (ii) the `disclosure`
 * map below is module-level state shared across calls (sufficient for the
 * single-credential benchmark loop, but not reentrant).
 */
import {hashAttributes} from './hashAttributes.js'
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
import crypto from 'crypto';
import { createRequire } from 'module';
import { secp256k1, hashToCurve, encodeToCurve } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/curves/abstract/utils.js';
import * as mod from '@noble/curves/abstract/modular';


const require = createRequire(import.meta.url);
var config =require('../config.json');


const options = {		
		header: {
			"typ": "JWT",
			"alg": "ES256K"
		},
	};

// Module-level record of the claims placed in the current credential: maps each
// claim name to its clear value and salt, so the Holder can later re-derive keys
// and the Verifier can re-check commitments. See implementation note in header.
let disclosure=new Map();


const randomString = crypto.randomBytes(config.CLAIM_VALUE_SIZE).toString('hex');

console.log("Random String length: "+config.CLAIM_VALUE_SIZE+" bytes "+randomString.length+" characters")
async function createVCPayload(user,nClaims,claimValueSize) {
	const VCPayload={};
	//VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vc']= {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiableCredential'],
			credentialSubject: {}
		};
	let hashedAttr;
	let hashTimeVCCreation=[];
	for (let i = 0; i < nClaims; i++) {
		let start = performance.now();
		var attrName="attrName"+i;
		var attrValue=randomString;

  		hashedAttr = await hashAttributes(attrValue,undefined,undefined,undefined);
  		disclosure.set(attrName,{path : [attrName],clearValue : attrValue,nonce : hashedAttr.nonce});
  		VCPayload['vc']['credentialSubject'][attrName] = hashedAttr.res;
  		let end = performance.now();
  		hashTimeVCCreation.push((end-start));
	} 
	//console.log(disclosure);
	return {res: VCPayload,timeKeyGen: hashedAttr.timeKeyGen,timeHash: hashTimeVCCreation};
}

// Issuer side: build a hash-based SD credential with 2^nClaims claims and sign
// it as a JWT VC. `nClaims` is the log2 of the claim count used by the benchmark.
export async function issueVC(issuer,subject,nClaims,claimValueSize){
	let start = performance.now();
	const VCPayload = await createVCPayload(subject,Math.pow(2, nClaims),claimValueSize);
	const jwt = await createVerifiableCredentialJwt(VCPayload.res, issuer, options);
	let end = performance.now();
	let time = (end-start);
	return {jwt,time:time,timeHash:VCPayload.timeHash,metadata:disclosure};
}

// Verifier/Holder side: validate the VC JWT (signature, issuer DID resolution).
export async function verifyVC(jwt,didResolver){
	let start = performance.now();
	const verifiedCredential= await verifyCredential(jwt, didResolver,{});
	let end = performance.now();
	const time = (end-start);
	return {verifiedVC: verifiedCredential,time:time};
}

// NOTE: unused legacy helper. It encrypts a claim under a *random* AES key and
// predates the protocol: the actual COD-SSI VP encryption (createVPPayload below)
// uses the OPRF-derived key k_i = H_2(x_i, H_1(x_i)^{msk_VP}). Kept for reference.
function createEncryptedClaim(keySize,ivSize,type,claimValue,nonce){
	const key = crypto.randomBytes(keySize/8); // AES-256 key
	const iv = crypto.randomBytes(ivSize/8); // AES-GCM standard IV size
	let cipher = crypto.createCipheriv(type, Buffer.from(key), Buffer.from(iv));
    let encrypted = Buffer.concat([cipher.update(Buffer.from(claimValue+nonce)),cipher.final()]);
    return{encryptedValue: encrypted, k: key, v: iv}
}

// VP creation (paper Algorithm 1): sample a fresh master key msk_VP, then for
// every claim derive a per-claim key k_i = H_2(x_i, H_1(x_i)^{msk_VP}) and
// AES-GCM-encrypt (value || salt) under it. Returns the VP message, msk_VP, and
// per-claim encryption timings.
function createVPPayload(vc) {
	const VPkey = secp256k1.utils.randomPrivateKey();
	const VCPayload={};
    VCPayload['vp']= {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			id: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
			type: ['VerifiablePresentation'],
			verifiableCredential: [vc.jwt]
		};
	const VPmetadata={};
	VPmetadata['vpId']=VCPayload.vp.id;
	let vPcreationEncryptionTime=[];
	disclosure.forEach (function(value, key){
		let start = performance.now();
		let name=key;
		let digest=vc.verifiableCredential.credentialSubject[key];
		let nonce=value.nonce;
		let clearValue=value.clearValue;
		const v1=hashToCurve(utf8ToBytes(digest));
		const VPkeyScalar = secp256k1.CURVE.Fp.create(BigInt('0x' + Buffer.from(VPkey).toString('hex')));
		const v2=v1.multiply(VPkeyScalar);
		const concatenated = Buffer.concat([Buffer.from(digest), Buffer.from(v2.toRawBytes())]);
		const hash = crypto.createHash('sha256');
		const aesKey=hash.update(concatenated).digest(); 
		const M = Buffer.from(clearValue+nonce, 'utf-8');
		// AES-GCM requires a 12-byte IV (nonce)
		const iv = crypto.randomBytes(12);
		// Encrypt
		const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
		const encrypted = Buffer.concat([cipher.update(M), cipher.final()]);
		const authTag = cipher.getAuthTag();
		// Output
		VPmetadata[key]={e:encrypted,iv:iv,authTag:authTag}
		let end = performance.now();
		const time = (end-start);
		vPcreationEncryptionTime.push(time);
	});
	const VPMessage={vp:VCPayload,metadata:VPmetadata};
	let str = JSON.stringify(VPMessage);
	str = JSON.stringify(VPMessage, null, 4); // (Optional) beautiful indented output.
	//console.log("VP message: "+str);
	return {VPMessage:VPMessage,VPkey:VPkey,VPcreationEncryptionTime:vPcreationEncryptionTime};
}

// Holder side: wrap the encrypted presentation (createVPPayload) into a signed
// JWT VP. Returns the VP JWT, the master key msk_VP (VPkey) and the encrypted
// claim material (metadata) needed by the disclosure round below.
export async function issueVP(jwt, subject){
	let start = performance.now();
	const VPresult=createVPPayload(jwt);
	const VPMessage=VPresult.VPMessage;
	const VPkey=VPresult.VPkey;
	let jwtVP=await createVerifiablePresentationJwt(VPMessage.vp,subject,options);
	let end = performance.now();
	let time = (end-start);
	return {jwtVP:jwtVP,time:time,VPcreationEncryptionTime:VPresult.VPcreationEncryptionTime,metadata:VPMessage.metadata,VPkey:VPkey};
}

export async function verifyVP(jwtVP,didResolver){
	let start = performance.now();
	const verifiedPresentation= await verifyPresentation(jwtVP, didResolver,{});
	let unverifiedVCs = verifiedPresentation.verifiablePresentation.verifiableCredential;
	const verifiedVP = verifiedPresentation.verifiablePresentation;
	//let str = JSON.stringify(verifiedVP, null, 4); // (Optional) beautiful indented output.
	//console.log(str)
	let end = performance.now();
	const time = (end-start);
	return {time:time,verifiedVP:verifiedVP};
}


// Verifier side -- oblivious request (paper Algorithm 2, ll. 8-9). For each of
// the `disclosedClaims` selected claims, blind its commitment x with a fresh r:
// a = H_1(x)^r. The blinding factors r are kept secret in `randomV` for unblinding.
export async function dislcosureRequestVP(verifiedVP,vpMetadata,disclosedClaims){
	let start = performance.now();
	//Verifier
	let str = JSON.stringify(verifiedVP, null, 4); // (Optional) beautiful indented output.
	const VPDisclosureRequest={};
	const VPDisclosureRequestBinding={};
	VPDisclosureRequest['id']=verifiedVP.vp.id;
	let claimsNames=Object.keys(verifiedVP['verifiableCredential'][0]['credentialSubject']);
	let keys=Array.from(disclosure.keys());
	const values = [];
	const random={};
	let sDrequestVPclaimsCreationTime=[];
	for (let i = 0; i < disclosedClaims; i++) {
			let t1=performance.now();
			let name=claimsNames[i];
			let digest=verifiedVP.verifiableCredential[0].credentialSubject[name];
			const r = secp256k1.utils.randomPrivateKey();
			const r_scalar = secp256k1.CURVE.Fp.create(BigInt('0x' + Buffer.from(r).toString('hex')));
			const requestedClaimDigest = hashToCurve(utf8ToBytes(digest));
			const A = requestedClaimDigest.multiply(r_scalar);
			values.push(A);
			random[name]=r_scalar;
			let t2=performance.now();
			sDrequestVPclaimsCreationTime.push((t2-t1));
	}
	VPDisclosureRequest['values']=values;
	let end = performance.now();
	const time = (end-start);
	return {time:time,VPDisclosureRequest:VPDisclosureRequest,randomV:random,SDrequestVPclaimsCreationTime:sDrequestVPclaimsCreationTime};
}


// Holder side -- oblivious response (paper Algorithm 2, l. 10). Acting as OPRF
// server, exponentiate each blinded point by msk_VP: b = a^{msk_VP}. The Holder
// learns nothing about which claims were requested.
export async function disclosureResponseVP(VPDisclosureRequest,VPkey){
	//Holder
	let start = performance.now();
	const VPkeyScalar = secp256k1.CURVE.Fp.create(BigInt('0x' + Buffer.from(VPkey).toString('hex')));
	const values=[];
	let vpSDResponseClaimTime=[];
	for (const element of VPDisclosureRequest.values) {
		let t1=performance.now();
		const B = element.multiply(VPkeyScalar);
		values.push(B);
		let t2=performance.now();
		vpSDResponseClaimTime.push((t2-t1));
	}
	let end = performance.now();
	const time = (end-start);
	const disclosureResponse={id:VPDisclosureRequest['id'], values:values };
	return {time:time,disclosureResponse:disclosureResponse,vpSDResponseClaimTime:vpSDResponseClaimTime};
}

// Verifier side -- unblind and decrypt (paper Algorithm 2, ll. 11-13). Recover
// c = b^{1/r} = H_1(x)^{msk_VP}, derive the claim key k = H_2(x, c), and
// AES-GCM-decrypt the stored ciphertext (tag-checked) to obtain (value || salt).
export async function decryptionDislcosureResponseVP(randomValues,disclosureResponse,verifiedVP,vpMetadata){
	let start = performance.now();
	let i=0;
	let vpSDresponseDecryptionClaimTime=[];
	const decryptedValues={};
	for (const [key, value] of Object.entries(randomValues)) {
		let t1=performance.now();
		const rInv = mod.invert(value, secp256k1.CURVE.n);
		let B=disclosureResponse.values[i];
		const C = B.multiply(rInv);
		let digest=verifiedVP.verifiableCredential[0].credentialSubject[key];
		const concatenation = Buffer.concat([Buffer.from(digest), Buffer.from(C.toRawBytes())]);
		const hash2 = crypto.createHash('sha256');
		const aesKeyVerifier=hash2.update(concatenation).digest(); 
		try {
  			const decipher = crypto.createDecipheriv('aes-256-gcm', aesKeyVerifier, vpMetadata[key].iv);
  			decipher.setAuthTag(vpMetadata[key].authTag);
  			const decrypted = Buffer.concat([
    				decipher.update(vpMetadata[key].e),
    			decipher.final()
  				]);
				const nonceLength=Math.ceil(config.OPRF.NonceLength / 4);
				const d=decrypted.toString();
				decryptedValues[key]=d;
			} catch (err) {
  				console.error("Decryption failed:", err.message);
			}
		i++;
		let t2=performance.now();
		vpSDresponseDecryptionClaimTime.push((t2-t1));
	}
	let end = performance.now();
	const time = (end-start);

	return {time:time,vpSDresponseDecryptionClaimTime:vpSDresponseDecryptionClaimTime,decryptedValues:decryptedValues};
}


// Verifier side -- commitment check (paper Algorithm 2, l. 14). Split the
// decrypted (value || salt) and recompute the commitment H(value || salt),
// confirming it matches the digest x certified inside the Issuer-signed VC.
export async function verifyDislcosureResponseVP(decryptedValues,verifiedVP){
	let start = performance.now();
	let vpSDresponseVerificationClaimTime=[];
	const nonceLength=Math.ceil(config.OPRF.NonceLength / 4);
	let i=0;
	for (const [key, d] of Object.entries(decryptedValues)) {
		let t1=performance.now();
		const digest=verifiedVP.verifiableCredential[0].credentialSubject[key];
		const nonce=d.substring(d.length-1-nonceLength+1, d.length);
		const value=d.substring(0,d.length-1-nonceLength+1);
		const hashedAttr = await hashAttributes(value,nonce,undefined,undefined);
		if(hashedAttr.res!==digest){
			console.log("Issue!");
		}
		let t2=performance.now();
		vpSDresponseVerificationClaimTime.push((t2-t1));
	}
	let end = performance.now();
	const time = (end-start);
	return {time:time,vpSDresponseVerificationClaimTime:vpSDresponseVerificationClaimTime};
}

