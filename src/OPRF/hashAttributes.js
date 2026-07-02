/**
 * Hash-based claim commitments (COD-SSI, Sec. 2 "Hash-based Selective
 * Disclosure" and Sec. 5 "Implementation details").
 *
 * A claim value v_i is committed as x_i = HMAC_{t_i}(v_i) under a fresh salt
 * t_i, instantiated here with SHA3-512 and a 1024-bit salt (see config.json).
 * Using a keyed hash (rather than a plain H(v_i || t_i)) is the choice made in
 * the paper's prototype.
 */
import process from 'process';
import { createRequire } from 'module';


const require = createRequire(import.meta.url);

let crypto;
var config =require('../config.json');

// Verify that the platform's crypto provides the configured commitment hash.
try {
	crypto = require('crypto');
	if (!crypto.getHashes().includes(config.OPRF.H)) {
		console.error(`Configured hash "${config.OPRF.H}" is not available on this platform.`);
		process.exit(1);
	}
} catch (err) {
	console.error('crypto support is disabled');
	process.exit(1);
}



// Sample a random HMAC key (kept for completeness; salts are sampled inline
// by hashAttributes below).
export const generateHMACKey = async (keylength = 256) => {
  const byteLength = keylength / 8; // convert bits to bytes
  const keyBuffer = crypto.randomBytes(byteLength);
  return crypto.createSecretKey(keyBuffer);
};


/**
 * Compute the claim commitment x = HMAC_t(attribute).
 *
 * @param attribute  the claim value v_i to commit.
 * @param key        the salt t_i (hex string). If omitted, a fresh `keylength`-bit
 *                   salt is sampled -- used at commitment time. Pass the stored
 *                   salt to recompute and verify a commitment at disclosure time.
 * @param keylength  salt length in bits (default config.OPRF.NonceLength = 1024).
 * @param type       HMAC hash (default config.OPRF.H = sha3-512).
 * @returns { nonce, res } where `nonce` is the salt t_i and `res` is x_i (hex).
 */
export const hashAttributes = async (attribute, key = undefined, keylength = config.OPRF.NonceLength, type =config.OPRF.H) => {
	if(!key){
		   const byteLength = keylength / 8; // convert bits to bytes
       const keyBuffer = crypto.randomBytes(byteLength);
       key= crypto.createSecretKey(keyBuffer);
	     key = key.export().toString('hex');
	}


	 	const hmac = await crypto.createHmac(type,key);
   	hmac.update(attribute);
   	const result = await hmac.digest('hex');
    return { nonce: key, res: result};
}

