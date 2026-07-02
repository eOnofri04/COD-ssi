/**
 * COD-SSI -- benchmarking harness (work in progress).
 *
 * This driver exercises the full credential stack on a local Ethereum network:
 * it creates Issuer/Holder/Verifier DIDs via `did:ethr`, issues and verifies
 * JWT VCs/VPs, and times each phase. Running it therefore requires external
 * infrastructure NOT bundled in this repository -- a Ganache node and a deployed
 * DID registry (`npm run ganache`, then a `truffle migrate` of the Ethr DID
 * registry contract).
 *
 * NOTE: this file is the harness skeleton and is not currently runnable as-is
 * (the `encryption` handle below is unbound, and it predates the oblivious
 * disclosure round now in `OPRF/main.js`). It is kept for reference while the
 * complete timing harness -- the one that produced `performancesData/` -- is
 * reintegrated. For a self-contained, runnable walkthrough of the actual COD-SSI
 * protocol, run `npm run demo` (see `demo.js`).
 */
import {Resolver} from 'did-resolver'
import getResolver from 'ethr-did-resolver'
import { EthrDID } from 'ethr-did'
import { ethers } from 'ethers' 
import { computePublicKey } from '@ethersproject/signing-key'
import bip39 from 'bip39'
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const hdkey = require('ethereumjs-wallet/hdkey')
const didJWT = require('did-jwt');
const config = require("./config.json");

import * as OPRF from './OPRF/main.js'

const output_file_name="OPRF1.csv";
const mnemonic = config.mnemonic;

//setup the provider 
console.log('Connecting to provider...');
const Web3HttpProvider = require('web3-providers-http')
const web3provider = new Web3HttpProvider('http://127.0.0.1:9545')
const provider = new ethers.providers.Web3Provider(web3provider)
//const provider = new ethers.providers.JsonRpcProvider('http://localhost:9545');

// get accounts provided by Truffle, with respective private keys


console.log('Connected to the provider');
//contract address of the registry
const RegAddress = '0x1482aDFDC2A33983EE69F9F8e4F852c467688Ea0';
	// create the DID resolver 
const ethrDidResolver = getResolver.getResolver(
	{
		rpcUrl: 'http://localhost:7545',
		registry: RegAddress,
		chainId: '0x539',
		provider
	}
);
const didResolver = new Resolver(ethrDidResolver)
const fs = require('fs')

const test = async (accounts) => {
	let issuerAddress=accounts[0];
	let subjectAddress=accounts[1];
	let verifierAddress=accounts[2];
	console.log("Issuer EOA:"+issuerAddress);
	console.log("Subject EOA:"+subjectAddress);
	console.log("Verifier EOA:"+verifierAddress);
	let issuerDID = await createDid(RegAddress, issuerAddress, 0);
	let subjectDID = await createDid(RegAddress, subjectAddress, 1);
	let verifierDID = await createDid(RegAddress, verifierAddress, 2);

	const file = fs.createWriteStream(output_file_name);
	file.on('error', (err) => {
		if(err) throw console.error(err)
	});
	file.write( 'Claims VCcreationTime stdDev VCKeyGenTime stdDev VCEncryptionTime stdDev VCSize VCverificationTime StdDev VPcreationTime stdDev VPSize VPverificationTime StdDev\n');
	file.end();

	for (let i = 1; i < config.maxClaims; i++) {
		//Subject create the VP
		const avgVcCreationTime=[];
		const avgKeyGenerationTime=[];
		const avgHashingTime=[];
		const avgVcSize=[];
		const avgVcVerificationTime=[];
		const avgVpCreationTime=[];
		const avgVpSize=[];
		const avgVpVerificationTime=[];
		const disclosedClaims=getDisclosedClaimsNumber(config.disclosedClaims, Math.pow(2, i));
		for (let j = 0; j <config.runs; j++) {
			//Issuer Create VC
			let vcResult=await encryption.issueVC(issuerDID,subjectDID,i);
			//Subject verify the VC
			avgVcCreationTime.push(vcResult.time);
			avgKeyGenerationTime.push(vcResult.timeKeyGen);
			avgHashingTime.push(vcResult.timeEnc);
			avgVcSize.push(memorySizeOf(vcResult.jwt));
			let timeVerifyVC=await encryption.verifyVC(vcResult.jwt,didResolver);
			avgVcVerificationTime.push(timeVerifyVC);	
			let vpResult= await encryption.issueVP(vcResult.jwt, disclosedClaims,subjectDID);
			avgVpCreationTime.push(vpResult.time);
			avgVpSize.push(memorySizeOf(vpResult.jwtVP));
			//Verifier verify the VP
			let timeverifyVP=await encryption.verifyVP(vpResult.jwtVP,didResolver);
			avgVpVerificationTime.push(timeverifyVP);
		}
		console.log("Claims:"+Math.pow(2,i)+" disclosed: "+disclosedClaims);
		if(i==1){
			avgVcCreationTime.shift();
			avgKeyGenerationTime.shift();
			avgHashingTime.shift();
			avgVcVerificationTime.shift();
			avgVpCreationTime.shift();
			avgVpVerificationTime.shift();
		}
	
		const VCcreationTime = avgVcCreationTime.reduce((a, b) => a + b, 0) / avgVcCreationTime.length;
		const VCkeyGenTime = avgKeyGenerationTime.reduce((a, b) => a + b, 0) / avgKeyGenerationTime.length;
		const VChashTime = avgHashingTime.reduce((a, b) => a + b, 0) / avgHashingTime.length;
		const vcSize = avgVcSize.reduce((a, b) => a + b, 0) / avgVcSize.length;
		const VCverification = avgVcVerificationTime.reduce((a, b) => a + b, 0) / avgVcVerificationTime.length;
		const VPcreationTime = avgVpCreationTime.reduce((a, b) => a + b, 0) / avgVpCreationTime.length;
		const vpSize = avgVpSize.reduce((a, b) => a + b, 0) / avgVpSize.length;
		const VPverification = avgVpVerificationTime.reduce((a, b) => a + b, 0) / avgVpVerificationTime.length;
		
		const data = Math.pow(2,i)+' '
		+VCcreationTime+' '
		+getStandardDeviation(avgVcCreationTime)+' '
		+VCkeyGenTime+' '
		+getStandardDeviation(avgKeyGenerationTime)+' '
		+VChashTime+' '
		+getStandardDeviation(avgHashingTime)+' '
		+vcSize+' '
		+VCverification+' '
		+getStandardDeviation(avgVcVerificationTime)+' '
		+VPcreationTime+' '
		+getStandardDeviation(avgVpCreationTime)+' '
		+vpSize+' '
		+VPverification+' '
		+getStandardDeviation(avgVpVerificationTime)+'\n';

		fs.appendFile(output_file_name, data, (err) => {
  		if (err) throw err;
  			console.log('Data appended to file');
		});
	}
}

provider.listAccounts().then((accounts) => {
	test(accounts);
});

//function that retrieves private keys of Truffle accounts
// return value : Promise
const getTrufflePrivateKey = (mnemonic, index) => {
	if (index < 0 || index > 9) throw new Error('please provide correct truffle account index')
	return bip39.mnemonicToSeed(mnemonic).then(seed => {
		const hdk = hdkey.fromMasterSeed(seed);
		const addr_node = hdk.derivePath(`m/44'/60'/0'/0/${index}`); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
		//const addr = addr_node.getWallet().getAddressString(); //check that this is the same with the address that ganache list for the first account to make sure the derivation is correct
		const privKey = addr_node.getWallet().getPrivateKey();
		const privKeyString = addr_node.getWallet().getPrivateKeyString();
		return {privKey,privKeyString};
	}).catch(error => console.log('getTrufflePrivateKey ERROR : ' + error));
}

//function to create and return the object used to manage a DID
const createDid = async (RegAddress, accountAddress, index, chainId = '0x539') => {
	return getTrufflePrivateKey(mnemonic, index)
		.then(privateKey => {
			const publicKey = computePublicKey(privateKey.privKey, true);
			const uncompressedPublicKey = computePublicKey(privateKey.privKey, false);
			console.log("Public Key: "+publicKey);
			console.log("Private Key: "+ privateKey.privKeyString);
			const identifier = `did:ethr:${chainId}:${publicKey}`;
			const signer = provider.getSigner(index);
			//const signJ=didJWT.SimpleSigner(privateKey);
		   //const signJ=didJWT.EllipticSigner(privateKey);
		  
		   //const signJ=didJWT.EdDSASigner(privateKey);
		   let signJ=didJWT.ES256KSigner(privateKey.privKey,false);
			const conf = {
				txSigner: signer,
				//privateKey : privateKey,
				signer: signJ,
				identifier: identifier,
				registry: RegAddress,
				chainNameOrId: chainId,
				alg: 'ES256K',
				provider
			};
			return new EthrDID(conf);
		})
}

function getStandardDeviation (array) {
  const n = array.length
  const mean = array.reduce((a, b) => a + b) / n
  return Math.sqrt(array.map(x => Math.pow(x - mean, 2)).reduce((a, b) => a + b) / n)
}

function getDisclosedClaimsNumber(fract,claimsTot){
	if (fract==1){
    	return claimsTot;
    }else{
	    if(claimsTot<=3){
		 	return 1;
		 }else{
		  	return Math.round(claimsTot*fract);
		 }
	}
}

function memorySizeOf(obj) {
    var bytes = 0;

    function sizeOf(obj) {
        if(obj !== null && obj !== undefined) {
            switch(typeof obj) {
            case 'number':
                bytes += 8;
                break;
            case 'string':
                bytes += obj.length * 2;
                break;
            case 'boolean':
                bytes += 4;
                break;
            case 'object':
                var objClass = Object.prototype.toString.call(obj).slice(8, -1);
                if(objClass === 'Object' || objClass === 'Array') {
                    for(var key in obj) {
                        if(!obj.hasOwnProperty(key)) continue;
                        sizeOf(obj[key]);
                    }
                } else bytes += obj.toString().length * 2;
                break;
            }
        }
        return bytes;
    };

    function formatByteSize(bytes) {
        if(bytes < 1024) return bytes + " bytes";
        else if(bytes < 1048576) return(bytes / 1024).toFixed(3) + " KiB";
        else if(bytes < 1073741824) return(bytes / 1048576).toFixed(3) + " MiB";
        else return(bytes / 1073741824).toFixed(3) + " GiB";
    };

    return sizeOf(obj);
};