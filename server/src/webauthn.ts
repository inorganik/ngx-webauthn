import * as crypto from 'crypto';
import base64url from 'base64url';
import * as cbor from 'cbor';
import { Certificate } from '@fidm/x509';
import * as iso_3166_1 from 'iso-3166-1';

export type AttestationType = 'direct' | 'indirect' | 'none';

export interface MakePublicKeyCredentialOptions {
  challenge: string;
  rp: PublicKeyRelyingPartyInfo;
  user: PublicKeyUserInfo;
  attestation: AttestationType;
  pubKeyCredParams: Array<PublicKeyCredParam>;
  timeout?: number;
  excludeCredentials?: string[];
  authenticatorSelection?: AuthenticatorSelection;
  extensions?: any;
  status?: string;
}
export interface AuthenticatorSelection {
  authenticatorAttachment?: 'platform' | 'cross-platform';
  requireResidentKey?: boolean;
  userVerification?: 'required' | 'preferred' | 'discouraged';
}
export interface PublicKeyRelyingPartyInfo {
  name: string;
  icon?: string;
  id?: string;
}
export interface PublicKeyUserInfo {
  id: string;
  name: string;
  displayName: string;
  icon?: string;
}
export interface PublicKeyCredParam {
  type: string;
  alg: number;
}

export interface EncodedAttestationResponse {
  attestationObject: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
}
export interface EncodedPublicKeyCredential {
  id: string;
  rawId: string;
  response: EncodedAttestationResponse;
  type: string; // 'public-key';
}
export interface PublicKeyCredentialRequestOptions {
  challenge: string;
  allowCredentials: Array<Credential>;
  status?: string;
}
export interface AuthenticatorData {
  rpIdHash: Buffer;
  flagsBuf: Buffer;
  flags: number;
  counter: number;
  counterBuf: Buffer;
  aaguid: Buffer;
  credID: Buffer;
  COSEPublicKey: Buffer;
  fmt?: string;
  publicKey?: string;
  signature?: string;
}
export interface AuthenticatorDataStruct {
  rpIdHash: Buffer;
  flagsBuf: Buffer;
  flags: number;
  counter: number;
  counterBuf: Buffer;
}
export interface AuthenticatorInfo {
  fmt: string;
  publicKey: string;
  counter: number;
  credID: string;
}
export interface VerificationResponse {
  verified: boolean;
  clientDataJSON?: string;
  authrInfo?: AuthenticatorInfo;
  counter?: number;
}

/**
 * U2F Presence constant
 */
const U2F_USER_PRESENTED = 0x01;

/**
 * Takes signature, data and PEM public key and tries to verify signature
 */
const verifySignature = (signature: Buffer, data: Buffer, publicKey: string): boolean => {
  return crypto.createVerify('SHA256')
    .update(data)
    .verify(publicKey, signature);
};


/**
 * Returns base64url encoded buffer of the given length
 */
export const randomBase64URLBuffer = (len?: number): string => {
  len = len || 32;

  const buff = crypto.randomBytes(len);

  return base64url(buff);
};

/**
 * Generates makeCredentials request
 */
export const generateServerMakeCredRequest = (username: string, displayName: string, id: string): MakePublicKeyCredentialOptions => {
  return {
    challenge: randomBase64URLBuffer(32),
    rp: {
      name: 'FIDO Examples Corporation'
    },
    user: { id, name: username, displayName },
    attestation: 'direct',
    authenticatorSelection: {
      userVerification: 'required'
    },
    pubKeyCredParams: [
      {
        type: 'public-key', alg: -7 // "ES256" IANA COSE Algorithms registry
      }
    ]
  };
};


/**
 * Generates getAssertion request from list of registered authenticators
 * and returns server encoded get assertion request
 */
export const generateServerGetAssertion = (authenticators: Array<AuthenticatorData>): PublicKeyCredentialRequestOptions => {
  const allowCredentials = [];
  for (const authr of authenticators) {
    allowCredentials.push({
      type: 'public-key',
      id: authr.credID,
      transports: ['usb', 'nfc', 'ble']
    });
  }
  return {
    challenge: randomBase64URLBuffer(32),
    allowCredentials
  };
};

/**
 * Returns SHA-256 digest of the given data.
 */
const hash = (data: Buffer): Buffer => {
  return crypto.createHash('SHA256').update(data).digest();
};

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 */
const COSEECDHAtoPKCS = (COSEPublicKey: Buffer): Buffer => {
  /*
     +------+-------+-------+---------+----------------------------------+
     | name | key   | label | type    | description                      |
     |      | type  |       |         |                                  |
     +------+-------+-------+---------+----------------------------------+
     | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
     |      |       |       | tstr    | the COSE Curves registry         |
     |      |       |       |         |                                  |
     | x    | 2     | -2    | bstr    | X Coordinate                     |
     |      |       |       |         |                                  |
     | y    | 2     | -3    | bstr /  | Y Coordinate                     |
     |      |       |       | bool    |                                  |
     |      |       |       |         |                                  |
     | d    | 2     | -4    | bstr    | Private key                      |
     +------+-------+-------+---------+----------------------------------+
  */

  const coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
  const tag = Buffer.from([0x04]);
  const x = coseStruct.get(-2);
  const y = coseStruct.get(-3);

  return Buffer.concat([tag, x, y]);
};

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 */
const ASN1toPEM = (pkBuffer: Buffer): string => {
  if (!Buffer.isBuffer(pkBuffer)) {
    throw new Error('ASN1toPEM: pkBuffer must be Buffer.');
  }

  let type;
  // TODO: test if this still works with triple equals
  // tslint:disable-next-line:triple-equals
  if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
    /*
        If needed, we encode rawpublic key to ASN structure, adding metadata:
        SEQUENCE {
          SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
             OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
          }
          BITSTRING <raw public key>
        }
        Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
    */

    pkBuffer = Buffer.concat([
      Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
      pkBuffer
    ]);

    type = 'PUBLIC KEY';
  } else {
    type = 'CERTIFICATE';
  }

  const b64cert = pkBuffer.toString('base64');

  let PEMKey = '';
  for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
    const start = 64 * i;
    PEMKey += b64cert.substr(start, 64) + '\n';
  }

  PEMKey = `-----BEGIN ${type}-----\n${PEMKey}-----END ${type}-----\n`;
  return PEMKey;
};

/**
 * Parses authenticatorData buffer.
 */
const parseMakeCredAuthData = (buffer: Buffer): AuthenticatorData => {
  const rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
  const flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
  const flags = flagsBuf[0];
  const counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
  const counter = counterBuf.readUInt32BE(0);
  const aaguid = buffer.slice(0, 16); buffer = buffer.slice(16);
  const credIDLenBuf = buffer.slice(0, 2); buffer = buffer.slice(2);
  const credIDLen = credIDLenBuf.readUInt16BE(0);
  const credID = buffer.slice(0, credIDLen); buffer = buffer.slice(credIDLen);
  const COSEPublicKey = buffer;

  return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey };
};

export const verifyAuthenticatorAttestationResponse = (webAuthnResponse: EncodedPublicKeyCredential): VerificationResponse => {
  const attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
  const ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];

  const response: VerificationResponse = { verified: false };
  if (ctapMakeCredResp.fmt === 'fido-u2f') {
    const authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

    if (!(authrDataStruct.flags & U2F_USER_PRESENTED)) {
      throw new Error('User was NOT presented durring authentication!');
    }

    const clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
    const reservedByte = Buffer.from([0x00]);
    const publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
    const signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

    const PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
    const signature = ctapMakeCredResp.attStmt.sig;

    response.verified = verifySignature(signature, signatureBase, PEMCertificate);

    if (response.verified) {
      response.authrInfo = {
        fmt: 'fido-u2f',
        publicKey: base64url.encode(publicKey),
        counter: authrDataStruct.counter,
        credID: base64url.encode(authrDataStruct.credID)
      };
    }
  } else if (ctapMakeCredResp.fmt === 'packed' && ctapMakeCredResp.attStmt.hasOwnProperty('x5c')) {
    const authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

    if (!(authrDataStruct.flags & U2F_USER_PRESENTED)) {
      throw new Error('User was NOT presented durring authentication!');
    }

    const clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
    const publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
    const signatureBase = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);

    const PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
    const signature = ctapMakeCredResp.attStmt.sig;

    const pem = Certificate.fromPEM(PEMCertificate);

    // Getting requirements from https://www.w3.org/TR/webauthn/#packed-attestation
    const aaguidExt = pem.getExtension('1.3.6.1.4.1.45724.1.1.4');

    response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
      // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
      verifySignature(signature, signatureBase, PEMCertificate) &&
      // version must be 3 (which is indicated by an ASN.1 INTEGER with value 2)
      pem.version == 3 &&
      // ISO 3166 valid country
      typeof iso_3166_1.whereAlpha2(pem.subject.countryName) !== 'undefined' &&
      // Legal name of the Authenticator vendor (UTF8String)
      pem.subject.organizationName &&
      // Literal string “Authenticator Attestation” (UTF8String)
      pem.subject.organizationalUnitName === 'Authenticator Attestation' &&
      // A UTF8String of the vendor’s choosing
      pem.subject.commonName &&
      // The Basic Constraints extension MUST have the CA component set to false
      !pem.extensions.isCA &&
      // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
      // verify that the value of this extension matches the aaguid in authenticatorData.
      // The extension MUST NOT be marked as critical.
      (aaguidExt != null ?
        (authrDataStruct.hasOwnProperty('aaguid') ?
          !aaguidExt.critical && aaguidExt.value.slice(2).equals(authrDataStruct.aaguid) : false)
        : true);

    if (response.verified) {
      response.authrInfo = {
        fmt: 'fido-u2f',
        publicKey: base64url.encode(publicKey),
        counter: authrDataStruct.counter,
        credID: base64url.encode(authrDataStruct.credID)
      };
    }

  } else if (ctapMakeCredResp.fmt === 'packed') { // Self signed
    const authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);
    if (!(authrDataStruct.flags & U2F_USER_PRESENTED)) {
      throw new Error('User was NOT presented durring authentication!');
    }

    const clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
    const publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
    const signatureBase = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);
    const PEMCertificate = ASN1toPEM(publicKey);

    const { attStmt: { sig: signature, alg } } = ctapMakeCredResp;

    response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
      // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
      verifySignature(signature, signatureBase, PEMCertificate) && alg === -7;

    if (response.verified) {
      response.authrInfo = {
        fmt: 'fido-u2f',
        publicKey: base64url.encode(publicKey),
        counter: authrDataStruct.counter,
        credID: base64url.encode(authrDataStruct.credID)
      };
    }

  } else {
    throw new Error('Unsupported attestation format! ' + ctapMakeCredResp.fmt);
  }

  return response;
};


/**
 * Takes an array of registered authenticators and find one specified by credID
 */
const findAuthr = (credID: string, authenticators: Array<AuthenticatorInfo>): AuthenticatorInfo => {
  const result = authenticators.find(authr => authr.credID === credID);
  if (result) {
    return result;
  } else {
    throw new Error(`Unknown authenticator with credID ${credID}!`);
  }
};

/**
 * Parses AuthenticatorData from GetAssertion response
 */
const parseGetAssertAuthData = (buffer: Buffer): AuthenticatorDataStruct => {
  const rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
  const flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
  const flags = flagsBuf[0];
  const counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
  const counter = counterBuf.readUInt32BE(0);

  return { rpIdHash, flagsBuf, flags, counter, counterBuf };
};

export const verifyAuthenticatorAssertionResponse = (
  webAuthnResponse: EncodedPublicKeyCredential,
  authenticators: Array<AuthenticatorInfo>
): VerificationResponse => {
  const authr = findAuthr(webAuthnResponse.id, authenticators);
  const authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData);

  const response: VerificationResponse = { verified: false };
  if (authr.fmt === 'fido-u2f') {
    const authrDataStruct = parseGetAssertAuthData(authenticatorData);

    if (!(authrDataStruct.flags & U2F_USER_PRESENTED)) {
      throw new Error('User was NOT presented durring authentication!');
    }

    const clientDataHash = hash(base64url.toBuffer(webAuthnResponse.response.clientDataJSON));
    const signatureBase = Buffer.concat([authrDataStruct.rpIdHash, authrDataStruct.flagsBuf, authrDataStruct.counterBuf, clientDataHash]);

    const publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));
    const signature = base64url.toBuffer(webAuthnResponse.response.signature);

    response.verified = verifySignature(signature, signatureBase, publicKey);
    response.counter = authrDataStruct.counter;
  }

  return response;
};
