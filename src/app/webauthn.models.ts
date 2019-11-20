export type AttestationType = 'direct' | 'indirect' | 'none';

export interface PublicKeyCredentialOptions {
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
