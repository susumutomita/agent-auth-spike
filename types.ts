import type { JWTPayload } from "jose";

export interface LabConfig {
  issuer: string;
  resource: string;
  scope: string;
  clientId: string;
  callback: string;
}
export interface LabState {
  member: boolean;
  graphAvailable: boolean;
  enforcePkce: boolean;
  refreshAdmission: boolean;
  groupChecks: number;
  refreshes: number;
  tokenRequests: string[][];
  protocol?: string;
}
export interface TokenKeys {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}
export interface CodeGrant {
  challenge?: string;
  callback: string;
  clientId: string;
  resource: string;
  scope: string;
  nonce?: string;
  expires: number;
}
export interface RefreshGrant {
  clientId: string;
  resource: string;
  scope: string;
}
export interface SignedOverrides extends JWTPayload {
  token_use?: string;
  client_id?: string;
  scope?: string;
}
