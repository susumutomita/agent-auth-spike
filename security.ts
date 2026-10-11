import { timingSafeEqual } from "node:crypto";
import { jwtVerify, SignJWT } from "jose";
import { z } from "zod";
import type { LabConfig, SignedOverrides, TokenKeys } from "./types";

const accessClaims = z.object({
  sub: z.literal("synthetic-subject"),
  exp: z.number(),
  token_use: z.literal("access"),
  client_id: z.string(),
  scope: z.string(),
});

export async function signAccess(keys: TokenKeys, config: LabConfig, overrides: SignedOverrides = {}) {
  return new SignJWT({
    sub: "synthetic-subject", token_use: "access", client_id: config.clientId,
    scope: config.scope, iss: config.issuer, aud: config.resource,
    iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60,
    ...overrides,
  }).setProtectedHeader({ alg: "RS256", kid: "local-ephemeral" }).sign(keys.privateKey);
}

export async function verifyAccess(token: string, keys: TokenKeys, config: LabConfig) {
  const result = await jwtVerify(token, keys.publicKey, {
    issuer: config.issuer, audience: config.resource, algorithms: ["RS256"],
    requiredClaims: ["exp", "sub", "iss", "aud"],
  });
  const claims = accessClaims.parse(result.payload);
  if (claims.client_id !== config.clientId || !claims.scope.split(" ").includes(config.scope)) {
    throw new Error("invalid access authorization");
  }
  return claims.sub;
}

export async function challenge(verifier: string) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
}

export function equalSecret(actual: string, expected: string) {
  const a = Buffer.from(actual); const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Callback owner, rather than finishAuth(code), must validate state and URI. */
export class CallbackTransaction {
  readonly state = crypto.randomUUID();
  private consumed = false;
  constructor(private readonly callback: string, private readonly expires = Date.now() + 60_000) {}
  consume(location: URL) {
    const expected = new URL(this.callback);
    if (this.consumed || Date.now() >= this.expires || location.origin !== expected.origin ||
      location.pathname !== expected.pathname || !equalSecret(location.searchParams.get("state") ?? "", this.state)) {
      throw new Error("invalid callback transaction");
    }
    const code = location.searchParams.get("code");
    if (!code || location.searchParams.has("error")) throw new Error("invalid authorization result");
    this.consumed = true;
    return code;
  }
}

/** OIDC only: never use an ID token as the MCP Bearer. */
export async function verifyIdNonce(token: string, nonce: string, keys: TokenKeys, config: LabConfig) {
  const { payload } = await jwtVerify(token, keys.publicKey, {
    issuer: config.issuer, audience: config.clientId, algorithms: ["RS256"], requiredClaims: ["exp", "nonce"],
  });
  if (typeof payload.nonce !== "string" || !equalSecret(payload.nonce, nonce)) throw new Error("invalid nonce");
}
