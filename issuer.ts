import { SignJWT } from "jose";
import { z } from "zod";
import { challenge, equalSecret, signAccess } from "./security";
import type { CodeGrant, LabConfig, LabState, RefreshGrant, TokenKeys } from "./types";

const authorizationInput = z.object({
  response_type: z.literal("code"), client_id: z.string(), redirect_uri: z.string(),
  resource: z.string(), scope: z.string(), state: z.string().min(1),
  code_challenge: z.string().optional(), code_challenge_method: z.literal("S256").optional(),
  nonce: z.string().optional(),
});
const tokenInput = z.object({
  grant_type: z.enum(["authorization_code", "refresh_token"]), client_id: z.string(),
  code: z.string().optional(), code_verifier: z.string().optional(),
  redirect_uri: z.string().optional(), refresh_token: z.string().optional(), resource: z.string().optional(),
});
const fail = (error: string) => Response.json({ error }, { status: 400 });

/** Synthetic issuer, NOT a Cognito/Entra emulator. No login UI or real identity. */
export function makeIssuer(config: LabConfig, state: LabState, keys: TokenKeys) {
  const codes = new Map<string, CodeGrant>();
  const refreshTokens = new Map<string, RefreshGrant>();
  async function issue(grant: RefreshGrant, nonce?: string) {
    const refresh = crypto.randomUUID(); refreshTokens.set(refresh, grant);
    const tokens = {
      access_token: await signAccess(keys, config, { aud: grant.resource, scope: grant.scope }),
      token_type: "Bearer", expires_in: 60, refresh_token: refresh, scope: grant.scope,
    };
    if (!nonce) return Response.json(tokens);
    const idToken = await new SignJWT({ nonce, token_use: "id", sub: "synthetic-subject" })
      .setProtectedHeader({ alg: "RS256" }).setIssuer(config.issuer).setAudience(config.clientId)
      .setExpirationTime("60s").sign(keys.privateKey);
    return Response.json({ ...tokens, id_token: idToken });
  }
  return async (request: Request) => {
    const url = new URL(request.url);
    if (url.pathname === "/.well-known/oauth-authorization-server") return Response.json({
      issuer: config.issuer, authorization_endpoint: `${config.issuer}/authorize`,
      token_endpoint: `${config.issuer}/token`, response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [config.scope],
    });
    if (url.pathname === "/authorize" && request.method === "GET") {
      const input = authorizationInput.safeParse(Object.fromEntries(url.searchParams));
      if (!input.success) return fail("invalid_request");
      const p = input.data;
      if (p.client_id !== config.clientId || p.redirect_uri !== config.callback ||
        p.resource !== config.resource || p.scope !== config.scope) return fail("invalid_request");
      if ((state.enforcePkce && !p.code_challenge) || (p.code_challenge && p.code_challenge_method !== "S256")) {
        return fail("invalid_request");
      }
      const code = crypto.randomUUID();
      codes.set(code, { challenge: p.code_challenge, callback: p.redirect_uri, clientId: p.client_id,
        resource: p.resource, scope: p.scope, nonce: p.nonce, expires: Date.now() + 60_000 });
      const callback = new URL(p.redirect_uri); callback.searchParams.set("code", code);
      callback.searchParams.set("state", p.state);
      return new Response(null, { status: 302, headers: { location: callback.toString() } });
    }
    if (url.pathname === "/token" && request.method === "POST") {
      if (!request.headers.get("content-type")?.startsWith("application/x-www-form-urlencoded")) return fail("invalid_request");
      const params = new URLSearchParams(await request.text());
      state.tokenRequests.push([...params.keys()].sort()); // names only, never credential values
      const input = tokenInput.safeParse(Object.fromEntries(params));
      if (!input.success || input.data.client_id !== config.clientId) return fail("invalid_client");
      const p = input.data;
      if (p.grant_type === "authorization_code") {
        const grant = codes.get(p.code ?? "");
        if (!grant || grant.expires <= Date.now() || p.redirect_uri !== grant.callback ||
          p.client_id !== grant.clientId || (p.resource && p.resource !== grant.resource)) return fail("invalid_grant");
        if (grant.challenge && (!p.code_verifier || !equalSecret(await challenge(p.code_verifier), grant.challenge))) {
          return fail("invalid_grant");
        }
        codes.delete(p.code ?? "");
        return issue(grant, grant.nonce);
      }
      const grant = refreshTokens.get(p.refresh_token ?? "");
      if (!grant || grant.clientId !== p.client_id || (p.resource && p.resource !== grant.resource)) return fail("invalid_grant");
      if (state.refreshAdmission && (!state.member || !state.graphAvailable)) return fail("invalid_grant");
      refreshTokens.delete(p.refresh_token ?? ""); state.refreshes += 1;
      return issue(grant);
    }
    return new Response(null, { status: 404 });
  };
}
