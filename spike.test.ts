import { afterEach, describe, expect, it } from "bun:test";
import { generateKeyPair, SignJWT } from "jose";
import { refreshAuthorization } from "@modelcontextprotocol/sdk/client/auth.js";
import { connectClient, LocalProvider } from "./client";
import { createLab } from "./lab";
import { CallbackTransaction, challenge, signAccess, verifyIdNonce } from "./security";
import type { SignedOverrides } from "./types";

const active: Awaited<ReturnType<typeof createLab>>[] = [];
async function lab() { const value = await createLab(); active.push(value); return value; }
afterEach(() => { for (const item of active.splice(0)) item.stop(); });
async function requestMcp(env: Awaited<ReturnType<typeof createLab>>, token: string, headers: Record<string, string> = {}) {
  return fetch(env.config.resource, { method: "POST", headers: { Authorization: `Bearer ${token}`,
    "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
      protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "negative-case", version: "0.1" } } }) });
}
async function authorize(env: Awaited<ReturnType<typeof createLab>>, extra: Record<string, string> = {}) {
  const url = new URL(`${env.config.issuer}/authorize`);
  url.search = new URLSearchParams({ response_type: "code", client_id: env.config.clientId,
    redirect_uri: env.config.callback, resource: env.config.resource, scope: env.config.scope,
    state: "synthetic-state", ...extra }).toString();
  return fetch(url, { redirect: "manual" });
}
async function exchange(env: Awaited<ReturnType<typeof createLab>>, code: string, extra: Record<string, string> = {}) {
  return fetch(`${env.config.issuer}/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", client_id: env.config.clientId,
      redirect_uri: env.config.callback, code, resource: env.config.resource, ...extra }) });
}

describe("合成issuerと公式MCP SDKクライアントの場合", () => {
  it("discoveryからS256・code交換・JSON tool呼出しまで接続できるべき", async () => {
    const env = await lab(); const { client, provider } = await connectClient(env.config);
    try {
      const tools = await client.listTools(); expect(tools.tools.map(tool => tool.name)).toEqual(["whoami"]);
      const result = await client.callTool({ name: "whoami", arguments: {} });
      expect(result.content).toEqual([{ type: "text", text: "synthetic-subject: local.read" }]);
      expect(provider.authorization?.searchParams.get("resource")).toBe(env.config.resource);
      expect(provider.authorization?.searchParams.get("code_challenge_method")).toBe("S256");
      expect(env.requests).toContain("GET /.well-known/oauth-protected-resource/mcp");
      expect(env.requests).toContain("GET /.well-known/oauth-authorization-server");
      expect(env.requests.some(path => path.includes("register"))).toBe(false);
      expect(env.state.tokenRequests[0]).toContain("code_verifier");
      expect(env.state.tokenRequests[0]).not.toContain("client_secret");
      expect(env.state.protocol).toBe("2025-11-25");
      expect(env.state.groupChecks).toBeGreaterThanOrEqual(3);
    } finally { await client.close(); }
  });
  it("資格情報なしのMCP要求に401とresource metadataを返すべき", async () => {
    const env = await lab(); const response = await fetch(env.config.resource);
    expect(response.status).toBe(401); expect(response.headers.get("www-authenticate")).toContain("resource_metadata=");
  });
});

describe("Bearer境界の場合", () => {
  const invalid: { label: string; claims: SignedOverrides }[] = [
    { label: "異なるissuer", claims: { iss: "https://other.example.com" } },
    { label: "異なるaudience", claims: { aud: "https://other.example.com/mcp" } },
    { label: "異なるclient", claims: { client_id: "other-client" } },
    { label: "期限切れ", claims: { exp: 1 } },
    { label: "expなし", claims: { exp: undefined } },
    { label: "scopeなし", claims: { scope: "other.read" } },
    { label: "scope部分一致", claims: { scope: "local.read.evil" } },
    { label: "ID token", claims: { token_use: "id" } },
    { label: "未対応subject", claims: { sub: "unknown-subject" } },
  ];
  for (const { label, claims } of invalid) it(`${label}を署名済みでも拒否するべき`, async () => {
    const env = await lab(); const token = await signAccess(env.keys, env.config, claims);
    expect((await requestMcp(env, token)).status).toBe(401); expect(env.state.groupChecks).toBe(0);
  });
  it("別鍵による署名を拒否するべき", async () => {
    const env = await lab(); const other = await generateKeyPair("RS256");
    expect((await requestMcp(env, await signAccess(other, env.config))).status).toBe(401);
  });
  it("許可済みBearerは再使用でき端末bindingを証明しないべき", async () => {
    const env = await lab(); const token = await env.sign();
    expect((await requestMcp(env, token)).status).toBe(200);
    expect((await requestMcp(env, token)).status).toBe(200);
  });
  it("group剥奪後は同じ有効tokenと詐称identity headerでも拒否するべき", async () => {
    const env = await lab(); const token = await env.sign(); expect((await requestMcp(env, token)).status).toBe(200);
    env.state.member = false;
    expect((await requestMcp(env, token, { "X-Groups": "allow", "X-User-Id": "administrator" })).status).toBe(403);
  });
  it("group照会障害ではfail closedにするべき", async () => {
    const env = await lab(); env.state.graphAvailable = false;
    expect((await requestMcp(env, await env.sign())).status).toBe(503);
  });
  it("不正Origin・Host・ローカル迂回routeを拒否するべき", async () => {
    const env = await lab(); const token = await env.sign();
    expect((await requestMcp(env, token, { Origin: "https://evil.example.com" })).status).toBe(403);
    expect((await requestMcp(env, token, { Host: "evil.example.com" })).status).toBe(403);
    expect((await fetch(`${env.config.issuer}/origin/mcp`, { headers: { Authorization: `Bearer ${token}` } })).status).toBe(403);
  });
});

describe("PKCEとcallback境界の場合", () => {
  it("同じproviderでも再認証時にstateを更新し新しいcallbackを受け入れるべき", async () => {
    const env = await lab(); const provider = new LocalProvider(env.config);
    const first = provider.state();
    provider.callbackResult = new URL(`${env.config.callback}?code=first&state=${first}`);
    expect(provider.consumeCallback()).toBe("first");
    const next = provider.state(); expect(next).not.toBe(first);
    provider.callbackResult = new URL(`${env.config.callback}?code=next&state=${first}`);
    expect(() => provider.consumeCallback()).toThrow();
    provider.callbackResult = new URL(`${env.config.callback}?code=next&state=${next}`);
    expect(provider.consumeCallback()).toBe("next");
  });
  it("strict ASはPKCE省略を拒否し任意ASは同じ入力を許すべき", async () => {
    const env = await lab(); expect((await authorize(env)).status).toBe(400);
    env.state.enforcePkce = false; const response = await authorize(env); expect(response.status).toBe(302);
    const code = new URL(response.headers.get("location") ?? "").searchParams.get("code") ?? "";
    expect((await exchange(env, code)).status).toBe(200);
  });
  it("plain challengeと未承認callback・resourceを拒否するべき", async () => {
    const env = await lab();
    expect((await authorize(env, { code_challenge: "x", code_challenge_method: "plain" })).status).toBe(400);
    expect((await authorize(env, { redirect_uri: "http://evil.example.com/callback" })).status).toBe(400);
    expect((await authorize(env, { resource: "https://other.example.com/mcp" })).status).toBe(400);
  });
  it("verifier省略・不一致・code再利用を拒否するべき", async () => {
    const env = await lab(); const verifier = "v".repeat(43);
    const response = await authorize(env, { code_challenge: await challenge(verifier), code_challenge_method: "S256" });
    const code = new URL(response.headers.get("location") ?? "").searchParams.get("code") ?? "";
    expect((await exchange(env, code)).status).toBe(400);
    expect((await exchange(env, code, { code_verifier: "wrong" })).status).toBe(400);
    expect((await exchange(env, code, { code_verifier: verifier })).status).toBe(200);
    expect((await exchange(env, code, { code_verifier: verifier })).status).toBe(400);
  });
  it("callbackのstate不一致・欠落・期限切れ・再利用を拒否するべき", () => {
    const uri = "http://localhost:63123/callback"; const transaction = new CallbackTransaction(uri);
    expect(() => transaction.consume(new URL(`${uri}?code=x&state=wrong`))).toThrow();
    expect(() => transaction.consume(new URL(`${uri}?code=x`))).toThrow();
    expect(() => transaction.consume(new URL(`http://evil.example.com/callback?code=x&state=${transaction.state}`))).toThrow();
    const expired = new CallbackTransaction(uri, 0);
    expect(() => expired.consume(new URL(`${uri}?code=x&state=${expired.state}`))).toThrow();
    const valid = new URL(`${uri}?code=x&state=${transaction.state}`);
    expect(transaction.consume(valid)).toBe("x"); expect(() => transaction.consume(valid)).toThrow();
  });
  it("OIDC利用時の署名済みID tokenはnonce不一致を拒否しBearerにはしないべき", async () => {
    const env = await lab(); const nonce = crypto.randomUUID();
    const token = await new SignJWT({ nonce, token_use: "id" }).setProtectedHeader({ alg: "RS256" })
      .setIssuer(env.config.issuer).setAudience(env.config.clientId).setExpirationTime("60s").sign(env.keys.privateKey);
    await verifyIdNonce(token, nonce, env.keys, env.config);
    await expect(verifyIdNonce(token, "wrong", env.keys, env.config)).rejects.toThrow();
    expect((await requestMcp(env, token)).status).toBe(401);
  });
});

describe("SDK refreshとlive認可を分けた場合", () => {
  it("rotation後の旧refreshを拒否しgroup剥奪のadmissionを拒否するべき", async () => {
    const env = await lab(); const { client, provider } = await connectClient(env.config);
    try {
      const old = provider.tokens()?.refresh_token ?? "";
      const refresh = () => refreshAuthorization(env.config.issuer, {
        clientInformation: provider.clientInformation(), refreshToken: old, resource: new URL(env.config.resource) });
      const next = await refresh(); expect(next.refresh_token).not.toBe(old); expect(env.state.refreshes).toBe(1);
      await expect(refresh()).rejects.toThrow();
      env.state.member = false;
      await expect(refreshAuthorization(env.config.issuer, { clientInformation: provider.clientInformation(),
        refreshToken: next.refresh_token ?? "", resource: new URL(env.config.resource) })).rejects.toThrow();
    } finally { await client.close(); }
  });
  it("直接refreshがgroupを見ない場合は発行成功してもMCPで拒否するべき", async () => {
    const env = await lab(); const { client, provider } = await connectClient(env.config);
    try {
      env.state.member = false; env.state.refreshAdmission = false;
      const next = await refreshAuthorization(env.config.issuer, { clientInformation: provider.clientInformation(),
        refreshToken: provider.tokens()?.refresh_token ?? "", resource: new URL(env.config.resource) });
      expect(next.access_token.length).toBeGreaterThan(0);
      expect((await requestMcp(env, next.access_token)).status).toBe(403);
    } finally { await client.close(); }
  });
});
