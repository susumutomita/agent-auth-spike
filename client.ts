import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import type { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import type { OAuthClientMetadata, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { CallbackTransaction } from "./security";
import type { LabConfig } from "./types";

/** In-memory provider; browser navigation is simulated, SDK networking is real HTTP. */
export class LocalProvider implements OAuthClientProvider {
  private saved?: OAuthTokens;
  private verifier = "";
  private transaction: CallbackTransaction;
  authorization?: URL;
  callbackResult?: URL;
  constructor(readonly config: LabConfig) { this.transaction = new CallbackTransaction(config.callback); }
  get redirectUrl() { return this.config.callback; }
  get clientMetadata(): OAuthClientMetadata {
    return { redirect_uris: [this.config.callback], token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], scope: this.config.scope };
  }
  state() {
    this.transaction = new CallbackTransaction(this.config.callback);
    return this.transaction.state;
  }
  clientInformation() { return { client_id: this.config.clientId, issuer: this.config.issuer }; }
  tokens() { return this.saved; }
  saveTokens(tokens: OAuthTokens) { this.saved = tokens; }
  saveCodeVerifier(verifier: string) { this.verifier = verifier; }
  codeVerifier() { return this.verifier; }
  async redirectToAuthorization(url: URL) {
    if (url.origin !== this.config.issuer || url.pathname !== "/authorize") throw new Error("unapproved issuer");
    this.authorization = url;
    const response = await fetch(url, { redirect: "manual" });
    const location = response.headers.get("location");
    if (response.status !== 302 || !location) throw new Error("synthetic authorization failed");
    this.callbackResult = new URL(location);
  }
  consumeCallback() {
    if (!this.callbackResult) throw new Error("callback missing");
    return this.transaction.consume(this.callbackResult);
  }
}

export async function connectClient(config: LabConfig) {
  const provider = new LocalProvider(config);
  const transport = new StreamableHTTPClientTransport(new URL(config.resource), { authProvider: provider });
  const client = new Client({ name: "official-sdk-local-spike", version: "0.1.0" });
  try { await client.connect(transport); }
  catch (error) {
    if (!(error instanceof UnauthorizedError)) throw error;
    await client.close();
    await transport.finishAuth(provider.consumeCallback());
    await client.connect(new StreamableHTTPClientTransport(new URL(config.resource), { authProvider: provider }));
  }
  return { client, provider };
}
