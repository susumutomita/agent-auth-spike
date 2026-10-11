import { generateKeyPair } from "jose";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { makeIssuer } from "./issuer";
import { signAccess, verifyAccess } from "./security";
import type { LabConfig, LabState } from "./types";

export async function createLab() {
  const keys = await generateKeyPair("RS256");
  const config: LabConfig = { issuer: "", resource: "", scope: "local.read", clientId: "pre-registered-local-client",
    callback: "http://localhost:63123/callback" };
  const state: LabState = { member: true, graphAvailable: true, enforcePkce: true, refreshAdmission: true,
    groupChecks: 0, refreshes: 0, tokenRequests: [] };
  const issuer = makeIssuer(config, state, keys);
  const requests: string[] = [];
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const url = new URL(request.url); requests.push(`${request.method} ${url.pathname}`);
    // Host is an exact binding. Native clients may omit Origin; browser cross-origin is denied.
    if (request.headers.get("host") !== new URL(config.issuer).host) return new Response(null, { status: 403 });
    const origin = request.headers.get("origin");
    if (origin && origin !== config.issuer) return new Response(null, { status: 403 });
    if (url.pathname === "/origin/mcp") return new Response(null, { status: 403 }); // local route only; NOT proof of AWS IAM
    if (url.pathname === "/.well-known/oauth-protected-resource/mcp") return Response.json({
      resource: config.resource, authorization_servers: [config.issuer], scopes_supported: [config.scope],
      bearer_methods_supported: ["header"],
    });
    if (url.pathname !== "/mcp") return issuer(request);
    const challenge = `Bearer resource_metadata="${config.issuer}/.well-known/oauth-protected-resource/mcp", scope="${config.scope}"`;
    const bearer = request.headers.get("authorization")?.match(/^Bearer (\S+)$/)?.[1];
    if (!bearer) return new Response(null, { status: 401, headers: { "WWW-Authenticate": challenge } });
    try { await verifyAccess(bearer, keys, config); }
    catch { return new Response(null, { status: 401, headers: { "WWW-Authenticate": `${challenge}, error="invalid_token"` } }); }
    state.groupChecks += 1;
    if (!state.graphAvailable) return new Response(null, { status: 503 });
    if (!state.member) return new Response(null, { status: 403 });
    if (request.method !== "POST") return new Response(null, { status: 405 }); // no standalone SSE
    state.protocol = request.headers.get("mcp-protocol-version") ?? state.protocol;
    const mcp = new McpServer({ name: "synthetic-protected-resource", version: "0.1.0" });
    mcp.registerTool("whoami", { description: "Non-sensitive synthetic identity only", inputSchema: {} }, async () => ({
      content: [{ type: "text", text: "synthetic-subject: local.read" }],
    }));
    const transport = new WebStandardStreamableHTTPServerTransport({ enableJsonResponse: true, maxRequestBodySize: 8192 });
    await mcp.connect(transport);
    const response = await transport.handleRequest(request);
    await mcp.close();
    return response;
  } });
  config.issuer = `http://localhost:${server.port}`; config.resource = `${config.issuer}/mcp`;
  return { config, state, keys, requests, sign: () => signAccess(keys, config), stop: () => server.stop(true) };
}
