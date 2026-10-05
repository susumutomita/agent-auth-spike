import { connectClient } from "./client";
import { createLab } from "./lab";

const lab = await createLab();
try {
  const { client, provider } = await connectClient(lab.config);
  try {
    const tools = await client.listTools();
    const result = await client.callTool({ name: "whoami", arguments: {} });
    const summary = {
      environment: "loopback-synthetic-issuer-only", sdk: "@modelcontextprotocol/sdk@1.32.1",
      protocol: lab.state.protocol, transport: "Streamable HTTP / JSON", tools: tools.tools.map(tool => tool.name),
      toolResult: result.content, authorizationParameterNames: [...(provider.authorization?.searchParams.keys() ?? [])].sort(),
      tokenParameterNames: lab.state.tokenRequests, routes: lab.requests,
      liveGroupChecks: lab.state.groupChecks, realCognitoEntraIntuneVerified: false,
      browserInteraction: "simulated navigation, callback validation by client provider", credentialsWritten: false,
    };
    await Bun.write("artifacts/smoke.json", `${JSON.stringify(summary, null, 2)}\n`);
    console.log(JSON.stringify(summary, null, 2));
  } finally { await client.close(); }
} finally { lab.stop(); }
