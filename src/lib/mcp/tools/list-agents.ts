import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";

const AGENTS = [
  { id: "SENTRY", role: "Perimeter detection & anomaly triage" },
  { id: "HUNTER", role: "Threat hunting across telemetry" },
  { id: "WARDEN", role: "Policy enforcement & access control" },
  { id: "REFLEX", role: "Autonomous mitigation & containment" },
  { id: "MEDIC", role: "Self-healing & service restoration" },
];

export default defineTool({
  name: "list_agents",
  title: "List fortress agents",
  description: "List the autonomous agents coordinated by the SENTINEL/9 orchestrator and their roles.",
  inputSchema: {},
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  handler: () => ({
    content: [{ type: "text", text: JSON.stringify(AGENTS, null, 2) }],
    structuredContent: { agents: AGENTS },
  }),
});
