import { defineMcp } from "@lovable.dev/mcp-js";
import fortressStatus from "./tools/fortress-status";
import listAgents from "./tools/list-agents";
import generateThreat from "./tools/generate-threat";

export default defineMcp({
  name: "sentinel9-mcp",
  title: "SENTINEL/9 Fortress MCP",
  version: "0.1.0",
  instructions:
    "Tools for the SENTINEL/9 cyberpunk fortress demo. Use `fortress_status` for a live posture snapshot, `list_agents` to enumerate coordinated defense agents, and `generate_threat_briefing` to produce a simulated threat feed with recommended mitigations. All data is simulated/demo content — no real security telemetry.",
  tools: [fortressStatus, listAgents, generateThreat],
});
