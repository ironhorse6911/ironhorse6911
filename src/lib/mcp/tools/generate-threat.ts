import { defineTool } from "@lovable.dev/mcp-js";
import { z } from "zod";

const TYPES = ["SSH BRUTE", "ZERO-DAY PROBE", "SQL INJECTION", "DDOS L7", "CREDENTIAL STUFF", "MALWARE C2"];
const SEVERITIES = ["LOW", "MED", "HIGH", "CRIT"] as const;

export default defineTool({
  name: "generate_threat_briefing",
  title: "Generate threat briefing",
  description:
    "Produce a simulated threat briefing with a random attacker signature, severity, and recommended containment runbook. Read-only demo data.",
  inputSchema: {
    count: z
      .number()
      .int()
      .min(1)
      .max(10)
      .default(3)
      .describe("How many simulated threats to include in the briefing (1-10)."),
  },
  annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: false },
  handler: ({ count }) => {
    const threats = Array.from({ length: count }, (_, i) => {
      const type = TYPES[Math.floor(Math.random() * TYPES.length)];
      const sev = SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)];
      return {
        id: `T-${Date.now().toString(36)}-${i}`,
        type,
        severity: sev,
        src: `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        recommended:
          sev === "CRIT" || sev === "HIGH"
            ? ["BLOCK_IP", "QUARANTINE", "RAISE_ALERT"]
            : ["BLOCK_IP"],
      };
    });
    return {
      content: [{ type: "text", text: JSON.stringify(threats, null, 2) }],
      structuredContent: { threats },
    };
  },
});
