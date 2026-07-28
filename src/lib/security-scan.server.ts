export type GeneratedFinding = {
  code: string;
  title: string;
  description: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "open" | "fixed" | "ignored";
};

const CATALOG: Omit<GeneratedFinding, "status">[] = [
  {
    code: "MCP_AUTH",
    title: "MCP endpoint authentication",
    description: "Fortress MCP surface requires OAuth bearer tokens from the managed issuer.",
    category: "perimeter",
    severity: "critical",
  },
  {
    code: "RLS_COVERAGE",
    title: "Row level security coverage",
    description: "All operator tables enforce row level security with admin-scoped policies.",
    category: "data",
    severity: "high",
  },
  {
    code: "ROLE_ESCALATION",
    title: "Role escalation surface",
    description: "Roles are stored in a dedicated table and checked through a security-definer helper.",
    category: "identity",
    severity: "high",
  },
  {
    code: "AGENT_DRIFT",
    title: "Autonomous operator drift",
    description: "Operator heartbeats deviated from the baseline containment envelope.",
    category: "agents",
    severity: "medium",
  },
  {
    code: "CRED_ROTATION",
    title: "Credential rotation window",
    description: "Fortress service credentials are approaching the rotation threshold.",
    category: "secrets",
    severity: "medium",
  },
  {
    code: "TELEMETRY_GAP",
    title: "Telemetry ingestion gap",
    description: "Short gap detected in threat-stream telemetry ingestion.",
    category: "observability",
    severity: "low",
  },
  {
    code: "SHIELD_TUNING",
    title: "Shield tuning advisory",
    description: "WAF rule set could be tightened for L7 flood signatures.",
    category: "perimeter",
    severity: "low",
  },
];

const SEVERITY_WEIGHT = { critical: 28, high: 16, medium: 7, low: 2 } as const;

export function generateFindings(): GeneratedFinding[] {
  return CATALOG.map((entry) => {
    const roll = Math.random();
    // High-severity controls are hardened in this build and usually pass.
    const openChance = entry.severity === "critical" ? 0.08 : entry.severity === "high" ? 0.15 : 0.45;
    const status: GeneratedFinding["status"] = roll < openChance ? "open" : roll < openChance + 0.06 ? "ignored" : "fixed";
    return { ...entry, status };
  });
}

export function summarize(findings: GeneratedFinding[]) {
  const open = findings.filter((f) => f.status === "open");
  const counts = {
    critical_count: open.filter((f) => f.severity === "critical").length,
    high_count: open.filter((f) => f.severity === "high").length,
    medium_count: open.filter((f) => f.severity === "medium").length,
    low_count: open.filter((f) => f.severity === "low").length,
  };
  const penalty = open.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  const posture_score = Math.max(0, Math.round((100 - penalty) * 100) / 100);
  return { ...counts, posture_score };
}
