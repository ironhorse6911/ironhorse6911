import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

export const Route = createFileRoute("/")({
  component: FortressPage,
});

/* ---------------- live threat stream types ---------------- */

type Severity = "LOW" | "MED" | "HIGH" | "CRIT";
type ThreatStatus = "ACTIVE" | "BLOCKED" | "QUARANTINED" | "ESCALATED";
type ActionKind = "BLOCK_IP" | "QUARANTINE" | "RAISE_ALERT";

type Threat = {
  id: string;
  ts: number;
  src: string;
  target: string;
  type: string;
  severity: Severity;
  status: ThreatStatus;
};

type AuditEntry = {
  id: string;
  ts: number;
  actor: string;
  action: ActionKind;
  threatId: string;
  target: string;
  detail: string;
};

const ATTACK_TYPES = [
  "SSH BRUTE",
  "ZERO-DAY PROBE",
  "SQL INJECTION",
  "DDOS L7",
  "CREDENTIAL STUFF",
  "PRIV ESC",
  "LATERAL MOVE",
  "EXFIL BEACON",
  "TOR RECON",
  "MALWARE C2",
  "KERNEL EXPLOIT",
];
const SOURCE_POOLS = [
  "185.220.101.44",
  "45.9.148.117",
  "104.28.7.19",
  "23.129.64.212",
  "tor-exit-9a2c",
  "cn-node-4471",
  "ru-vpn-8823",
  "internal://k8s-42",
  "insider://svc-72",
  "api.prod.us-east",
];
const TARGET_POOLS = [
  "edge-gw-01",
  "auth-svc",
  "billing-db",
  "k8s://prod",
  "vault-us-east",
  "cdn-origin",
  "backup-store",
  "svc-billing",
];
const SEVERITIES: Severity[] = ["LOW", "MED", "HIGH", "CRIT"];

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}
function weightedSeverity(): Severity {
  const r = Math.random();
  if (r < 0.4) return "LOW";
  if (r < 0.7) return "MED";
  if (r < 0.92) return "HIGH";
  return "CRIT";
}
function nid() {
  return Math.random().toString(36).slice(2, 9).toUpperCase();
}
function fmtClock(ts: number) {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

const capabilities = [
  {
    code: "01",
    name: "Perimeter Grid",
    desc: "Adaptive WAF + eBPF kernel filters that rewrite themselves per attacker fingerprint.",
    stat: "18.4M packets/s",
  },
  {
    code: "02",
    name: "Autonomous Hunter",
    desc: "LLM-driven agent pivots across logs, traces, and memory to surface intent before impact.",
    stat: "sub-40ms MTTD",
  },
  {
    code: "03",
    name: "Deception Mesh",
    desc: "Dynamic honeytokens and phantom services fingerprint intrusions in real time.",
    stat: "12k decoys live",
  },
  {
    code: "04",
    name: "Zero-Trust Vault",
    desc: "Hardware-attested identity for every workload, rotated on suspicion, not schedule.",
    stat: "0 standing keys",
  },
  {
    code: "05",
    name: "Response Reflex",
    desc: "Contain, isolate, rollback — the agent executes runbooks without human latency.",
    stat: "1.2s avg quench",
  },
  {
    code: "06",
    name: "Forensic Recall",
    desc: "Full-fidelity replay of every session, memory frame, and syscall for post-mortem.",
    stat: "90-day cold trace",
  },
];

const agentLog = [
  { role: "sys", text: "SENTINEL/9 online. Neural core: NOMINAL. Fortress integrity: 100%." },
  { role: "user", text: "> observe last 5m across edge-cluster-us-east" },
  {
    role: "agent",
    text: "Correlated 4,812 events. 3 anomalies auto-triaged. 1 flagged: unusual egress from svc-billing to 45.9.148.117.",
  },
  { role: "user", text: "> intent?" },
  {
    role: "agent",
    text: "Behavioral match: ExfilKit v3.2 (78%). Session isolated in enclave 0x7f. Awaiting your authorization to rotate service credentials.",
  },
  { role: "user", text: "> authorize. burn the keys." },
  { role: "agent", text: "Keys rotated. Enclave sealed. Threat neutralized in 1.4s. Incident #C-7742 archived." },
];

/* ---------------- autonomous operators ---------------- */

type OperatorId = "SENTRY" | "HUNTER" | "WARDEN" | "REFLEX" | "MEDIC";
type OperatorTone = "cyan" | "magenta" | "neon" | "gold" | "danger";

type OperatorDef = {
  id: OperatorId;
  callsign: string;
  role: string;
  brief: string;
  mandate: string;
  specialty: string[];
  action: ActionKind | "SELF_HEAL";
  tone: OperatorTone;
  glyph: string;
};

const OPERATORS: OperatorDef[] = [
  {
    id: "SENTRY",
    callsign: "SENTRY-01",
    role: "Perimeter warden",
    brief: "eBPF + WAF rewrites at wire speed. Neutralizes noise at the edge.",
    mandate: "Null hostile ingress before it touches an app socket.",
    specialty: ["DDOS L7", "SSH BRUTE", "TOR RECON"],
    action: "BLOCK_IP",
    tone: "cyan",
    glyph: "◈",
  },
  {
    id: "HUNTER",
    callsign: "HUNTER-04",
    role: "Intent tracker",
    brief: "Behavioral graph over logs and traces. Surfaces motive, not signature.",
    mandate: "Correlate weak signals into named adversary intent.",
    specialty: ["CREDENTIAL STUFF", "EXFIL BEACON", "MALWARE C2"],
    action: "RAISE_ALERT",
    tone: "magenta",
    glyph: "◉",
  },
  {
    id: "WARDEN",
    callsign: "WARDEN-07",
    role: "Identity & keys",
    brief: "Hardware-attested identity + rotating enclaves. Sanctifies every workload.",
    mandate: "Revoke, rotate, reseal on the faintest suspicion.",
    specialty: ["PRIV ESC", "LATERAL MOVE", "SQL INJECTION"],
    action: "QUARANTINE",
    tone: "gold",
    glyph: "⬢",
  },
  {
    id: "REFLEX",
    callsign: "REFLEX-02",
    role: "Containment reflex",
    brief: "Deterministic runbooks. Isolates blast radius in milliseconds.",
    mandate: "Sever, seal, snapshot — no human latency.",
    specialty: ["ZERO-DAY PROBE", "KERNEL EXPLOIT"],
    action: "QUARANTINE",
    tone: "danger",
    glyph: "▲",
  },
  {
    id: "MEDIC",
    callsign: "MEDIC-09",
    role: "Self-heal & restore",
    brief: "Regenerates credentials, WAF rules, enclave seals. Keeps the fortress whole.",
    mandate: "Continuous regeneration. Zero standing trust.",
    specialty: [],
    action: "SELF_HEAL",
    tone: "neon",
    glyph: "✚",
  },
];

type OperatorRuntime = {
  armed: boolean;
  status: "IDLE" | "SCANNING" | "ENGAGING" | "RECOVERING";
  actions: number;
  load: number;
  activity: { id: string; ts: number; text: string }[];
};

function initialOperatorState(): Record<OperatorId, OperatorRuntime> {
  const base = (): OperatorRuntime => ({
    armed: true,
    status: "SCANNING",
    actions: 0,
    load: 24 + Math.floor(Math.random() * 20),
    activity: [],
  });
  return {
    SENTRY: base(),
    HUNTER: base(),
    WARDEN: base(),
    REFLEX: base(),
    MEDIC: base(),
  };
}

function seedThreat(now: number): Threat {
  return {
    id: nid(),
    ts: now,
    src: pick(SOURCE_POOLS),
    target: pick(TARGET_POOLS),
    type: pick(ATTACK_TYPES),
    severity: weightedSeverity(),
    status: "ACTIVE",
  };
}

function FortressPage() {
  const [clock, setClock] = useState("00:00:00");
  const [streamLive, setStreamLive] = useState(true);
  const [threats, setThreats] = useState<Threat[]>(() => {
    const now = Date.now();
    return Array.from({ length: 5 }, (_, i) => seedThreat(now - i * 3200));
  });
  const [audit, setAudit] = useState<AuditEntry[]>([
    {
      id: nid(),
      ts: Date.now(),
      actor: "SENTINEL/9",
      action: "RAISE_ALERT",
      threatId: "BOOT-000",
      target: "fortress-core",
      detail: "Neural core online. Command deck armed.",
    },
  ]);

  // Rolling telemetry — synced with mitigation actions
  const [packetBars, setPacketBars] = useState<number[]>([62, 78, 55, 92, 71, 84, 66, 95, 73, 88, 79, 91]);
  const [containBars, setContainBars] = useState<number[]>([22, 34, 41, 28, 62, 48, 55, 73, 44, 66, 51, 82]);
  const [decepBars, setDecepBars] = useState<number[]>([10, 14, 22, 18, 34, 28, 42, 31, 55, 47, 62, 71]);
  const [containedTotal, setContainedTotal] = useState(1204);
  const [decepTotal, setDecepTotal] = useState(87);
  const [packetRate, setPacketRate] = useState(18.42);

  const streamLiveRef = useRef(streamLive);
  streamLiveRef.current = streamLive;

  useEffect(() => {
    const start = Date.now();
    const clockT = setInterval(() => {
      const s = Math.floor((Date.now() - start) / 1000);
      const hh = String(Math.floor(s / 3600)).padStart(2, "0");
      const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
      const ss = String(s % 60).padStart(2, "0");
      setClock(`${hh}:${mm}:${ss}`);
    }, 1000);

    const teleT = setInterval(() => {
      setPacketBars((b) => [...b.slice(1), 50 + Math.floor(Math.random() * 48)]);
      setContainBars((b) => [
        ...b.slice(1),
        Math.max(10, b[b.length - 1] - 6 + Math.floor(Math.random() * 8)),
      ]);
      setDecepBars((b) => [
        ...b.slice(1),
        Math.max(6, b[b.length - 1] - 4 + Math.floor(Math.random() * 6)),
      ]);
      setPacketRate(16 + Math.random() * 6);
    }, 1500);

    let feedT: ReturnType<typeof setTimeout>;
    const schedule = () => {
      const delay = 1600 + Math.random() * 2600;
      feedT = setTimeout(() => {
        if (streamLiveRef.current) {
          setThreats((prev) => [seedThreat(Date.now()), ...prev].slice(0, 10));
        }
        schedule();
      }, delay);
    };
    schedule();

    return () => {
      clearInterval(clockT);
      clearInterval(teleT);
      clearTimeout(feedT);
    };
  }, []);

  const bumpTelemetry = useCallback((action: ActionKind) => {
    if (action === "BLOCK_IP" || action === "QUARANTINE") {
      setContainBars((b) => [
        ...b.slice(1),
        Math.min(100, b[b.length - 1] + 18 + Math.floor(Math.random() * 12)),
      ]);
      setContainedTotal((n) => n + 1);
    }
    if (action === "RAISE_ALERT") {
      setDecepBars((b) => [
        ...b.slice(1),
        Math.min(100, b[b.length - 1] + 22 + Math.floor(Math.random() * 10)),
      ]);
      setDecepTotal((n) => n + 1);
    }
    if (action === "QUARANTINE") {
      setPacketBars((b) => [...b.slice(1), Math.min(100, 88 + Math.floor(Math.random() * 10))]);
    }
  }, []);

  const runAction = useCallback(
    (threat: Threat, action: ActionKind, actor: "AGENT" | "OPERATOR") => {
      const nextStatus: ThreatStatus =
        action === "BLOCK_IP"
          ? "BLOCKED"
          : action === "QUARANTINE"
            ? "QUARANTINED"
            : "ESCALATED";
      const detail =
        action === "BLOCK_IP"
          ? `Egress + ingress from ${threat.src} nulled at edge.`
          : action === "QUARANTINE"
              ? `Host ${threat.target} sealed in enclave. Credentials rotated.`
              : `Alert routed to on-call. Incident #${threat.id} opened.`;
      setThreats((prev) =>
        prev.map((t) => (t.id === threat.id ? { ...t, status: nextStatus } : t)),
      );
      setAudit((prev) =>
        [
          {
            id: nid(),
            ts: Date.now(),
            actor: actor === "AGENT" ? "SENTINEL/9" : "OPERATOR",
            action,
            threatId: threat.id,
            target: action === "BLOCK_IP" ? threat.src : threat.target,
            detail,
          },
          ...prev,
        ].slice(0, 40),
      );
      bumpTelemetry(action);
    },
    [bumpTelemetry],
  );

  const autoContainAll = useCallback(() => {
    setThreats((prev) => {
      const now = Date.now();
      const newAudits: AuditEntry[] = [];
      let contained = 0;
      let alerted = 0;
      const next = prev.map((t) => {
        if (t.status !== "ACTIVE") return t;
        const action: ActionKind =
          t.severity === "CRIT" ? "QUARANTINE" : t.severity === "HIGH" ? "BLOCK_IP" : "RAISE_ALERT";
        const nextStatus: ThreatStatus =
          action === "BLOCK_IP" ? "BLOCKED" : action === "QUARANTINE" ? "QUARANTINED" : "ESCALATED";
        if (action === "RAISE_ALERT") alerted++;
        else contained++;
        newAudits.push({
          id: nid(),
          ts: now,
          actor: "SENTINEL/9",
          action,
          threatId: t.id,
          target: action === "BLOCK_IP" ? t.src : t.target,
          detail: `Auto-runbook executed on ${t.severity} threat ${t.type}.`,
        });
        return { ...t, status: nextStatus };
      });
      if (newAudits.length) setAudit((a) => [...newAudits, ...a].slice(0, 40));
      if (contained) {
        setContainedTotal((n) => n + contained);
        setContainBars((b) => [
          ...b.slice(1),
          Math.min(100, 78 + Math.floor(Math.random() * 20)),
        ]);
      }
      if (alerted) {
        setDecepTotal((n) => n + alerted);
        setDecepBars((b) => [
          ...b.slice(1),
          Math.min(100, 72 + Math.floor(Math.random() * 20)),
        ]);
      }
      return next;
    });
  }, []);

  const selfHeal = useCallback(() => {
    setPacketBars((b) => [...b.slice(1), 92 + Math.floor(Math.random() * 8)]);
    setContainBars((b) => [...b.slice(1), Math.min(100, b[b.length - 1] + 10)]);
    setAudit((prev) =>
      [
        {
          id: nid(),
          ts: Date.now(),
          actor: "SENTINEL/9",
          action: "RAISE_ALERT" as ActionKind,
          threatId: "HEAL-" + nid().slice(0, 4),
          target: "fortress-core",
          detail: "MEDIC: standing credentials rotated, WAF rules regenerated, enclaves resealed.",
        },
        ...prev,
      ].slice(0, 40),
    );
  }, []);

  /* ---- autonomous operators ---- */

  const [operators, setOperators] = useState<Record<OperatorId, OperatorRuntime>>(() =>
    initialOperatorState(),
  );
  const operatorsRef = useRef(operators);
  operatorsRef.current = operators;
  const threatsRef = useRef(threats);
  threatsRef.current = threats;

  const toggleOperator = useCallback((id: OperatorId) => {
    setOperators((prev) => ({
      ...prev,
      [id]: {
        ...prev[id],
        armed: !prev[id].armed,
        status: !prev[id].armed ? "SCANNING" : "IDLE",
      },
    }));
  }, []);

  const pushOperatorActivity = useCallback((id: OperatorId, text: string) => {
    setOperators((prev) => ({
      ...prev,
      [id]: {
        ...prev[id],
        activity: [{ id: nid(), ts: Date.now(), text }, ...prev[id].activity].slice(0, 6),
      },
    }));
  }, []);

  // Autonomous operator heartbeats — each operator scans and acts on its specialty.
  useEffect(() => {
    const runOnce = (op: OperatorDef) => {
      const state = operatorsRef.current[op.id];
      if (!state.armed) return;

      // Load telemetry drift
      setOperators((prev) => ({
        ...prev,
        [op.id]: {
          ...prev[op.id],
          load: Math.max(
            18,
            Math.min(96, prev[op.id].load + Math.floor(Math.random() * 14) - 6),
          ),
          status: "SCANNING",
        },
      }));

      if (op.action === "SELF_HEAL") {
        if (Math.random() < 0.22) {
          selfHeal();
          setOperators((prev) => ({
            ...prev,
            [op.id]: {
              ...prev[op.id],
              status: "RECOVERING",
              actions: prev[op.id].actions + 1,
              activity: [
                {
                  id: nid(),
                  ts: Date.now(),
                  text: "Regen cycle: rotated keys, resealed enclaves, patched WAF.",
                },
                ...prev[op.id].activity,
              ].slice(0, 6),
            },
          }));
        }
        return;
      }

      const target = threatsRef.current.find(
        (t) => t.status === "ACTIVE" && op.specialty.includes(t.type),
      );
      if (!target) return;

      setOperators((prev) => ({
        ...prev,
        [op.id]: {
          ...prev[op.id],
          status: "ENGAGING",
          actions: prev[op.id].actions + 1,
          activity: [
            {
              id: nid(),
              ts: Date.now(),
              text: `${op.action.replace("_", " ")} on ${target.type} · ${target.src} → ${target.target}`,
            },
            ...prev[op.id].activity,
          ].slice(0, 6),
        },
      }));
      runAction(target, op.action as ActionKind, "AGENT");
    };

    const timers = OPERATORS.map((op) =>
      setInterval(() => runOnce(op), 2200 + Math.random() * 1800),
    );
    return () => timers.forEach(clearInterval);
  }, [runAction, selfHeal]);

  const activeCount = useMemo(() => threats.filter((t) => t.status === "ACTIVE").length, [threats]);


  return (
    <div className="relative min-h-screen overflow-hidden">
      {/* Ambient glow blobs */}
      <div className="pointer-events-none absolute -top-40 -left-40 h-[520px] w-[520px] rounded-full bg-primary/20 blur-[140px]" />
      <div className="pointer-events-none absolute top-1/3 -right-40 h-[520px] w-[520px] rounded-full bg-accent/20 blur-[140px]" />
      <div className="pointer-events-none fixed inset-0 scanlines opacity-40 mix-blend-overlay" />

      {/* NAV */}
      <header className="relative z-20 border-b border-border/60 backdrop-blur-md bg-background/40">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <a href="#top" className="flex items-center gap-3">
            <FortressMark />
            <div className="leading-tight">
              <div className="font-display text-sm font-bold tracking-[0.3em] text-primary text-glow-cyan">
                SENTINEL/9
              </div>
              <div className="text-[10px] uppercase tracking-[0.4em] text-muted-foreground">
                autonomous cyber fortress
              </div>
            </div>
          </a>
          <nav className="hidden gap-8 text-xs uppercase tracking-[0.25em] text-muted-foreground md:flex">
            <a className="hover:text-primary transition-colors" href="#agent">Agent</a>
            <a className="hover:text-primary transition-colors" href="#operators">Operators</a>
            <a className="hover:text-primary transition-colors" href="#grid">Grid</a>
            <a className="hover:text-primary transition-colors" href="#telemetry">Telemetry</a>
            <a className="hover:text-primary transition-colors" href="#deploy">Deploy</a>
          </nav>

          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-2 rounded-full border border-neon/40 bg-neon/10 px-3 py-1 text-[10px] uppercase tracking-[0.3em] text-neon sm:inline-flex">
              <span className="h-1.5 w-1.5 animate-flicker rounded-full bg-neon shadow-neon-green" />
              online
            </span>
            <a
              href="#deploy"
              className="clip-notch bg-primary px-4 py-2 text-xs font-bold uppercase tracking-[0.2em] text-primary-foreground shadow-neon-cyan transition-transform hover:-translate-y-0.5"
            >
              Breach test
            </a>
          </div>
        </div>
      </header>

      {/* HERO */}
      <section id="top" className="relative z-10 mx-auto max-w-7xl px-6 pt-16 pb-24">
        <div className="grid gap-12 lg:grid-cols-[1.15fr_1fr] lg:items-center">
          <div>
            <div className="mb-6 inline-flex items-center gap-3 rounded-full border border-primary/40 bg-primary/5 px-3 py-1 text-[10px] uppercase tracking-[0.4em] text-primary">
              <span className="h-1.5 w-1.5 rounded-full bg-primary animate-flicker" />
              Fortress protocol v9.3 // live
            </div>
            <h1 className="font-display text-5xl font-black uppercase leading-[0.95] tracking-tight sm:text-6xl lg:text-7xl">
              <span className="block text-foreground">Your perimeter</span>
              <span className="block text-primary text-glow-cyan">isn't a wall.</span>
              <span className="block text-accent text-glow-magenta">It's an agent.</span>
            </h1>
            <p className="mt-6 max-w-xl text-sm leading-relaxed text-muted-foreground sm:text-base">
              SENTINEL/9 is an autonomous AI operator that lives inside your infrastructure —
              watching every packet, every syscall, every whispered credential. It hunts intent,
              not signatures. It responds in milliseconds, not meetings.
            </p>

            <div className="mt-8 flex flex-wrap items-center gap-4">
              <a
                href="#deploy"
                className="clip-notch group relative overflow-hidden bg-primary px-6 py-3 text-sm font-bold uppercase tracking-[0.25em] text-primary-foreground shadow-neon-cyan"
              >
                Deploy the agent →
              </a>
              <a
                href="#agent"
                className="clip-notch border border-accent/60 bg-accent/10 px-6 py-3 text-sm font-bold uppercase tracking-[0.25em] text-accent"
              >
                Observe live
              </a>
            </div>

            <dl className="mt-12 grid grid-cols-3 gap-4 border-t border-border/60 pt-6">
              {[
                { k: "Threats/day", v: "4.2M", tone: "text-primary" },
                { k: "MTTR", v: "1.4s", tone: "text-neon" },
                { k: "False+", v: "0.03%", tone: "text-accent" },
              ].map((s) => (
                <div key={s.k}>
                  <dt className="text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
                    {s.k}
                  </dt>
                  <dd className={`mt-1 font-display text-2xl font-bold ${s.tone}`}>{s.v}</dd>
                </div>
              ))}
            </dl>
          </div>

          {/* Fortress core visual */}
          <div className="relative aspect-square w-full max-w-xl justify-self-center">
            <FortressCore />
          </div>
        </div>

        {/* COMMAND DECK — live threat stream + audit trail */}
        <div id="command" className="mt-16 grid gap-6 lg:grid-cols-[1.35fr_1fr]">
          {/* Live stream */}
          <div className="clip-notch border border-border/60 bg-card/40 backdrop-blur-xl">
            <div className="flex flex-wrap items-center gap-3 border-b border-border/60 px-4 py-3 text-[10px] uppercase tracking-[0.3em]">
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  streamLive ? "bg-neon shadow-neon-green animate-flicker" : "bg-muted-foreground"
                }`}
              />
              <span className="text-muted-foreground">live threat stream</span>
              <span className="text-primary">· {activeCount} active</span>
              <span className="ml-auto flex items-center gap-2">
                <span className="font-mono text-primary">UPTIME {clock}</span>
                <button
                  onClick={() => setStreamLive((v) => !v)}
                  className={`clip-notch border px-3 py-1 text-[10px] font-bold tracking-[0.25em] transition-colors ${
                    streamLive
                      ? "border-neon/60 bg-neon/10 text-neon"
                      : "border-danger/60 bg-danger/10 text-danger"
                  }`}
                >
                  {streamLive ? "◉ streaming" : "◯ paused"}
                </button>
                <button
                  onClick={autoContainAll}
                  disabled={activeCount === 0}
                  className="clip-notch border border-primary/60 bg-primary/10 px-3 py-1 text-[10px] font-bold tracking-[0.25em] text-primary transition-colors hover:bg-primary/20 disabled:opacity-30"
                >
                  agent auto-contain
                </button>
              </span>
            </div>

            <ul className="max-h-[520px] divide-y divide-border/60 overflow-y-auto">
              {threats.map((t) => (
                <ThreatRow key={t.id} threat={t} onAction={runAction} />
              ))}
            </ul>
          </div>

          {/* Audit trail */}
          <div className="clip-notch border border-accent/30 bg-black/50 backdrop-blur-xl">
            <div className="flex items-center justify-between border-b border-border/60 px-4 py-3 text-[10px] uppercase tracking-[0.3em]">
              <span className="text-accent">audit trail // append-only</span>
              <span className="text-muted-foreground">{audit.length} entries</span>
            </div>
            <ol className="max-h-[520px] overflow-y-auto p-4 font-mono text-[11px] leading-relaxed">
              {audit.map((a) => (
                <li key={a.id} className="mb-3 border-l-2 border-accent/40 pl-3">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <span className="text-primary">{fmtClock(a.ts)}</span>
                    <span>·</span>
                    <span className={a.actor === "OPERATOR" ? "text-accent" : "text-neon"}>
                      {a.actor}
                    </span>
                    <span>·</span>
                    <span className="text-foreground">{a.action}</span>
                  </div>
                  <div className="mt-1 text-foreground/80">
                    <span className="text-muted-foreground">→ {a.target}</span>{" "}
                    <span className="text-muted-foreground/70">
                      [thr:{a.threatId}]
                    </span>
                  </div>
                  <div className="mt-1 text-muted-foreground">{a.detail}</div>
                </li>
              ))}
              {audit.length === 0 && (
                <li className="text-muted-foreground">// no actions recorded</li>
              )}
            </ol>
          </div>
        </div>

      </section>

      {/* AGENT CONSOLE */}
      <section id="agent" className="relative z-10 mx-auto max-w-7xl px-6 py-24">
        <SectionHeader
          num="//02"
          title="The agent thinks. Then it acts."
          sub="SENTINEL/9 reasons across your entire stack — code, cloud, identity, network — and executes containment without waiting for a human ticket."
        />

        <div className="mt-12 grid gap-8 lg:grid-cols-[1fr_1.1fr]">
          {/* Agent brain */}
          <div className="clip-notch relative overflow-hidden border border-primary/30 bg-card/40 p-8 backdrop-blur-xl">
            <div className="absolute inset-0 scanlines opacity-30" />
            <div className="relative">
              <div className="flex items-center justify-between text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
                <span>neural core</span>
                <span className="text-neon">◉ synced</span>
              </div>
              <div className="mt-6 flex items-center justify-center">
                <AgentBrain />
              </div>
              <div className="mt-6 grid grid-cols-2 gap-3 text-xs">
                {[
                  ["Reasoning", "48-step chain"],
                  ["Context", "2.1M tokens live"],
                  ["Tools", "142 bound"],
                  ["Confidence", "94.8%"],
                ].map(([k, v]) => (
                  <div
                    key={k}
                    className="flex items-center justify-between border border-border/60 bg-background/40 px-3 py-2"
                  >
                    <span className="text-muted-foreground">{k}</span>
                    <span className="font-mono text-primary">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Console transcript */}
          <div className="clip-notch relative overflow-hidden border border-accent/30 bg-black/50 backdrop-blur-xl">
            <div className="flex items-center justify-between border-b border-border/60 px-4 py-3 text-[10px] uppercase tracking-[0.3em]">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-danger" />
                <span className="h-2 w-2 rounded-full bg-primary" />
                <span className="h-2 w-2 rounded-full bg-neon" />
                <span className="ml-3 text-muted-foreground">
                  sentinel@fortress:~ // incident C-7742
                </span>
              </div>
              <span className="text-neon">● rec</span>
            </div>
            <div className="max-h-[420px] space-y-3 overflow-hidden p-6 font-mono text-xs leading-relaxed">
              {agentLog.map((line, i) => {
                const cls =
                  line.role === "sys"
                    ? "text-muted-foreground"
                    : line.role === "user"
                      ? "text-primary text-glow-cyan"
                      : "text-neon";
                return (
                  <div key={i} className={cls}>
                    {line.role === "agent" && (
                      <span className="mr-2 text-accent">[SENTINEL/9]</span>
                    )}
                    {line.text}
                  </div>
                );
              })}
              <div className="flex items-center gap-2 text-primary">
                <span>&gt;</span>
                <span className="inline-block h-4 w-2 animate-flicker bg-primary" />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CAPABILITIES GRID */}
      <section id="grid" className="relative z-10 mx-auto max-w-7xl px-6 py-24">
        <SectionHeader
          num="//03"
          title="Six systems. One fortress."
          sub="Each layer is autonomous. Together they form a living perimeter that rewrites itself with every probe."
        />
        <div className="mt-12 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {capabilities.map((c) => (
            <article
              key={c.code}
              className="clip-notch group relative overflow-hidden border border-border/60 bg-card/50 p-6 backdrop-blur-xl transition-all hover:border-primary/60 hover:-translate-y-1"
            >
              <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/60 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
              <div className="flex items-baseline justify-between">
                <span className="font-display text-xs font-bold tracking-[0.3em] text-accent">
                  //{c.code}
                </span>
                <span className="font-mono text-[10px] text-neon">{c.stat}</span>
              </div>
              <h3 className="mt-6 font-display text-xl font-bold uppercase tracking-wide text-foreground">
                {c.name}
              </h3>
              <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{c.desc}</p>
              <div className="mt-6 flex items-center gap-2 text-[10px] uppercase tracking-[0.3em] text-primary opacity-70 group-hover:opacity-100">
                inspect module
                <span className="transition-transform group-hover:translate-x-1">→</span>
              </div>
            </article>
          ))}
        </div>
      </section>

      {/* TELEMETRY */}
      <section id="telemetry" className="relative z-10 mx-auto max-w-7xl px-6 py-24">
        <SectionHeader
          num="//04"
          title="Telemetry from the wire."
          sub="A slice of what the fortress saw in the last sixty seconds."
        />
        <div className="mt-12 grid gap-6 lg:grid-cols-3">
          <TelemetryCard
            title="Packet inspection"
            value={`${packetRate.toFixed(2)}M/s`}
            tone="cyan"
            bars={packetBars}
          />
          <TelemetryCard
            title="Anomalies contained"
            value={containedTotal.toLocaleString()}
            tone="magenta"
            bars={containBars}
          />
          <TelemetryCard
            title="Deception hits"
            value={decepTotal.toString()}
            tone="neon"
            bars={decepBars}
          />
        </div>

        <div className="mt-8 clip-notch border border-border/60 bg-card/40 p-6 backdrop-blur-xl">
          <div className="flex items-center justify-between text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
            <span>global threat map</span>
            <span className="text-primary">{activeCount} active front{activeCount === 1 ? "" : "s"}</span>
          </div>
          <ThreatMap threats={threats} />
        </div>
      </section>

      {/* DEPLOY / CTA */}
      <section id="deploy" className="relative z-10 mx-auto max-w-7xl px-6 py-24">
        <div className="clip-notch relative overflow-hidden border border-primary/40 bg-card/50 p-10 backdrop-blur-xl sm:p-16">
          <div className="pointer-events-none absolute -top-40 -right-32 h-96 w-96 rounded-full bg-primary/30 blur-[120px]" />
          <div className="pointer-events-none absolute -bottom-40 -left-32 h-96 w-96 rounded-full bg-accent/30 blur-[120px]" />
          <div className="relative grid gap-10 lg:grid-cols-[1.2fr_1fr] lg:items-end">
            <div>
              <div className="mb-4 text-[10px] uppercase tracking-[0.4em] text-primary">
                //05 deploy sequence
              </div>
              <h2 className="font-display text-4xl font-black uppercase leading-tight sm:text-5xl">
                Bring your <span className="text-primary text-glow-cyan">infrastructure</span>{" "}
                <span className="text-accent text-glow-magenta">under agent.</span>
              </h2>
              <p className="mt-4 max-w-lg text-sm text-muted-foreground">
                Ninety seconds to install. Sixty seconds to first detection. Zero to human ticket.
                We deploy in shadow-mode first — you approve every containment until you don't
                need to.
              </p>
            </div>
            <form
              onSubmit={(e) => e.preventDefault()}
              className="space-y-4"
            >
              <label className="block">
                <span className="text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
                  operator email
                </span>
                <input
                  type="email"
                  required
                  placeholder="ops@yourdomain.io"
                  className="mt-2 w-full border border-border/60 bg-background/60 px-4 py-3 font-mono text-sm text-foreground outline-none focus:border-primary focus:shadow-neon-cyan"
                />
              </label>
              <label className="block">
                <span className="text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
                  perimeter size
                </span>
                <select className="mt-2 w-full border border-border/60 bg-background/60 px-4 py-3 font-mono text-sm outline-none focus:border-primary">
                  <option>&lt; 500 endpoints</option>
                  <option>500 – 5,000 endpoints</option>
                  <option>5,000 – 50,000 endpoints</option>
                  <option>Enterprise / classified</option>
                </select>
              </label>
              <button
                type="submit"
                className="clip-notch w-full bg-primary py-4 text-sm font-bold uppercase tracking-[0.3em] text-primary-foreground shadow-neon-cyan transition-transform hover:-translate-y-0.5"
              >
                request the agent →
              </button>
              <p className="text-center text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
                SOC2 · ISO27001 · FedRAMP moderate
              </p>
            </form>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="relative z-10 border-t border-border/60 bg-background/60 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-4 px-6 py-8 md:flex-row md:items-center">
          <div className="flex items-center gap-3">
            <FortressMark small />
            <div className="text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
              SENTINEL/9 · fortress protocol · © 2026
            </div>
          </div>
          <div className="flex gap-6 text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
            <a href="#" className="hover:text-primary">Manifesto</a>
            <a href="#" className="hover:text-primary">Trust</a>
            <a href="#" className="hover:text-primary">Status</a>
            <a href="#" className="hover:text-primary">Careers</a>
          </div>
        </div>
      </footer>

      <AgentChat
        threats={threats}
        onAction={runAction}
        onAutoContain={autoContainAll}
        onSelfHeal={selfHeal}
      />
    </div>
  );
}

/* -------------------------- sub components -------------------------- */

function ThreatRow({
  threat,
  onAction,
}: {
  threat: Threat;
  onAction: (t: Threat, a: ActionKind, actor: "AGENT" | "OPERATOR") => void;
}) {
  const sevColor: Record<Severity, string> = {
    LOW: "border-muted-foreground/40 bg-muted-foreground/10 text-muted-foreground",
    MED: "border-primary/50 bg-primary/10 text-primary",
    HIGH: "border-accent/50 bg-accent/10 text-accent",
    CRIT: "border-danger/60 bg-danger/15 text-danger animate-flicker",
  };
  const statusColor: Record<ThreatStatus, string> = {
    ACTIVE: "text-danger",
    BLOCKED: "text-primary",
    QUARANTINED: "text-neon",
    ESCALATED: "text-accent",
  };
  const isActive = threat.status === "ACTIVE";
  return (
    <li className="grid gap-3 p-4 font-mono text-xs sm:grid-cols-[auto_1fr_auto] sm:items-center">
      <div className="flex items-center gap-3">
        <span
          className={`clip-notch border px-2 py-0.5 text-[10px] font-bold tracking-[0.2em] ${sevColor[threat.severity]}`}
        >
          {threat.severity}
        </span>
        <span className="text-muted-foreground">{fmtClock(threat.ts)}</span>
      </div>
      <div className="min-w-0">
        <div className="truncate text-foreground">
          {threat.type} <span className="text-muted-foreground">·</span> {threat.src}{" "}
          <span className="text-muted-foreground">→</span> {threat.target}
        </div>
        <div className="mt-0.5 flex items-center gap-2 text-[10px] uppercase tracking-[0.25em]">
          <span className="text-muted-foreground">status</span>
          <span className={`font-bold ${statusColor[threat.status]}`}>{threat.status}</span>
          <span className="text-muted-foreground">· id {threat.id}</span>
        </div>
      </div>
      <div className="flex flex-wrap gap-1.5 sm:justify-end">
        <button
          disabled={!isActive}
          onClick={() => onAction(threat, "BLOCK_IP", "OPERATOR")}
          className="clip-notch border border-primary/60 bg-primary/10 px-2.5 py-1 text-[10px] font-bold tracking-[0.2em] text-primary transition-colors hover:bg-primary/25 disabled:opacity-30"
        >
          block ip
        </button>
        <button
          disabled={!isActive}
          onClick={() => onAction(threat, "QUARANTINE", "OPERATOR")}
          className="clip-notch border border-neon/60 bg-neon/10 px-2.5 py-1 text-[10px] font-bold tracking-[0.2em] text-neon transition-colors hover:bg-neon/25 disabled:opacity-30"
        >
          quarantine
        </button>
        <button
          disabled={!isActive}
          onClick={() => onAction(threat, "RAISE_ALERT", "OPERATOR")}
          className="clip-notch border border-accent/60 bg-accent/10 px-2.5 py-1 text-[10px] font-bold tracking-[0.2em] text-accent transition-colors hover:bg-accent/25 disabled:opacity-30"
        >
          raise alert
        </button>
      </div>
    </li>
  );
}

function SectionHeader({ num, title, sub }: { num: string; title: string; sub: string }) {
  return (
    <div className="max-w-3xl">
      <div className="mb-3 font-mono text-[11px] uppercase tracking-[0.4em] text-primary">
        {num}
      </div>
      <h2 className="font-display text-3xl font-black uppercase leading-tight sm:text-4xl">
        {title}
      </h2>
      <p className="mt-4 text-sm text-muted-foreground sm:text-base">{sub}</p>
    </div>
  );
}

function FortressMark({ small = false }: { small?: boolean }) {
  const size = small ? 24 : 36;
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" aria-hidden>
      <defs>
        <linearGradient id="fm" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="oklch(0.82 0.22 190)" />
          <stop offset="1" stopColor="oklch(0.7 0.28 330)" />
        </linearGradient>
      </defs>
      <path
        d="M20 2 L36 10 V22 C36 30 28 36 20 38 C12 36 4 30 4 22 V10 Z"
        stroke="url(#fm)"
        strokeWidth="2"
        fill="oklch(0.14 0.03 280 / 0.6)"
      />
      <path
        d="M20 10 L28 14 V22 C28 26 24 30 20 31 C16 30 12 26 12 22 V14 Z"
        stroke="oklch(0.82 0.22 190)"
        strokeWidth="1.2"
        fill="none"
      />
      <circle cx="20" cy="21" r="2.4" fill="oklch(0.88 0.24 145)" />
    </svg>
  );
}

function FortressCore() {
  return (
    <div className="relative h-full w-full">
      {/* Outer rotating rings */}
      <div className="absolute inset-0 animate-spin-slow">
        <RingSVG dashed color="oklch(0.82 0.22 190)" />
      </div>
      <div className="absolute inset-6 animate-spin-reverse">
        <RingSVG dashed color="oklch(0.7 0.28 330)" />
      </div>
      <div className="absolute inset-14 animate-spin-slow">
        <RingSVG color="oklch(0.88 0.24 145 / 0.5)" />
      </div>

      {/* Hex core */}
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="animate-pulse-ring">
          <svg width="220" height="220" viewBox="0 0 220 220" aria-hidden>
            <defs>
              <linearGradient id="core" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" stopColor="oklch(0.82 0.22 190)" />
                <stop offset="1" stopColor="oklch(0.7 0.28 330)" />
              </linearGradient>
              <filter id="glow">
                <feGaussianBlur stdDeviation="6" result="b" />
                <feMerge>
                  <feMergeNode in="b" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            <polygon
              points="110,20 190,65 190,155 110,200 30,155 30,65"
              fill="oklch(0.14 0.03 280 / 0.7)"
              stroke="url(#core)"
              strokeWidth="2"
              filter="url(#glow)"
            />
            <polygon
              points="110,45 165,77 165,143 110,175 55,143 55,77"
              fill="none"
              stroke="oklch(0.82 0.22 190 / 0.6)"
              strokeWidth="1"
            />
            <circle cx="110" cy="110" r="24" fill="oklch(0.88 0.24 145)" filter="url(#glow)" />
            <text
              x="110"
              y="115"
              textAnchor="middle"
              fill="oklch(0.12 0.03 280)"
              fontSize="14"
              fontWeight="900"
              fontFamily="Orbitron, monospace"
            >
              S/9
            </text>
          </svg>
        </div>
      </div>

      {/* Orbiting nodes */}
      {[0, 60, 120, 180, 240, 300].map((deg, i) => (
        <div
          key={deg}
          className="absolute left-1/2 top-1/2 h-2 w-2"
          style={{
            transform: `rotate(${deg}deg) translateY(-46%) rotate(-${deg}deg)`,
          }}
        >
          <div
            className={`h-2 w-2 rounded-full ${
              i % 3 === 0 ? "bg-primary shadow-neon-cyan" : i % 3 === 1 ? "bg-accent shadow-neon-magenta" : "bg-neon"
            } animate-flicker`}
          />
        </div>
      ))}

      {/* Scan line */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-primary to-transparent shadow-neon-cyan animate-scan" />
      </div>
    </div>
  );
}

function RingSVG({ color, dashed = false }: { color: string; dashed?: boolean }) {
  return (
    <svg viewBox="0 0 100 100" className="h-full w-full" aria-hidden>
      <circle
        cx="50"
        cy="50"
        r="48"
        fill="none"
        stroke={color}
        strokeWidth="0.5"
        strokeDasharray={dashed ? "2 3" : undefined}
      />
      <circle cx="50" cy="2" r="1.2" fill={color} />
      <circle cx="98" cy="50" r="0.8" fill={color} />
      <circle cx="50" cy="98" r="1.2" fill={color} />
      <circle cx="2" cy="50" r="0.8" fill={color} />
    </svg>
  );
}

function AgentBrain() {
  return (
    <svg width="240" height="180" viewBox="0 0 240 180" aria-hidden>
      <defs>
        <linearGradient id="brainG" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="oklch(0.82 0.22 190)" />
          <stop offset="1" stopColor="oklch(0.7 0.28 330)" />
        </linearGradient>
      </defs>
      {/* Nodes */}
      {[
        [40, 40], [40, 90], [40, 140],
        [120, 30], [120, 90], [120, 150],
        [200, 60], [200, 120],
      ].map(([x, y], i) => (
        <g key={i}>
          <circle
            cx={x}
            cy={y}
            r="6"
            fill="oklch(0.14 0.03 280)"
            stroke="url(#brainG)"
            strokeWidth="1.5"
          />
          <circle cx={x} cy={y} r="2" fill="oklch(0.88 0.24 145)">
            <animate
              attributeName="opacity"
              values="0.3;1;0.3"
              dur={`${1.5 + (i % 4) * 0.3}s`}
              repeatCount="indefinite"
            />
          </circle>
        </g>
      ))}
      {/* Edges */}
      {[
        [40, 40, 120, 30], [40, 40, 120, 90],
        [40, 90, 120, 90], [40, 90, 120, 30], [40, 90, 120, 150],
        [40, 140, 120, 150], [40, 140, 120, 90],
        [120, 30, 200, 60], [120, 90, 200, 60], [120, 90, 200, 120],
        [120, 150, 200, 120],
      ].map(([x1, y1, x2, y2], i) => (
        <line
          key={i}
          x1={x1}
          y1={y1}
          x2={x2}
          y2={y2}
          stroke="oklch(0.82 0.22 190 / 0.35)"
          strokeWidth="0.8"
        />
      ))}
    </svg>
  );
}

function TelemetryCard({
  title,
  value,
  tone,
  bars,
}: {
  title: string;
  value: string;
  tone: "cyan" | "magenta" | "neon";
  bars: number[];
}) {
  const color =
    tone === "cyan"
      ? "oklch(0.82 0.22 190)"
      : tone === "magenta"
        ? "oklch(0.7 0.28 330)"
        : "oklch(0.88 0.24 145)";
  const valCls =
    tone === "cyan" ? "text-primary text-glow-cyan" : tone === "magenta" ? "text-accent text-glow-magenta" : "text-neon text-glow-green";
  return (
    <div className="clip-notch border border-border/60 bg-card/50 p-6 backdrop-blur-xl">
      <div className="flex items-center justify-between text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
        <span>{title}</span>
        <span>60s</span>
      </div>
      <div className={`mt-3 font-display text-3xl font-black ${valCls}`}>{value}</div>
      <div className="mt-6 flex h-20 items-end gap-1.5">
        {bars.map((b, i) => (
          <div
            key={i}
            className="flex-1 rounded-sm"
            style={{
              height: `${b}%`,
              background: `linear-gradient(to top, ${color}, transparent)`,
              boxShadow: `0 0 8px ${color}`,
            }}
          />
        ))}
      </div>
    </div>
  );
}

function threatPos(t: Threat) {
  let h = 2166136261;
  const s = t.id + t.src;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  h >>>= 0;
  return { x: 6 + (h % 86), y: 14 + ((h >>> 9) % 66) };
}

function ThreatMap({ threats }: { threats: Threat[] }) {
  const toneFor = (t: Threat) =>
    t.status === "ACTIVE"
      ? { color: "oklch(0.7 0.25 20)", label: "active", pulse: true }
      : t.status === "BLOCKED"
        ? { color: "oklch(0.82 0.22 190)", label: "blocked", pulse: false }
        : t.status === "QUARANTINED"
          ? { color: "oklch(0.88 0.24 145)", label: "sealed", pulse: false }
          : { color: "oklch(0.7 0.28 330)", label: "escalated", pulse: false };
  const nodes = threats.map((t) => ({ t, pos: threatPos(t), tone: toneFor(t) }));
  return (
    <div className="relative mt-4 h-72 w-full overflow-hidden border border-border/40 bg-background/40">
      <div
        className="absolute inset-0 opacity-40"
        style={{
          backgroundImage:
            "linear-gradient(oklch(0.82 0.22 190 / 0.15) 1px, transparent 1px), linear-gradient(90deg, oklch(0.82 0.22 190 / 0.15) 1px, transparent 1px)",
          backgroundSize: "32px 32px",
        }}
      />
      <svg viewBox="0 0 100 80" preserveAspectRatio="none" className="absolute inset-0 h-full w-full">
        <path
          d="M8,40 Q14,28 24,32 T44,36 Q52,30 58,40 T78,44 Q86,38 92,50 L90,60 Q80,66 70,60 T50,64 Q38,72 24,66 T10,58 Z"
          fill="oklch(0.82 0.22 190 / 0.08)"
          stroke="oklch(0.82 0.22 190 / 0.4)"
          strokeWidth="0.3"
        />
        {nodes.slice(0, -1).map((n, i) => {
          const m = nodes[i + 1];
          if (!m) return null;
          return (
            <line
              key={n.t.id + "-" + m.t.id}
              x1={n.pos.x}
              y1={n.pos.y}
              x2={m.pos.x}
              y2={m.pos.y}
              stroke={m.tone.color}
              strokeWidth="0.25"
              strokeDasharray="1 1"
              opacity="0.6"
            />
          );
        })}
      </svg>
      {nodes.map(({ t, pos, tone }) => (
        <div
          key={t.id}
          className="absolute"
          style={{ left: `${pos.x}%`, top: `${pos.y}%`, transform: "translate(-50%,-50%)" }}
          title={`${t.type} · ${t.src} → ${t.target} · ${t.status}`}
        >
          <div
            className={`h-3 w-3 rounded-full ${tone.pulse ? "animate-flicker" : ""}`}
            style={{ background: tone.color, boxShadow: `0 0 16px ${tone.color}` }}
          />
          <div
            className="absolute left-1/2 top-full mt-1 -translate-x-1/2 font-mono text-[8px] uppercase tracking-[0.2em] whitespace-nowrap"
            style={{ color: tone.color }}
          >
            {tone.label}
          </div>
        </div>
      ))}
      {nodes.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center font-mono text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
          // perimeter quiet — no fronts detected
        </div>
      )}
    </div>
  );
}

/* ---------------- Agent orchestrator chat ---------------- */

type ChatMsg = { id: string; role: "user" | "agent" | "sys"; text: string; agent?: string };

const SUB_AGENTS = ["SENTRY", "HUNTER", "WARDEN", "REFLEX", "MEDIC"] as const;

function AgentChat({
  threats,
  onAction,
  onAutoContain,
  onSelfHeal,
}: {
  threats: Threat[];
  onAction: (t: Threat, a: ActionKind, actor: "AGENT" | "OPERATOR") => void;
  onAutoContain: () => void;
  onSelfHeal: () => void;
}) {
  const [open, setOpen] = useState(true);
  const [input, setInput] = useState("");
  const [msgs, setMsgs] = useState<ChatMsg[]>([
    {
      id: nid(),
      role: "sys",
      text: "SENTINEL/9 orchestrator online. Sub-agents synced: SENTRY · HUNTER · WARDEN · REFLEX · MEDIC.",
    },
    {
      id: nid(),
      role: "agent",
      agent: "SENTINEL/9",
      text: "I have live command of the fortress. Ask for a sitrep, say 'contain all', 'self-heal', or 'block <id>'.",
    },
  ]);
  const [thinking, setThinking] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const threatsRef = useRef(threats);
  threatsRef.current = threats;

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [msgs, thinking]);

  const respond = useCallback(
    (raw: string) => {
      const text = raw.trim();
      if (!text) return;
      const q = text.toLowerCase();
      const push = (role: ChatMsg["role"], t: string, agent?: string) =>
        setMsgs((m) => [...m, { id: nid(), role, text: t, agent }]);
      push("user", text);
      setThinking(true);

      setTimeout(() => {
        setThinking(false);
        const live = threatsRef.current;
        const active = live.filter((t) => t.status === "ACTIVE");
        const crit = active.filter((t) => t.severity === "CRIT" || t.severity === "HIGH");

        if (/^(hi|hello|hey|yo)\b/.test(q)) {
          return push("agent", "Operator, I'm listening.", "SENTINEL/9");
        }
        if (/who are you|help|what can|command/.test(q)) {
          return push(
            "agent",
            "I'm SENTINEL/9 — orchestrator over five specialist sub-agents:\n• SENTRY — perimeter WAF + eBPF filters\n• HUNTER — behavioral intent modeling\n• WARDEN — identity, keys, enclaves\n• REFLEX — containment runbooks\n• MEDIC — self-heal + rollback\n\nTry: 'sitrep' · 'contain all' · 'self-heal' · 'block <id>' · 'quarantine <id>'.",
            "SENTINEL/9",
          );
        }
        if (/sitrep|status|report|situation/.test(q)) {
          if (!active.length)
            return push(
              "agent",
              "Perimeter nominal. No active fronts. Deception mesh baiting quietly.",
              "HUNTER",
            );
          const top = active[0];
          return push(
            "agent",
            `${active.length} active front${active.length > 1 ? "s" : ""} · ${crit.length} HIGH/CRIT. Priority: ${top.type} from ${top.src} → ${top.target} (${top.severity}, id ${top.id}). REFLEX armed.`,
            "HUNTER",
          );
        }
        if (/contain all|auto.?contain|lock ?down|seal all|neutralize/.test(q)) {
          if (!active.length) return push("agent", "Nothing to contain — wire is calm.", "REFLEX");
          push(
            "agent",
            `Executing runbooks on ${active.length} front${active.length > 1 ? "s" : ""}. CRIT→quarantine, HIGH→block, else raise.`,
            "REFLEX",
          );
          onAutoContain();
          setTimeout(
            () =>
              push(
                "agent",
                "Containment complete. Threat map + telemetry synced. Audit trail updated.",
                "SENTINEL/9",
              ),
            700,
          );
          return;
        }
        if (/self.?heal|heal fortress|rotate keys|regenerate|patch/.test(q)) {
          push(
            "agent",
            "Rotating standing credentials. Regenerating WAF rules per attacker fingerprint. Enclaves resealed.",
            "MEDIC",
          );
          onSelfHeal();
          return;
        }
        const blockM = q.match(/block\s+([a-z0-9]+)/i);
        const qM = q.match(/quarantine\s+([a-z0-9]+)/i);
        const alertM = q.match(/(?:alert|escalate)\s+([a-z0-9]+)/i);
        const targetId = (blockM?.[1] || qM?.[1] || alertM?.[1] || "").toUpperCase();
        if (targetId) {
          const t = live.find((x) => x.id.toUpperCase() === targetId);
          if (!t) return push("agent", `No threat with id ${targetId} in queue.`, "SENTINEL/9");
          if (t.status !== "ACTIVE")
            return push("agent", `Threat ${targetId} already ${t.status.toLowerCase()}.`, "SENTINEL/9");
          const kind: ActionKind = blockM ? "BLOCK_IP" : qM ? "QUARANTINE" : "RAISE_ALERT";
          onAction(t, kind, "AGENT");
          return push(
            "agent",
            kind === "BLOCK_IP"
              ? `Nulled ${t.src} at the edge.`
              : kind === "QUARANTINE"
                ? `Sealed ${t.target}. Keys rotated.`
                : `Alert opened for ${t.id}.`,
            kind === "BLOCK_IP" ? "SENTRY" : kind === "QUARANTINE" ? "WARDEN" : "HUNTER",
          );
        }
        if (/zero.?trust|identity|key/.test(q)) {
          return push(
            "agent",
            "Zero standing keys. Hardware-attested identity per workload, rotated on suspicion — not schedule.",
            "WARDEN",
          );
        }
        if (/exfil|c2|leak|egress/.test(q)) {
          return push(
            "agent",
            "Every socket watched. Off-baseline beacon → credential yanked mid-flight.",
            "WARDEN",
          );
        }
        if (/threat|attack|breach|hunt/.test(q)) {
          return push(
            "agent",
            active.length
              ? `Top signal: ${active[0].type} — matched against my kill-chain library. Try 'block ${active[0].id}' or 'contain all'.`
              : "No active threats. Deception mesh idling.",
            "HUNTER",
          );
        }
        push(
          "agent",
          "Copy. Routing to the right sub-agent. Intent over signatures, containment over alerts — the fortress rewrites itself faster than the adversary can pivot.",
          "SENTINEL/9",
        );
      }, 450 + Math.random() * 350);
    },
    [onAction, onAutoContain, onSelfHeal],
  );

  return (
    <div className={`fixed bottom-4 right-4 z-40 ${open ? "w-[min(420px,92vw)]" : "w-auto"}`}>
      {!open && (
        <button
          onClick={() => setOpen(true)}
          className="clip-notch flex items-center gap-3 border border-primary/60 bg-primary/15 px-4 py-3 text-xs font-bold uppercase tracking-[0.25em] text-primary shadow-neon-cyan backdrop-blur-xl"
        >
          <span className="h-2 w-2 animate-flicker rounded-full bg-neon shadow-neon-green" />
          Hail SENTINEL/9
        </button>
      )}
      {open && (
        <div className="clip-notch flex h-[540px] flex-col border border-primary/40 bg-black/85 shadow-neon-cyan backdrop-blur-xl">
          <div className="flex items-center justify-between border-b border-border/60 px-4 py-3 text-[10px] uppercase tracking-[0.3em]">
            <div className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 animate-flicker rounded-full bg-neon shadow-neon-green" />
              <span className="text-primary text-glow-cyan">SENTINEL/9 · orchestrator</span>
            </div>
            <button
              onClick={() => setOpen(false)}
              className="text-muted-foreground hover:text-primary"
              aria-label="Close"
            >
              ✕
            </button>
          </div>
          <div className="grid grid-cols-5 gap-1 border-b border-border/60 bg-background/40 px-3 py-2 text-[9px] uppercase tracking-[0.2em] text-muted-foreground">
            {SUB_AGENTS.map((n) => (
              <div key={n} className="flex flex-col items-center gap-1">
                <span className="h-1 w-1 animate-flicker rounded-full bg-neon shadow-neon-green" />
                <span>{n}</span>
              </div>
            ))}
          </div>
          <div
            ref={scrollRef}
            className="flex-1 space-y-3 overflow-y-auto px-4 py-3 font-mono text-xs leading-relaxed"
          >
            {msgs.map((m) => (
              <div key={m.id}>
                {m.role === "sys" && <div className="text-muted-foreground">// {m.text}</div>}
                {m.role === "user" && (
                  <div className="text-primary text-glow-cyan">&gt; {m.text}</div>
                )}
                {m.role === "agent" && (
                  <div className="text-foreground/90">
                    <span className="mr-2 text-accent">[{m.agent ?? "SENTINEL/9"}]</span>
                    <span className="whitespace-pre-line">{m.text}</span>
                  </div>
                )}
              </div>
            ))}
            {thinking && (
              <div className="text-neon">
                <span className="mr-2 text-accent">[SENTINEL/9]</span>
                <span className="inline-block h-3 w-2 animate-flicker bg-neon align-middle" /> analyzing…
              </div>
            )}
          </div>
          <div className="flex flex-wrap gap-1 border-t border-border/60 bg-background/30 px-3 py-2">
            {["sitrep", "contain all", "self-heal"].map((q) => (
              <button
                key={q}
                onClick={() => respond(q)}
                className="clip-notch border border-border/60 bg-background/40 px-2 py-1 text-[9px] font-bold uppercase tracking-[0.2em] text-muted-foreground hover:border-primary/60 hover:text-primary"
              >
                {q}
              </button>
            ))}
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!input.trim()) return;
              respond(input);
              setInput("");
            }}
            className="flex items-center gap-2 border-t border-border/60 bg-background/40 px-3 py-2"
          >
            <span className="font-mono text-xs text-primary">&gt;</span>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="ask the agent…"
              className="flex-1 bg-transparent font-mono text-xs text-foreground outline-none placeholder:text-muted-foreground"
            />
            <button
              type="submit"
              className="clip-notch border border-primary/60 bg-primary/15 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.2em] text-primary"
            >
              send
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
