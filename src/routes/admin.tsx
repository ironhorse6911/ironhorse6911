import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import {
  claimAdmin,
  getAdminState,
  listScans,
  runScan,
  updateFindingStatus,
} from "@/lib/security-admin.functions";

export const Route = createFileRoute("/admin")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "Security Command · SENTINEL/9 Admin" },
      {
        name: "description",
        content:
          "Trigger fortress security re-scans and review the full history of SENTINEL/9 security findings over time.",
      },
      { property: "og:title", content: "Security Command · SENTINEL/9 Admin" },
      {
        property: "og:description",
        content: "Trigger re-scans and audit the SENTINEL/9 security findings timeline.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: AdminPage,
});

const SEV_STYLES: Record<string, string> = {
  critical: "border-destructive/60 text-destructive",
  high: "border-secondary/60 text-secondary",
  medium: "border-primary/60 text-primary",
  low: "border-muted-foreground/40 text-muted-foreground",
};

const STATUS_STYLES: Record<string, string> = {
  open: "border-destructive/60 text-destructive",
  fixed: "border-neon/60 text-neon",
  ignored: "border-muted-foreground/40 text-muted-foreground",
};

function Chip({ label, className }: { label: string; className: string }) {
  return (
    <span
      className={`inline-flex items-center border px-2 py-0.5 text-[10px] uppercase tracking-[0.2em] ${className}`}
    >
      {label}
    </span>
  );
}

function AdminPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [sessionChecked, setSessionChecked] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const fetchAdminState = useServerFn(getAdminState);
  const fetchScans = useServerFn(listScans);
  const doRunScan = useServerFn(runScan);
  const doClaimAdmin = useServerFn(claimAdmin);
  const doUpdateFinding = useServerFn(updateFindingStatus);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (!data.session) {
        navigate({ to: "/login", search: { next: "/admin" }, replace: true });
        return;
      }
      setSessionChecked(true);
    });
  }, [navigate]);

  const adminState = useQuery({
    queryKey: ["admin-state"],
    queryFn: () => fetchAdminState(),
    enabled: sessionChecked,
  });

  const isAdmin = adminState.data?.isAdmin ?? false;

  const history = useQuery({
    queryKey: ["security-history"],
    queryFn: () => fetchScans(),
    enabled: sessionChecked && isAdmin,
  });

  const scanMutation = useMutation({
    mutationFn: () => doRunScan(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["security-history"] }),
  });

  const claimMutation = useMutation({
    mutationFn: () => doClaimAdmin(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-state"] }),
  });

  const findingMutation = useMutation({
    mutationFn: (input: { id: string; status: "open" | "fixed" | "ignored" }) =>
      doUpdateFinding({ data: input }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["security-history"] }),
  });

  const scans = history.data?.scans ?? [];
  const findings = history.data?.findings ?? [];

  const trend = useMemo(() => {
    return [...scans]
      .slice(0, 12)
      .reverse()
      .map((s) => ({
        id: s.id,
        score: Number(s.posture_score ?? 0),
        open: s.critical_count + s.high_count + s.medium_count + s.low_count,
        at: new Date(s.started_at).toLocaleString(),
      }));
  }, [scans]);

  const latest = scans[0];

  async function signOut() {
    await queryClient.cancelQueries();
    queryClient.clear();
    await supabase.auth.signOut();
    navigate({ to: "/login", search: { next: "/admin" }, replace: true });
  }

  if (!sessionChecked || adminState.isLoading) {
    return (
      <main className="min-h-screen bg-background p-10 text-sm text-muted-foreground">
        Establishing secure channel…
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      <header className="border-b border-primary/25 bg-card/40 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-6 py-4">
          <div>
            <div className="font-display text-sm font-bold tracking-[0.3em] text-primary text-glow-cyan">
              SECURITY COMMAND
            </div>
            <div className="text-[10px] uppercase tracking-[0.35em] text-muted-foreground">
              re-scan control · findings history
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs uppercase tracking-[0.2em]">
            <Link to="/" className="text-muted-foreground hover:text-primary">
              fortress
            </Link>
            <button onClick={signOut} className="border border-border px-3 py-1.5 hover:border-primary">
              sign out
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-6xl px-6 py-8">
        {!isAdmin ? (
          <div className="border border-secondary/40 bg-card/60 p-6">
            <h1 className="font-display text-lg tracking-widest text-secondary">CLEARANCE REQUIRED</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              {adminState.data?.adminExists
                ? "This console is restricted to fortress administrators. Ask an existing admin to grant you access."
                : "No administrator is registered yet. Claim the first admin seat to unlock the security console."}
            </p>
            {!adminState.data?.adminExists && (
              <button
                onClick={() => claimMutation.mutate()}
                disabled={claimMutation.isPending}
                className="mt-4 bg-primary px-4 py-2 text-xs font-bold uppercase tracking-[0.2em] text-primary-foreground disabled:opacity-50"
              >
                {claimMutation.isPending ? "Provisioning…" : "Claim admin seat"}
              </button>
            )}
            {claimMutation.error && (
              <p className="mt-3 text-xs text-destructive">{(claimMutation.error as Error).message}</p>
            )}
          </div>
        ) : (
          <>
            <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {[
                { label: "Posture score", value: latest ? `${latest.posture_score}` : "—" },
                { label: "Open critical", value: latest ? latest.critical_count : "—" },
                { label: "Open high", value: latest ? latest.high_count : "—" },
                { label: "Scans recorded", value: scans.length },
              ].map((card) => (
                <div key={card.label} className="clip-notch border border-primary/30 bg-card/60 p-4">
                  <div className="text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
                    {card.label}
                  </div>
                  <div className="mt-2 font-display text-2xl text-primary">{card.value}</div>
                </div>
              ))}
            </section>

            <section className="mt-6 flex flex-wrap items-center gap-3 border border-primary/25 bg-card/40 p-4">
              <button
                onClick={() => scanMutation.mutate()}
                disabled={scanMutation.isPending}
                className="clip-notch bg-primary px-4 py-2 text-xs font-bold uppercase tracking-[0.2em] text-primary-foreground shadow-neon-cyan disabled:opacity-50"
              >
                {scanMutation.isPending ? "Scanning fortress…" : "Trigger re-scan"}
              </button>
              <span className="text-xs text-muted-foreground">
                {latest
                  ? `Last scan ${new Date(latest.started_at).toLocaleString()} · ${latest.duration_ms ?? 0} ms`
                  : "No scans recorded yet."}
              </span>
              <div className="ml-auto flex items-center gap-2">
                <span className="text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
                  severity
                </span>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="border border-border bg-background/60 px-2 py-1 text-xs"
                >
                  <option value="all">all</option>
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </select>
              </div>
              {scanMutation.error && (
                <p className="w-full text-xs text-destructive">{(scanMutation.error as Error).message}</p>
              )}
            </section>

            {trend.length > 1 && (
              <section className="mt-6 border border-primary/25 bg-card/40 p-4">
                <div className="text-[10px] uppercase tracking-[0.3em] text-muted-foreground">
                  posture score over time
                </div>
                <div className="mt-4 flex h-32 items-end gap-2">
                  {trend.map((point) => (
                    <div key={point.id} className="group flex flex-1 flex-col items-center gap-1">
                      <div
                        className="w-full bg-primary/70 transition-colors group-hover:bg-primary"
                        style={{ height: `${Math.max(4, point.score)}%` }}
                        title={`${point.at} · score ${point.score} · ${point.open} open`}
                      />
                      <span className="text-[9px] text-muted-foreground">{point.score}</span>
                    </div>
                  ))}
                </div>
              </section>
            )}

            <section className="mt-6 space-y-3">
              <h2 className="font-display text-sm tracking-[0.3em] text-primary">SCAN HISTORY</h2>
              {history.isLoading && <p className="text-xs text-muted-foreground">Loading history…</p>}
              {!history.isLoading && scans.length === 0 && (
                <p className="text-xs text-muted-foreground">
                  No scans yet — trigger the first fortress re-scan above.
                </p>
              )}
              {scans.map((scan) => {
                const scanFindings = findings
                  .filter((f) => f.scan_id === scan.id)
                  .filter((f) => severityFilter === "all" || f.severity === severityFilter);
                const open = scanFindings.filter((f) => f.status === "open").length;
                const isOpen = expanded === scan.id;
                return (
                  <div key={scan.id} className="border border-border bg-card/40">
                    <button
                      onClick={() => setExpanded(isOpen ? null : scan.id)}
                      className="flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left"
                    >
                      <span className="font-mono text-xs text-primary">
                        {new Date(scan.started_at).toLocaleString()}
                      </span>
                      <Chip label={scan.status} className="border-primary/50 text-primary" />
                      <span className="text-xs text-muted-foreground">
                        score {scan.posture_score} · {open} open of {scanFindings.length}
                      </span>
                      <span className="ml-auto flex gap-2">
                        <Chip label={`C ${scan.critical_count}`} className={SEV_STYLES.critical} />
                        <Chip label={`H ${scan.high_count}`} className={SEV_STYLES.high} />
                        <Chip label={`M ${scan.medium_count}`} className={SEV_STYLES.medium} />
                        <Chip label={`L ${scan.low_count}`} className={SEV_STYLES.low} />
                      </span>
                    </button>
                    {isOpen && (
                      <div className="border-t border-border/60 divide-y divide-border/40">
                        {scanFindings.length === 0 && (
                          <p className="px-4 py-3 text-xs text-muted-foreground">
                            No findings match this filter.
                          </p>
                        )}
                        {scanFindings.map((f) => (
                          <div key={f.id} className="flex flex-wrap items-start gap-3 px-4 py-3">
                            <div className="min-w-[240px] flex-1">
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-xs text-foreground">{f.title}</span>
                                <Chip label={f.severity} className={SEV_STYLES[f.severity] ?? SEV_STYLES.low} />
                                <Chip label={f.status} className={STATUS_STYLES[f.status] ?? STATUS_STYLES.open} />
                              </div>
                              <p className="mt-1 text-xs text-muted-foreground">{f.description}</p>
                              <p className="mt-1 text-[10px] uppercase tracking-[0.25em] text-muted-foreground">
                                {f.category} · {f.code}
                              </p>
                            </div>
                            <div className="flex gap-2">
                              {(["open", "fixed", "ignored"] as const)
                                .filter((s) => s !== f.status)
                                .map((s) => (
                                  <button
                                    key={s}
                                    disabled={findingMutation.isPending}
                                    onClick={() => findingMutation.mutate({ id: f.id, status: s })}
                                    className="border border-border px-2 py-1 text-[10px] uppercase tracking-[0.2em] text-muted-foreground hover:border-primary hover:text-primary disabled:opacity-50"
                                  >
                                    mark {s}
                                  </button>
                                ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </section>
          </>
        )}
      </div>
    </main>
  );
}
