import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { generateFindings, summarize } from "./security-scan.server";

export const getAdminState = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data: roles, error } = await context.supabase
      .from("user_roles")
      .select("role")
      .eq("user_id", context.userId);
    if (error) throw new Error(error.message);
    const isAdmin = (roles ?? []).some((r) => r.role === "admin");

    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { count } = await supabaseAdmin
      .from("user_roles")
      .select("id", { count: "exact", head: true })
      .eq("role", "admin");

    return { isAdmin, adminExists: (count ?? 0) > 0, email: (context.claims.email as string) ?? null };
  });

export const claimAdmin = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { count } = await supabaseAdmin
      .from("user_roles")
      .select("id", { count: "exact", head: true })
      .eq("role", "admin");
    if ((count ?? 0) > 0) throw new Error("An administrator already exists for this fortress.");

    const { error } = await supabaseAdmin
      .from("user_roles")
      .insert({ user_id: context.userId, role: "admin" });
    if (error) throw new Error(error.message);
    return { isAdmin: true };
  });

export const listScans = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data: scans, error } = await context.supabase
      .from("security_scans")
      .select("*")
      .order("started_at", { ascending: false })
      .limit(25);
    if (error) throw new Error(error.message);

    const ids = (scans ?? []).map((s) => s.id);
    if (ids.length === 0) return { scans: [], findings: [] };

    const { data: findings, error: fErr } = await context.supabase
      .from("security_findings")
      .select("*")
      .in("scan_id", ids)
      .order("severity", { ascending: true });
    if (fErr) throw new Error(fErr.message);

    return { scans: scans ?? [], findings: findings ?? [] };
  });

export const runScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const startedAt = Date.now();
    const { data: scan, error } = await context.supabase
      .from("security_scans")
      .insert({ triggered_by: context.userId, trigger_source: "manual", status: "running" })
      .select()
      .single();
    if (error) throw new Error(error.message);

    const findings = generateFindings();
    const summary = summarize(findings);

    const { error: fErr } = await context.supabase
      .from("security_findings")
      .insert(findings.map((f) => ({ ...f, scan_id: scan.id })));
    if (fErr) throw new Error(fErr.message);

    const { data: completed, error: uErr } = await context.supabase
      .from("security_scans")
      .update({
        status: "complete",
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - startedAt,
        ...summary,
      })
      .eq("id", scan.id)
      .select()
      .single();
    if (uErr) throw new Error(uErr.message);

    return { scan: completed };
  });

export const updateFindingStatus = createServerFn({ method: "POST" })
  .inputValidator((data: { id: string; status: "open" | "fixed" | "ignored" }) => data)
  .middleware([requireSupabaseAuth])
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase
      .from("security_findings")
      .update({ status: data.status })
      .eq("id", data.id);
    if (error) throw new Error(error.message);
    return { ok: true };
  });
