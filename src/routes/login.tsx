import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";

function safeNext(value: unknown): string {
  if (typeof value !== "string") return "/";
  if (!value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

export const Route = createFileRoute("/login")({
  ssr: false,
  validateSearch: (s: Record<string, unknown>) => ({ next: safeNext(s.next) }),
  head: () => ({
    meta: [
      { title: "Operator Access · SENTINEL/9" },
      { name: "description", content: "Sign in to the SENTINEL/9 fortress console." },
      { property: "og:title", content: "Operator Access · SENTINEL/9" },
      { property: "og:description", content: "Sign in to the SENTINEL/9 fortress console." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Login,
});

function Login() {
  const { next } = Route.useSearch();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const returnUrl = new URL(next, typeof window !== "undefined" ? window.location.origin : "http://localhost").toString();

  async function signIn(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    setBusy(false);
    if (error) return setMsg(error.message);
    window.location.href = next;
  }

  async function signUp() {
    setBusy(true);
    setMsg(null);
    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: { emailRedirectTo: returnUrl },
    });
    setBusy(false);
    setMsg(error ? error.message : "Check your inbox to confirm the account.");
  }

  return (
    <main className="min-h-screen flex items-center justify-center bg-background p-6">
      <div className="w-full max-w-sm border border-primary/40 bg-card/70 p-6 shadow-[0_0_40px_-12px] shadow-primary/40">
        <h1 className="font-display text-xl tracking-widest text-primary">OPERATOR ACCESS</h1>
        <p className="mt-1 text-xs text-muted-foreground">
          Authenticate to reach the SENTINEL/9 console and authorize agent clients.
        </p>
        <form onSubmit={signIn} className="mt-5 space-y-3">
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="operator@fortress.io"
            className="w-full bg-background/60 border border-border px-3 py-2 text-sm outline-none focus:border-primary"
          />
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="passphrase"
            className="w-full bg-background/60 border border-border px-3 py-2 text-sm outline-none focus:border-primary"
          />
          {msg && <p className="text-xs text-destructive">{msg}</p>}
          <button
            type="submit"
            disabled={busy}
            className="w-full bg-primary px-3 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50"
          >
            {busy ? "AUTHENTICATING…" : "SIGN IN"}
          </button>
          <button
            type="button"
            onClick={signUp}
            disabled={busy}
            className="w-full border border-border px-3 py-2 text-sm text-foreground disabled:opacity-50"
          >
            CREATE OPERATOR
          </button>
        </form>
        <button
          type="button"
          onClick={() => navigate({ to: "/" })}
          className="mt-4 w-full text-xs text-muted-foreground hover:text-primary"
        >
          ← back to fortress
        </button>
      </div>
    </main>
  );
}
