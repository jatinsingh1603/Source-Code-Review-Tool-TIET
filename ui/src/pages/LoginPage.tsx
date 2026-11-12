import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { Eye, EyeOff, Fingerprint, LockKeyhole, ScrollText, ShieldCheck } from "lucide-react";
import { useSession } from "@/app/session";
import { ApiError, api } from "@/api/client";
import { Button, Callout, Field, Input } from "@/components/ui";
import { LogoMark } from "@/components/layout/Logo";

const FEATURES = [
  {
    icon: ShieldCheck,
    title: "Deterministic first",
    text: "Rules, taint analysis and external engines find candidates locally before any model is involved.",
  },
  {
    icon: Fingerprint,
    title: "Privacy by construction",
    text: "Secrets and personal data are redacted, internal names pseudonymised and code minimally sliced before egress.",
  },
  {
    icon: ScrollText,
    title: "Verifiable egress",
    text: "Every payload is recorded in a hash-chained ledger you can inspect side by side with the original.",
  },
];

export default function LoginPage() {
  const { user, login, loading } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const state = (location.state ?? {}) as { from?: string; expired?: boolean };
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!loading && user) return <Navigate to={state.from ?? "/"} replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(username.trim(), password);
      navigate(state.from && state.from !== "/login" ? state.from : "/", { replace: true });
    } catch (err) {
      setError(
        err instanceof ApiError && (err.status === 401 || err.status === 400)
          ? "The username or password is not correct."
          : err instanceof Error
            ? err.message
            : "Sign-in failed.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-screen lg:grid-cols-[1.1fr_1fr]">
      <div className="relative hidden overflow-hidden bg-sidebar p-12 text-white lg:flex lg:flex-col">
        <div
          aria-hidden
          className="pointer-events-none absolute -right-32 -top-32 h-[28rem] w-[28rem] rounded-full bg-[rgb(var(--ck-primary)/0.35)] blur-3xl"
        />
        <div
          aria-hidden
          className="pointer-events-none absolute -bottom-40 left-10 h-[26rem] w-[26rem] rounded-full bg-[rgb(var(--ck-accent)/0.25)] blur-3xl"
        />
        <div className="relative flex items-center gap-3">
          <LogoMark className="h-10 w-10" />
          <div>
            <p className="text-xl font-bold tracking-tight">CodeKavach</p>
            <p className="text-sm text-sidebar-muted">Privacy-preserving secure code review</p>
          </div>
        </div>
        <div className="relative mt-auto max-w-lg">
          <h1 className="text-3xl font-semibold leading-tight tracking-tight">
            LLM-assisted security review, without handing over your source code.
          </h1>
          <ul className="mt-8 space-y-5">
            {FEATURES.map((f) => (
              <li key={f.title} className="flex gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-white/10">
                  <f.icon className="h-5 w-5 text-[rgb(var(--ck-accent))]" aria-hidden />
                </div>
                <div>
                  <p className="font-semibold">{f.title}</p>
                  <p className="mt-0.5 text-sm text-sidebar-fg">{f.text}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
        <p className="relative mt-12 text-xs text-sidebar-muted">Thapar Institute of Engineering &amp; Technology</p>
      </div>

      <div className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <LogoMark className="h-10 w-10" />
            <div>
              <p className="text-xl font-bold tracking-tight text-fg">CodeKavach</p>
              <p className="text-sm text-fg-subtle">Privacy-preserving secure code review</p>
            </div>
          </div>
          <h2 className="text-2xl font-semibold tracking-tight text-fg">Sign in</h2>
          <p className="mt-1 text-sm text-fg-muted">Use your CodeKavach account to continue.</p>

          {state.expired && !error && (
            <Callout tone="warning" className="mt-6">
              Your session has ended. Please sign in again.
            </Callout>
          )}
          {error && (
            <Callout tone="danger" className="mt-6" title="Sign-in failed">
              {error}
            </Callout>
          )}

          <form onSubmit={submit} className="mt-6 space-y-4" noValidate>
            <Field label="Username" required>
              {(id) => (
                <Input
                  id={id}
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  autoFocus
                />
              )}
            </Field>
            <Field label="Password" required>
              {(id) => (
                <div className="relative">
                  <Input
                    id={id}
                    type={show ? "text" : "password"}
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShow((s) => !s)}
                    aria-label={show ? "Hide password" : "Show password"}
                    className="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-fg-subtle hover:text-fg"
                  >
                    {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              )}
            </Field>
            <Button type="submit" className="w-full" size="lg" loading={busy} icon={<LockKeyhole className="h-4 w-4" />}>
              Sign in
            </Button>
          </form>
          <p className="mt-6 text-xs text-fg-subtle">
            {api.isMock
              ? "Demo data mode: sign in as admin with password kavach-admin."
              : "Local installations print the initial administrator password when the server starts."}
          </p>
        </div>
      </div>
    </div>
  );
}
