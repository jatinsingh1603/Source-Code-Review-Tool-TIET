import { useRef, useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useSession } from "@/app/session";
import { ApiError } from "@/api/client";
import { api } from "@/api/client";
import { Icon, Logo } from "@/components/ui";

/** Login (landing hero), SCREENS.md §04. Outside the app shell. */
export default function LoginPage() {
  const { login, user, loading } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const state = (location.state ?? {}) as { from?: string; expired?: boolean };
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [demoHint, setDemoHint] = useState(false);
  const nextRef = useRef<string>(state.from ?? "/");
  const emailRef = useRef<HTMLInputElement>(null);

  if (!loading && user) return <Navigate to={nextRef.current && nextRef.current !== "/login" ? nextRef.current : "/"} replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError("Enter your email or username and password.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password, remember);
      const to = nextRef.current && nextRef.current !== "/login" ? nextRef.current : "/";
      navigate(to, { replace: true });
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 400 || err.status === 403)) {
        setError("Email or password is incorrect.");
      } else if (err instanceof ApiError && err.status === 429) {
        setError("Too many attempts. Wait a minute and try again.");
      } else if (err instanceof ApiError && err.status === 0) {
        setError("The CodeKavach server cannot be reached.");
      } else {
        setError(err instanceof Error ? err.message : "Sign-in failed.");
      }
    } finally {
      setBusy(false);
    }
  };

  const tryDemo = () => {
    nextRef.current = "/demo";
    if (api.isMock) {
      void login("admin", "kavach-admin").then(() => navigate("/demo", { replace: true }));
      return;
    }
    setError(null);
    setDemoHint(true);
    emailRef.current?.focus();
  };

  const host = typeof window !== "undefined" ? window.location.host : "";

  return (
    <main className="ck" style={{ display: "flex", flexWrap: "wrap", minHeight: "100vh" }}>
      <section
        style={{
          flex: "1 1 520px",
          padding: "clamp(24px, 6vw, 56px)",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          gap: 40,
          background: "var(--surface)",
          borderRight: "1px solid var(--border)",
          minWidth: 0,
        }}
      >
        <div className="row" style={{ gap: 12 }}>
          <Logo size={32} />
          <span style={{ fontSize: 20, fontWeight: 700 }}>CodeKavach</span>
          <span style={{ fontFamily: "'Noto Sans Devanagari', sans-serif", color: "var(--muted)" }}>कवच</span>
        </div>
        <div className="stack s20" style={{ maxWidth: 560 }}>
          <h1 style={{ fontSize: "clamp(28px, 4vw, 36px)", lineHeight: 1.15, fontWeight: 650, letterSpacing: "-0.025em" }}>
            Get an LLM security review. Keep secrets and personal data local.
          </h1>
          <p className="muted" style={{ fontSize: 16 }}>
            Minimise and measure the business logic you disclose. Every byte that leaves is hashed, checked and written to a
            tamper-evident ledger.
          </p>
          <div className="stack s6">
            <div className="guard">
              <span className="gid">L3</span>
              <span className="gt">Minimal slice by default. No whole files.</span>
            </div>
            <div className="guard">
              <span className="gid">I4</span>
              <span className="gt">Any privacy-step failure aborts the request.</span>
            </div>
            <div className="guard">
              <span className="gid">I6</span>
              <span className="gt">Ledger payloads checked for listed terms of 4+ characters.</span>
            </div>
          </div>
        </div>
        <div className="xs faint">OWASP Code Review Guide · ASVS · CWE · CVSS 4.0 · SARIF 2.1.0 · NIST SSDF</div>
      </section>
      <section
        style={{ flex: "1 1 440px", display: "flex", alignItems: "center", justifyContent: "center", padding: "48px 24px", minWidth: 0 }}
      >
        <form className="card stack s16" style={{ width: "100%", maxWidth: 420, padding: 28 }} onSubmit={submit} noValidate>
          <div>
            <h2 style={{ fontSize: 20, fontWeight: 650 }}>Sign in</h2>
            <p className="sub" style={{ marginTop: 4 }}>
              Choose your organisation to continue.
            </p>
          </div>
          <div className="fld">
            <label htmlFor="tenant">Organisation</label>
            <select id="tenant" className="inp">
              <option>This server · {host}</option>
            </select>
          </div>
          <button
            className="btn pri"
            type="button"
            style={{ width: "100%" }}
            disabled
            title="Single sign-on is not configured on this server. Use a local account."
          >
            <Icon name="lock-wide" />
            Continue with SSO (SAML / OIDC)
          </button>
          <div className="row" style={{ gap: 10 }}>
            <div className="hr" style={{ flex: 1 }} />
            <span className="xs faint">or local account</span>
            <div className="hr" style={{ flex: 1 }} />
          </div>
          {state.expired && !error && <div className="banner warn sm">Your session has ended. Sign in again.</div>}
          {demoHint && !error && (
            <div className="banner info sm">Sign in with your local account to open the demo.</div>
          )}
          <div className="fld">
            <label htmlFor="em">Email or username</label>
            <input
              id="em"
              ref={emailRef}
              className="inp"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div className="fld">
            <label htmlFor="pw">Password</label>
            <input
              id="pw"
              className="inp"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <div className="row between">
            <label className="swrow">
              <input type="checkbox" className="chk" checked={remember} onChange={(e) => setRemember(e.target.checked)} /> Remember
              this device
            </label>
            <span className="sm faint" title="Ask an administrator to reset your password in Admin → Users and roles.">
              Forgot password? Ask an admin.
            </span>
          </div>
          {error && (
            <div className="banner bad sm" role="alert">
              {error}
            </div>
          )}
          <button className="btn" type="submit" style={{ width: "100%" }} disabled={busy} aria-busy={busy || undefined}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <div className="hr" />
          <button className="btn ghost" type="button" style={{ width: "100%" }} onClick={tryDemo}>
            <Icon name="play" />
            Try the offline demo
          </button>
          <p className="xs faint" style={{ textAlign: "center" }}>
            No telemetry leaves this machine.
          </p>
        </form>
      </section>
    </main>
  );
}
