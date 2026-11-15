import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "@/api/client";
import { endpoints } from "@/api/endpoints";
import { useSession } from "@/app/session";
import { GOOGLE_CLIENT_ID, GOOGLE_LOGIN_PATH, GSI_SCRIPT_URL, decodeGoogleCredential } from "@/lib/sso";

interface GsiId {
  initialize: (options: { client_id: string; callback: (response: { credential?: string }) => void }) => void;
  renderButton: (parent: HTMLElement, options: Record<string, unknown>) => void;
}

declare global {
  interface Window {
    google?: { accounts?: { id?: GsiId } };
  }
}

/** The four-colour Google "G" mark. */
export function GoogleMark({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" aria-hidden="true" focusable="false">
      <path
        fill="#EA4335"
        d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
      />
      <path
        fill="#4285F4"
        d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
      />
      <path
        fill="#FBBC05"
        d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
      />
      <path
        fill="#34A853"
        d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
      />
    </svg>
  );
}

interface Props {
  onSignedIn: () => void;
  onError: (message: string) => void;
  /** Shown in the same place while Google sign-in is not available. */
  fallback?: ReactNode;
}

/**
 * "Sign in with Google" for the login page's single sign-on place. Renders the
 * fallback unless the server says Google sign-in is configured, or (mock mode
 * only) the build carries a Google client ID for the hosted demo.
 */
export function GoogleSignIn(props: Props) {
  if (api.isMock) return GOOGLE_CLIENT_ID ? <DemoGoogleSignIn {...props} /> : <>{props.fallback ?? null}</>;
  return <ServerGoogleSignIn fallback={props.fallback} />;
}

function ServerGoogleSignIn({ fallback }: Pick<Props, "fallback">) {
  const [enabled, setEnabled] = useState(false);
  useEffect(() => {
    let live = true;
    endpoints
      .authProviders()
      .then((p) => {
        if (live) setEnabled(p?.google?.enabled === true);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);
  if (!enabled) return <>{fallback ?? null}</>;
  return (
    <a
      className="btn"
      href={GOOGLE_LOGIN_PATH}
      style={{ width: "100%", textDecoration: "none" }}
      data-testid="google-sign-in"
    >
      <GoogleMark />
      Sign in with Google
    </a>
  );
}

function loadGsi(): Promise<GsiId> {
  return new Promise((resolve, reject) => {
    const ready = () => {
      const id = window.google?.accounts?.id;
      if (id) resolve(id);
      else reject(new Error("Google Identity Services did not load"));
    };
    if (window.google?.accounts?.id) {
      ready();
      return;
    }
    const script = document.createElement("script");
    script.src = GSI_SCRIPT_URL;
    script.async = true;
    script.onload = ready;
    script.onerror = () => reject(new Error("Google Identity Services did not load"));
    document.head.appendChild(script);
  });
}

function DemoGoogleSignIn({ onSignedIn, onError, fallback }: Props) {
  const { loginWithGoogleDemo } = useSession();
  const holder = useRef<HTMLDivElement>(null);
  const [failed, setFailed] = useState(false);
  const handlers = useRef({ onSignedIn, onError, loginWithGoogleDemo });
  useEffect(() => {
    handlers.current = { onSignedIn, onError, loginWithGoogleDemo };
  });

  useEffect(() => {
    let live = true;
    loadGsi()
      .then((gsi) => {
        if (!live || !holder.current) return;
        gsi.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: (response) => {
            const profile = response.credential ? decodeGoogleCredential(response.credential) : null;
            if (!profile) {
              handlers.current.onError("Google sign-in did not return a usable account.");
              return;
            }
            handlers.current
              .loginWithGoogleDemo(profile)
              .then(() => handlers.current.onSignedIn())
              .catch(() => handlers.current.onError("Google sign-in failed in the demo."));
          },
        });
        gsi.renderButton(holder.current, {
          type: "standard",
          theme: "outline",
          size: "large",
          text: "signin_with",
          width: 320,
        });
      })
      .catch(() => {
        if (live) setFailed(true);
      });
    return () => {
      live = false;
    };
  }, []);

  if (failed) return <>{fallback ?? null}</>;
  return (
    <div className="stack s6" data-testid="google-demo-sign-in">
      <div ref={holder} style={{ display: "flex", justifyContent: "center", minHeight: 44 }} />
      <p className="xs faint" style={{ textAlign: "center" }}>
        Demo sign-in: Google tells this page only your name and email, which stay in your browser. You see sample data.
      </p>
    </div>
  );
}
