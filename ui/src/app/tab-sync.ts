/**
 * Share the sign-in between this browser's open dashboard tabs.
 *
 * The token lives in sessionStorage, which a tab opened with Ctrl+click or "Open in new tab"
 * does not inherit, so every finding opened in a new tab asked for the password again. A new
 * tab without a token now asks the open tabs for theirs over a same-origin BroadcastChannel,
 * and signing out in one tab signs out the others. Closing every tab still ends the session.
 */
export type TabMessage = { type: "ask" } | { type: "token"; token: string } | { type: "signed-out" };

const CHANNEL = "codekavach-session";

export function openTabChannel(onMessage: (m: TabMessage) => void): { post: (m: TabMessage) => void; close: () => void } {
  let channel: BroadcastChannel | null = null;
  try {
    channel = typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel(CHANNEL);
  } catch {
    channel = null;
  }
  if (channel) {
    channel.onmessage = (e: MessageEvent) => {
      const m = e.data as TabMessage | null;
      if (m && typeof m === "object" && typeof m.type === "string") onMessage(m);
    };
  }
  return {
    post: (m) => {
      try {
        channel?.postMessage(m);
      } catch {
        /* channel closed */
      }
    },
    close: () => channel?.close(),
  };
}

/**
 * Why the sign-in page is showing: another tab signed out, or the server refused the token
 * (expired or revoked). Router state cannot carry this: the auth guard redirects first.
 */
export const signOutNotice = { elsewhere: false, expired: false };

/** How long a new tab waits for an open tab to answer before showing the sign-in page. */
export const ASK_TIMEOUT_MS = 250;
