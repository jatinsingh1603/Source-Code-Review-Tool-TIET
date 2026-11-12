/**
 * Dark mode: `class` strategy on the document root. The default follows
 * `prefers-color-scheme`; an explicit choice is persisted in localStorage.
 * `public/theme-init.js` applies the same rule before first paint.
 */
import { useCallback, useEffect, useState } from "react";

export type ThemeChoice = "light" | "dark" | "system";
const KEY = "ck-theme";

export function resolveTheme(choice: ThemeChoice, systemDark: boolean): "light" | "dark" {
  if (choice === "system") return systemDark ? "dark" : "light";
  return choice;
}

export function readChoice(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

function systemPrefersDark(): boolean {
  return typeof window !== "undefined" && !!window.matchMedia?.("(prefers-color-scheme: dark)").matches;
}

export function applyTheme(choice: ThemeChoice): "light" | "dark" {
  const t = resolveTheme(choice, systemPrefersDark());
  document.documentElement.classList.toggle("dark", t === "dark");
  return t;
}

export function useTheme() {
  const [choice, setChoiceState] = useState<ThemeChoice>(readChoice);
  const [resolved, setResolved] = useState<"light" | "dark">(() =>
    resolveTheme(readChoice(), systemPrefersDark()),
  );
  useEffect(() => {
    setResolved(applyTheme(choice));
    if (choice !== "system" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const on = () => setResolved(applyTheme("system"));
    mq.addEventListener?.("change", on);
    return () => mq.removeEventListener?.("change", on);
  }, [choice]);
  const setChoice = useCallback((c: ThemeChoice) => {
    try {
      if (c === "system") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, c);
    } catch {
      /* ignore */
    }
    setChoiceState(c);
  }, []);
  const toggle = useCallback(() => setChoice(resolved === "dark" ? "light" : "dark"), [resolved, setChoice]);
  return { choice, resolved, setChoice, toggle };
}
