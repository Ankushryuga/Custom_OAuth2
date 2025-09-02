// src/LoginApp.tsx
import { useEffect, useState } from "react";

export default function LoginApp() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [msg, setMsg] = useState("");
  const [csrf, setCsrf] = useState<string>("");
  const [loadingCsrf, setLoadingCsrf] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  // NOTE: We use RELATIVE URLs so this works when hosted at the AS under /auth/login
  // If you run this app in dev on a different port, change to absolute:
  // const AS_BASE = "http://localhost:9000";
  // and prefix fetch calls with AS_BASE.
  const CSRF_URL = "/auth/csrf";
  const LOGIN_URL = "/login";

  useEffect(() => {
    let cancelled = false;
    setLoadingCsrf(true);
    fetch(CSRF_URL, { credentials: "include" })
      .then(async (r) => {
        if (!r.ok) throw new Error(`CSRF fetch failed: ${r.status}`);
        const t = await r.json();
        if (!cancelled) setCsrf(t.token as string);
      })
      .catch((err) => {
        if (!cancelled)
          setMsg(
            `Failed to initialize login (CSRF): ${String(err.message || err)}`
          );
      })
      .finally(() => {
        if (!cancelled) setLoadingCsrf(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setMsg("");

    if (!csrf) {
      setMsg("CSRF token not available yet. Please wait and try again.");
      return;
    }

    setSubmitting(true);
    try {
      const body = new URLSearchParams();
      body.set("username", username);
      body.set("password", password);
      body.set("_csrf", csrf); // required

      const res = await fetch(LOGIN_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
          "X-XSRF-TOKEN": csrf, // mirrors the cookie & _csrf body param
        },
        body: body.toString(),
        credentials: "include",
        redirect: "manual", // fetch won't auto-navigate cross-origin
      });

      // Spring usually returns a 302. In fetch, this often appears as an opaqueredirect.
      if (
        res.type === "opaqueredirect" ||
        res.status === 0 ||
        (res.status >= 300 && res.status < 400) ||
        res.redirected
      ) {
        const loc = res.headers.get("Location");
        if (loc) {
          // Navigate the top window to let the browser follow the redirect
          window.location.assign(loc);
          return;
        }
        // Some environments hide Location—force a reload so the browser performs the 302
        window.location.reload();
        return;
      }

      if (res.ok) {
        // Some setups render HTML (200) after login; reloading ensures session is picked up
        window.location.reload();
        return;
      }

      // Friendly error messages
      if (res.status === 401)
        setMsg("Login failed: Unauthorized (check username/password).");
      else if (res.status === 403)
        setMsg("Login failed: Forbidden (CSRF or permissions).");
      else if (res.status >= 500) setMsg("Login failed: Server error.");
      else setMsg(`Login failed: ${res.status} ${res.statusText}`);
    } catch (err: any) {
      setMsg(err?.message ?? "Login failed.");
    } finally {
      setSubmitting(false);
    }
  }

  const disabled = loadingCsrf || submitting;

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-sky-50 flex items-center justify-center p-6">
      <div className="w-full max-w-md rounded-2xl border bg-white/80 backdrop-blur p-6 shadow-lg">
        <div className="mb-6">
          <h1 className="text-xl font-semibold text-slate-900">Sign in</h1>
          <p className="text-sm text-slate-600">
            Use your Authorization Server account
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <label className="block">
            <span className="text-sm text-slate-700">Username</span>
            <input
              className="mt-1 w-full rounded-xl border border-slate-300 px-3 py-2 outline-none focus:ring-2 focus:ring-slate-300"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
              disabled={disabled}
            />
          </label>

          <label className="block">
            <span className="text-sm text-slate-700">Password</span>
            <input
              type="password"
              className="mt-1 w-full rounded-xl border border-slate-300 px-3 py-2 outline-none focus:ring-2 focus:ring-slate-300"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              disabled={disabled}
            />
          </label>

          <button
            type="submit"
            disabled={disabled}
            className={`w-full rounded-xl text-white py-2 font-semibold transition ${
              disabled
                ? "bg-slate-400 cursor-not-allowed"
                : "bg-slate-900 hover:-translate-y-0.5 hover:shadow-md"
            }`}
            title={loadingCsrf ? "Preparing security token..." : undefined}
          >
            {submitting
              ? "Signing in..."
              : loadingCsrf
              ? "Preparing..."
              : "Sign in"}
          </button>

          {msg && (
            <div className="text-center text-sm text-slate-700 bg-slate-100 rounded-xl py-2">
              {msg}
            </div>
          )}
        </form>

        <div className="mt-6 text-xs text-slate-500">
          Having trouble? Ensure cookies aren’t blocked and try again.
        </div>
      </div>
    </div>
  );
}
