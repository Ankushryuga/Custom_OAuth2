import { useEffect, useMemo, useState } from "react";
import { CheckCircle } from "lucide-react";

export default function ClientsDashboard() {
  const [authCode, setAuthCode] = useState<string | null>(null);

  // Read ?code=... (for future PKCE exchange)
  useEffect(() => {
    const u = new URL(window.location.href);
    const code = u.searchParams.get("code");
    setAuthCode(code);
  }, []);

  const state = useMemo(() => {
    const u = new URL(window.location.href);
    return u.searchParams.get("state");
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-emerald-50 via-white to-teal-50 p-8">
      <div className="max-w-2xl mx-auto rounded-3xl border border-emerald-200 bg-white p-8 shadow-lg">
        <div className="flex items-center gap-3">
          <CheckCircle className="text-emerald-600" />
          <h1 className="text-2xl font-bold text-slate-900">
            Welcome to Clients Dashboard
          </h1>
        </div>
        <p className="mt-3 text-slate-600">
          You were redirected here as your <code>redirect_uri</code>. If this
          page shows, your OAuth login and redirect worked.
        </p>

        <div className="mt-6 rounded-2xl bg-slate-50 p-4 text-sm">
          <div className="font-semibold text-slate-700 mb-2">
            Authorization Response
          </div>
          <div className="space-y-1">
            <div>
              code: <code>{authCode ?? "(none)"}</code>
            </div>
            <div>
              state: <code>{state ?? "(none)"}</code>
            </div>
          </div>
          <p className="mt-3 text-slate-600">
            Next: exchange the code for tokens (PKCE recommended for SPA) or
            route the user to your actual client list UI.
          </p>
        </div>
      </div>
    </div>
  );
}
