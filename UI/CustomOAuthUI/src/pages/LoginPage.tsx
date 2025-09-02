// // import { useMemo, useState } from "react";
// // import { cfg } from "../lib/api";
// // import { ExternalLink, LogIn, Shield, Sparkles } from "lucide-react";

// // export default function LoginPage() {
// //   const [clientId, setClientId] = useState(cfg.clientId);
// //   const [redirectUri, setRedirectUri] = useState(cfg.redirectUri);
// //   const [scopes, setScopes] = useState(cfg.scopes);

// //   const authorizeUrl = useMemo(() => {
// //     const p = new URLSearchParams({
// //       response_type: "code",
// //       client_id: clientId.trim(),
// //       scope: scopes.trim(),
// //       redirect_uri: redirectUri.trim(),
// //       state: crypto.getRandomValues(new Uint32Array(1))[0].toString(16),
// //       nonce: crypto.getRandomValues(new Uint32Array(1))[0].toString(16),
// //     });
// //     return `${cfg.asBase}/oauth2/authorize?${p.toString()}`;
// //   }, [clientId, redirectUri, scopes]);

// //   return (
// //     <div className="relative min-h-[70vh]">
// //       {/* background */}
// //       <div className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-br from-indigo-50 via-white to-sky-50" />
// //       <div className="pointer-events-none absolute -top-20 -left-24 h-64 w-64 rounded-full bg-indigo-200/30 blur-3xl" />
// //       <div className="pointer-events-none absolute -bottom-16 -right-24 h-64 w-64 rounded-full bg-sky-200/30 blur-3xl" />

// //       <header className="mb-8 flex items-center gap-3">
// //         <div className="inline-flex h-10 w-10 items-center justify-center rounded-2xl bg-slate-900 text-white">
// //           <Shield size={18} />
// //         </div>
// //         <div>
// //           <h1 className="text-xl font-semibold tracking-tight text-slate-900">
// //             OAuth2 Login
// //           </h1>
// //           <p className="text-sm text-slate-600">
// //             Sign in to your Authorization Server or craft an authorization
// //             request.
// //           </p>
// //         </div>
// //       </header>

// //       <div className="grid gap-8 md:grid-cols-2">
// //         {/* Left: form card */}
// //         <div className="group relative rounded-3xl border border-slate-200/70 bg-white/80 p-6 shadow-lg backdrop-blur-sm transition hover:shadow-xl">
// //           <div className="absolute -right-2 -top-2 rounded-xl bg-slate-900 px-2 py-1 text-xs text-white">
// //             <span className="inline-flex items-center gap-1">
// //               <Sparkles size={12} /> Quick Start
// //             </span>
// //           </div>

// //           <div className="mb-6">
// //             <h2 className="text-lg font-semibold text-slate-900">
// //               Authorization Request
// //             </h2>
// //             <p className="text-sm text-slate-600">
// //               Fill the fields below and click{" "}
// //               <span className="font-medium">Authorize</span>.
// //             </p>
// //           </div>

// //           <div className="space-y-4">
// //             <Field
// //               label="Client ID"
// //               value={clientId}
// //               onChange={setClientId}
// //               placeholder="client-app"
// //             />
// //             <Field
// //               label="Redirect URI"
// //               value={redirectUri}
// //               onChange={setRedirectUri}
// //               placeholder="http://localhost:8082/login/oauth2/code/client-app"
// //             />
// //             <Field
// //               label="Scopes"
// //               value={scopes}
// //               onChange={setScopes}
// //               placeholder="openid profile email api.read"
// //             />
// //             <div className="rounded-xl bg-slate-50 p-3 text-xs text-slate-600">
// //               <div className="font-medium text-slate-700 mb-1">Preview URL</div>
// //               <div className="break-all">{authorizeUrl}</div>
// //             </div>
// //           </div>

// //           <div className="mt-6 flex flex-wrap gap-3">
// //             <a
// //               href={`${cfg.asBase}/login`}
// //               target="_blank"
// //               className="inline-flex items-center gap-2 rounded-xl bg-slate-900 px-4 py-2 text-white transition hover:-translate-y-0.5 hover:shadow-md active:translate-y-0"
// //             >
// //               <LogIn size={16} /> Open /login
// //             </a>
// //             <a
// //               href={authorizeUrl}
// //               target="_blank"
// //               className="inline-flex items-center gap-2 rounded-xl bg-slate-800 px-4 py-2 text-white transition hover:-translate-y-0.5 hover:shadow-md active:translate-y-0"
// //             >
// //               <ExternalLink size={16} /> Authorize
// //             </a>
// //           </div>
// //         </div>

// //         {/* Right: tips / help */}
// //         <div className="rounded-3xl border border-slate-200/70 bg-slate-900 text-white shadow-lg">
// //           <div className="space-y-4 p-6">
// //             <h3 className="text-lg font-semibold">Tips</h3>
// //             <ul className="list-disc space-y-2 pl-5 text-slate-200">
// //               <li>
// //                 Use the same hostnames you registered as{" "}
// //                 <span className="font-medium">redirect_uris</span> (e.g.{" "}
// //                 <code className="rounded bg-black/40 px-1.5 py-0.5">
// //                   http://localhost:8082
// //                 </code>
// //                 ).
// //               </li>
// //               <li>
// //                 If you changed redirect URIs or client settings, clear cookies
// //                 on both ports.
// //               </li>
// //               <li>
// //                 Verify endpoints at{" "}
// //                 <a
// //                   className="underline decoration-slate-400/60 underline-offset-2 hover:text-sky-300"
// //                   href={`${cfg.asBase}/.well-known/openid-configuration`}
// //                   target="_blank"
// //                 >
// //                   /.well-known/openid-configuration
// //                 </a>
// //                 .
// //               </li>
// //             </ul>

// //             <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-4">
// //               <p className="text-sm text-slate-200">
// //                 Need a client quickly? Use the{" "}
// //                 <span className="font-medium">Register Client</span> page to
// //                 create one via Admin API or DCR, then come back here to test the
// //                 flow.
// //               </p>
// //             </div>

// //             <div className="grid grid-cols-2 gap-3 pt-2 text-xs text-slate-300">
// //               <Info label="AS Base" value={cfg.asBase} />
// //               <Info label="Default Scopes" value={cfg.scopes} />
// //             </div>
// //           </div>
// //         </div>
// //       </div>
// //     </div>
// //   );
// // }

// // /* ---------- tiny UI helpers ---------- */

// // function Field({
// //   label,
// //   value,
// //   onChange,
// //   placeholder,
// // }: {
// //   label: string;
// //   value: string;
// //   onChange: (v: string) => void;
// //   placeholder?: string;
// // }) {
// //   return (
// //     <label className="block">
// //       <span className="text-sm text-slate-700">{label}</span>
// //       <input
// //         value={value}
// //         onChange={(e) => onChange(e.target.value)}
// //         placeholder={placeholder}
// //         className="mt-1 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 outline-none ring-slate-300 placeholder:text-slate-400 focus:border-slate-400 focus:ring-2"
// //       />
// //     </label>
// //   );
// // }

// // function Info({ label, value }: { label: string; value: string }) {
// //   return (
// //     <div className="rounded-lg bg-white/5 px-3 py-2">
// //       <div className="text-[10px] uppercase tracking-wide text-slate-400">
// //         {label}
// //       </div>
// //       <div className="truncate text-xs text-slate-200">{value}</div>
// //     </div>
// //   );
// // }

// import { useMemo, useState } from "react";
// import { cfg } from "../lib/api";
// import { ExternalLink, LogIn, Shield, Sparkles } from "lucide-react";

// const REDIRECT_URI = "http://localhost:5173/clients"; // must be registered in AS

// export default function LoginPage() {
//   const [clientId, setClientId] = useState(cfg.clientId);
//   const [scopes, setScopes] = useState(cfg.scopes);

//   // Always build absolute URLs so SPA/router/base tags can't rewrite them
//   const asLoginUrl = useMemo(
//     () => new URL("/oauth/login", cfg.asBase).toString(),
//     []
//   );

//   const authorizeUrl = useMemo(() => {
//     const params = new URLSearchParams({
//       response_type: "code",
//       client_id: clientId.trim(),
//       scope: scopes.trim(),
//       redirect_uri: REDIRECT_URI, // ABSOLUTE, registered in AS
//       state: crypto.getRandomValues(new Uint32Array(1))[0].toString(16),
//       nonce: crypto.getRandomValues(new Uint32Array(1))[0].toString(16),
//       // For a public SPA with token exchange in browser, add PKCE:
//       // code_challenge: <value>,
//       // code_challenge_method: "S256",
//     });
//     return new URL(
//       `/oauth2/authorize?${params.toString()}`,
//       cfg.asBase
//     ).toString();
//   }, [clientId, scopes]);

//   function openASLogin() {
//     window.location.assign(asLoginUrl);
//   }

//   function beginAuthorize() {
//     window.location.assign(authorizeUrl);
//   }

//   return (
//     <div className="relative min-h-[70vh]">
//       {/* background */}
//       <div className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-br from-indigo-50 via-white to-sky-50" />
//       <div className="pointer-events-none absolute -top-20 -left-24 h-64 w-64 rounded-full bg-indigo-200/30 blur-3xl" />
//       <div className="pointer-events-none absolute -bottom-16 -right-24 h-64 w-64 rounded-full bg-sky-200/30 blur-3xl" />

//       <header className="mb-8 flex items-center gap-3">
//         <div className="inline-flex h-10 w-10 items-center justify-center rounded-2xl bg-slate-900 text-white">
//           <Shield size={18} />
//         </div>
//         <div>
//           <h1 className="text-xl font-semibold tracking-tight text-slate-900">
//             OAuth2 Login
//           </h1>
//           <p className="text-sm text-slate-600">
//             Sign in to your Authorization Server or craft an authorization
//             request.
//           </p>
//         </div>
//       </header>

//       <div className="grid gap-8 md:grid-cols-2">
//         {/* Left: form card */}
//         <div className="group relative rounded-3xl border border-slate-200/70 bg-white/80 p-6 shadow-lg backdrop-blur-sm transition hover:shadow-xl">
//           <div className="absolute -right-2 -top-2 rounded-xl bg-slate-900 px-2 py-1 text-xs text-white">
//             <span className="inline-flex items-center gap-1">
//               <Sparkles size={12} /> Quick Start
//             </span>
//           </div>

//           <div className="mb-6">
//             <h2 className="text-lg font-semibold text-slate-900">
//               Authorization Request
//             </h2>
//             <p className="text-sm text-slate-600">
//               Fill the fields below and click{" "}
//               <span className="font-medium">Authorize</span>.
//             </p>
//           </div>

//           <div className="space-y-4">
//             <Field
//               label="Client ID"
//               value={clientId}
//               onChange={setClientId}
//               placeholder="client-app"
//             />
//             <Field
//               label="Scopes"
//               value={scopes}
//               onChange={setScopes}
//               placeholder="openid profile email api.read"
//             />
//             <div className="rounded-xl bg-slate-50 p-3 text-xs text-slate-600">
//               <div className="font-medium text-slate-700 mb-1">Preview URL</div>
//               <div className="break-all">{authorizeUrl}</div>
//               <div className="mt-2 text-slate-500">
//                 Redirect URI:{" "}
//                 <code className="bg-white/70 px-1 rounded">{REDIRECT_URI}</code>
//               </div>
//             </div>
//           </div>

//           <div className="mt-6 flex flex-wrap gap-3">
//             <button
//               type="button"
//               onClick={openASLogin}
//               className="inline-flex items-center gap-2 rounded-xl bg-slate-900 px-4 py-2 text-white transition hover:-translate-y-0.5 hover:shadow-md"
//             >
//               <LogIn size={16} /> Open /login
//             </button>
//             <button
//               type="button"
//               onClick={beginAuthorize}
//               className="inline-flex items-center gap-2 rounded-xl bg-slate-800 px-4 py-2 text-white transition hover:-translate-y-0.5 hover:shadow-md"
//             >
//               <ExternalLink size={16} /> Authorize
//             </button>
//           </div>
//         </div>

//         {/* Right: tips / help */}
//         <div className="rounded-3xl border border-slate-200/70 bg-slate-900 text-white shadow-lg">
//           <div className="space-y-4 p-6">
//             <h3 className="text-lg font-semibold">Tips</h3>
//             <ul className="list-disc space-y-2 pl-5 text-slate-200">
//               <li>
//                 Ensure <code>redirect_uri</code> matches exactly what’s
//                 registered on the AS:
//                 <div className="mt-1">
//                   <code className="rounded bg-black/40 px-1.5 py-0.5">
//                     {REDIRECT_URI}
//                   </code>
//                 </div>
//               </li>
//               <li>
//                 If you changed redirect URIs or client settings, clear cookies.
//               </li>
//               <li>
//                 Verify endpoints at{" "}
//                 <a
//                   className="underline decoration-slate-400/60 underline-offset-2 hover:text-sky-300"
//                   href={`${cfg.asBase}/.well-known/openid-configuration`}
//                   target="_blank"
//                 >
//                   /.well-known/openid-configuration
//                 </a>
//                 .
//               </li>
//             </ul>
//             <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-4">
//               <p className="text-sm text-slate-200">
//                 After successful login & code redirect, handle token exchange
//                 (PKCE) or just land on your dashboard.
//               </p>
//             </div>
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// }

// function Field({
//   label,
//   value,
//   onChange,
//   placeholder,
// }: {
//   label: string;
//   value: string;
//   onChange: (v: string) => void;
//   placeholder?: string;
// }) {
//   return (
//     <label className="block">
//       <span className="text-sm text-slate-700">{label}</span>
//       <input
//         value={value}
//         onChange={(e) => onChange(e.target.value)}
//         placeholder={placeholder}
//         className="mt-1 w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-slate-900 outline-none ring-slate-300 placeholder:text-slate-400 focus:border-slate-400 focus:ring-2"
//       />
//     </label>
//   );
// }

import { useMemo, useState } from "react";
import { cfg } from "../lib/api";
import { ExternalLink, LogIn, Shield, Sparkles } from "lucide-react";

const REDIRECT_URI = "http://localhost:5173/clients"; // must be registered in AS

export default function LoginPage() {
  const [clientId, setClientId] = useState(cfg.clientId);
  const [scopes, setScopes] = useState(cfg.scopes);

  const asLoginUrl = useMemo(
    () => new URL("/oauth/login", cfg.asBase).toString(),
    []
  );

  const authorizeUrl = useMemo(() => {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: clientId.trim(),
      scope: scopes.trim(),
      redirect_uri: REDIRECT_URI,
      state: crypto.getRandomValues(new Uint32Array(1))[0].toString(16),
      nonce: crypto.getRandomValues(new Uint32Array(1))[0].toString(16),
    });
    return new URL(
      `/oauth2/authorize?${params.toString()}`,
      cfg.asBase
    ).toString();
  }, [clientId, scopes]);

  return (
    <div
      style={{ maxWidth: 720, margin: "3rem auto", fontFamily: "system-ui" }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          marginBottom: 24,
        }}
      >
        <div
          style={{
            width: 40,
            height: 40,
            display: "grid",
            placeItems: "center",
            borderRadius: 12,
            background: "#0f172a",
            color: "#fff",
          }}
        >
          <Shield size={18} />
        </div>
        <div>
          <h1 style={{ fontSize: 20, margin: 0 }}>OAuth2 Login</h1>
          <p style={{ color: "#475569", margin: 0 }}>
            Sign in or craft an authorization request.
          </p>
        </div>
      </header>

      <div style={{ display: "grid", gap: 24, gridTemplateColumns: "1fr 1fr" }}>
        <div
          style={{ border: "1px solid #e2e8f0", borderRadius: 16, padding: 16 }}
        >
          <div style={{ marginBottom: 12, fontWeight: 600 }}>
            Authorization Request
          </div>
          <label style={{ display: "block", marginBottom: 8 }}>
            <div style={{ fontSize: 12, color: "#334155" }}>Client ID</div>
            <input
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              style={{
                width: "100%",
                padding: "8px 10px",
                borderRadius: 10,
                border: "1px solid #cbd5e1",
              }}
            />
          </label>
          <label style={{ display: "block", marginBottom: 8 }}>
            <div style={{ fontSize: 12, color: "#334155" }}>Scopes</div>
            <input
              value={scopes}
              onChange={(e) => setScopes(e.target.value)}
              style={{
                width: "100%",
                padding: "8px 10px",
                borderRadius: 10,
                border: "1px solid #cbd5e1",
              }}
            />
          </label>

          <div
            style={{
              fontSize: 12,
              color: "#64748b",
              background: "#f8fafc",
              padding: 8,
              borderRadius: 10,
              wordBreak: "break-all",
            }}
          >
            <div style={{ fontWeight: 600, color: "#334155" }}>Preview URL</div>
            {authorizeUrl}
            <div style={{ marginTop: 6 }}>
              Redirect URI: <code>{REDIRECT_URI}</code>
            </div>
          </div>

          <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
            <button
              onClick={() => window.location.assign(asLoginUrl)}
              style={{
                background: "#0f172a",
                color: "#fff",
                borderRadius: 10,
                padding: "8px 12px",
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
              }}
            >
              <LogIn size={16} /> Open /login
            </button>
            <button
              onClick={() => window.location.assign(authorizeUrl)}
              style={{
                background: "#1e293b",
                color: "#fff",
                borderRadius: 10,
                padding: "8px 12px",
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
              }}
            >
              <ExternalLink size={16} /> Authorize
            </button>
          </div>
        </div>

        <div
          style={{
            border: "1px solid #0b1220",
            background: "#0b1220",
            color: "#fff",
            borderRadius: 16,
            padding: 16,
          }}
        >
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              background: "#111827",
              borderRadius: 8,
              padding: "4px 8px",
              marginBottom: 10,
              fontSize: 12,
            }}
          >
            <Sparkles size={12} /> Tips
          </div>
          <ul style={{ margin: 0, paddingLeft: 18, color: "#cbd5e1" }}>
            <li>
              Ensure <code>redirect_uri</code> matches exactly what’s
              registered.
            </li>
            <li>Clear cookies if you changed client/redirect URIs.</li>
            <li>
              Verify endpoints at{" "}
              <a
                href={`${cfg.asBase}/.well-known/openid-configuration`}
                target="_blank"
                style={{ color: "#7dd3fc" }}
              >
                /.well-known/openid-configuration
              </a>
              .
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
