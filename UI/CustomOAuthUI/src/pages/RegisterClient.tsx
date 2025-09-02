// import { useState } from "react";
// import { apiFetch, basicAuth, cfg } from "../lib/api";
// import { PlusCircle } from "lucide-react";

// export default function RegisterClientPage() {
//   const [asBase, setAsBase] = useState(cfg.asBase);
//   const [adminUser, setAdminUser] = useState(cfg.adminUser);
//   const [adminPass, setAdminPass] = useState(cfg.adminPass);
//   const [dcrToken, setDcrToken] = useState(cfg.dcrToken);

//   const [clientId, setClientId] = useState("my-web-app");
//   const [clientName, setClientName] = useState("My Web App");
//   const [redirectUris, setRedirectUris] = useState(cfg.redirectUri);
//   const [scopes, setScopes] = useState(cfg.scopes);
//   const [isPublic, setIsPublic] = useState(false);

//   const [out, setOut] = useState<string>("");

//   async function registerAdmin() {
//     setOut("...");
//     const payload = {
//       clientId,
//       clientName,
//       redirectUris: splitLines(redirectUris),
//       grantTypes: ["authorization_code", "refresh_token"],
//       scopes: scopes.split(/\s+/).filter(Boolean),
//       publicClient: isPublic,
//     };
//     const res = await apiFetch(`${asBase}/admin/clients`, {
//       method: "POST",
//       headers: {
//         "Content-Type": "application/json",
//         Authorization: basicAuth(adminUser, adminPass),
//       },
//       body: JSON.stringify(payload),
//     });
//     setOut(JSON.stringify(res, null, 2));
//   }

//   async function registerDcr() {
//     setOut("...");
//     const payload = {
//       client_name: clientName || clientId,
//       redirect_uris: splitLines(redirectUris),
//       grant_types: ["authorization_code", "refresh_token"],
//       response_types: ["code"],
//       scope: scopes,
//       token_endpoint_auth_method: isPublic ? "none" : "client_secret_basic",
//     };
//     const res = await apiFetch(`${asBase}/connect/register`, {
//       method: "POST",
//       headers: {
//         "Content-Type": "application/json",
//         "X-Initial-Access": dcrToken, // your server strips optional 'Bearer ' if you want to send it
//       },
//       body: JSON.stringify(payload),
//     });
//     setOut(JSON.stringify(res, null, 2));
//   }

//   return (
//     <div className="grid md:grid-cols-2 gap-8">
//       <div className="rounded-3xl p-6 bg-white border shadow">
//         <h1 className="text-xl font-semibold mb-4">Register via Admin API</h1>

//         <Section title="Server & Admin">
//           <Input label="AS Base" value={asBase} setValue={setAsBase} />
//           <div className="grid grid-cols-2 gap-3">
//             <Input
//               label="Admin Username"
//               value={adminUser}
//               setValue={setAdminUser}
//             />
//             <Input
//               label="Admin Password"
//               type="password"
//               value={adminPass}
//               setValue={setAdminPass}
//             />
//           </div>
//         </Section>

//         <Section title="Client">
//           <div className="grid grid-cols-2 gap-3">
//             <Input label="Client ID" value={clientId} setValue={setClientId} />
//             <Input
//               label="Client Name"
//               value={clientName}
//               setValue={setClientName}
//             />
//           </div>
//           <Textarea
//             label="Redirect URIs (comma/newline)"
//             value={redirectUris}
//             setValue={setRedirectUris}
//           />
//           <Input
//             label="Scopes (space-separated)"
//             value={scopes}
//             setValue={setScopes}
//           />
//           <label className="inline-flex items-center gap-2 mt-2">
//             <input
//               type="checkbox"
//               checked={isPublic}
//               onChange={(e) => setIsPublic(e.target.checked)}
//             />
//             <span>Public (PKCE, no secret)</span>
//           </label>
//         </Section>

//         <div className="mt-4 flex gap-3">
//           <Button onClick={registerAdmin} icon={<PlusCircle size={16} />}>
//             Create via Admin API
//           </Button>
//           <Button onClick={registerDcr} variant="secondary">
//             Create via DCR
//           </Button>
//         </div>
//       </div>

//       <div className="rounded-3xl p-6 bg-slate-900 text-slate-50 shadow">
//         <h2 className="text-lg font-semibold mb-2">Response</h2>
//         <pre className="bg-black/40 rounded-xl p-4 text-xs overflow-auto min-h-[360px]">
//           {out || "// results will appear here"}
//         </pre>

//         <Section title="DCR Token" dark>
//           <Input
//             label="X-Initial-Access"
//             value={dcrToken}
//             setValue={setDcrToken}
//           />
//         </Section>
//       </div>
//     </div>
//   );
// }

// function splitLines(str: string) {
//   return str
//     .split(/\n|,/)
//     .map((s) => s.trim())
//     .filter(Boolean);
// }

// function Section({
//   title,
//   children,
//   dark = false,
// }: {
//   title: string;
//   children: any;
//   dark?: boolean;
// }) {
//   return (
//     <div className={`mt-4 ${dark ? "" : ""}`}>
//       <div
//         className={`text-sm font-semibold ${
//           dark ? "text-slate-200" : "text-slate-700"
//         }`}
//       >
//         {title}
//       </div>
//       <div className="mt-2 space-y-3">{children}</div>
//     </div>
//   );
// }

// function Input({ label, value, setValue, type = "text" }: any) {
//   return (
//     <label className="block">
//       <span className="text-sm text-slate-600">{label}</span>
//       <input
//         type={type}
//         value={value}
//         onChange={(e) => setValue(e.target.value)}
//         className="mt-1 w-full border rounded-xl px-3 py-2 focus:outline-none focus:ring"
//       />
//     </label>
//   );
// }

// function Textarea({ label, value, setValue }: any) {
//   return (
//     <label className="block">
//       <span className="text-sm text-slate-600">{label}</span>
//       <textarea
//         value={value}
//         onChange={(e) => setValue(e.target.value)}
//         rows={4}
//         className="mt-1 w-full border rounded-xl px-3 py-2 focus:outline-none focus:ring"
//       />
//     </label>
//   );
// }

// function Button({ children, onClick, icon, variant = "primary" }: any) {
//   const cls =
//     variant === "primary"
//       ? "bg-emerald-600 hover:bg-emerald-700 text-white"
//       : "bg-slate-700 hover:bg-slate-800 text-white";
//   return (
//     <button
//       onClick={onClick}
//       className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl ${cls}`}
//     >
//       {icon}
//       {children}
//     </button>
//   );
// }
// src/pages/RegisterClientPage.tsx
import { useState } from "react";
import { apiFetch, basicAuth, cfg, getCsrfToken } from "../lib/api";
import { PlusCircle } from "lucide-react";

export default function RegisterClientPage() {
  const [asBase, setAsBase] = useState(cfg.asBase);
  const [adminUser, setAdminUser] = useState(cfg.adminUser);
  const [adminPass, setAdminPass] = useState(cfg.adminPass);
  const [dcrToken, setDcrToken] = useState(cfg.dcrToken);

  const [clientId, setClientId] = useState("my-web-app");
  const [clientName, setClientName] = useState("My Web App");
  const [redirectUris, setRedirectUris] = useState(cfg.redirectUri);
  const [scopes, setScopes] = useState(cfg.scopes);
  const [isPublic, setIsPublic] = useState(false);

  const [out, setOut] = useState<string>("");

  async function registerAdmin() {
    try {
      setOut("…");
      const payload = {
        clientId,
        clientName,
        redirectUris: splitLines(redirectUris),
        grantTypes: ["authorization_code", "refresh_token"],
        scopes: scopes.split(/\s+/).filter(Boolean),
        publicClient: isPublic,
      };

      // fetch CSRF up front (optional; apiFetch can auto-fetch for POST)
      const csrf = await getCsrfToken(asBase);

      const res = await apiFetch(`${asBase}/admin/clients`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: basicAuth(adminUser, adminPass),
        },
        body: JSON.stringify(payload),
        csrf, // ensure header is set and cookie is present
      });

      setOut(JSON.stringify(res, null, 2));
    } catch (e: any) {
      setOut("ERROR: " + (e?.message || String(e)));
    }
  }

  async function registerDcr() {
    try {
      setOut("…");
      const payload = {
        client_name: clientName || clientId,
        redirect_uris: splitLines(redirectUris),
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: scopes,
        token_endpoint_auth_method: isPublic ? "none" : "client_secret_basic",
      };

      // /connect/register in your server is typically CSRF-ignored; if not, remove csrf:false to include token.
      const res = await apiFetch(`${asBase}/connect/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Initial-Access": dcrToken,
        },
        body: JSON.stringify(payload),
        csrf: false, // <-- disable CSRF header for this call if your server ignores CSRF here
      });

      setOut(JSON.stringify(res, null, 2));
    } catch (e: any) {
      setOut("ERROR: " + (e?.message || String(e)));
    }
  }

  return (
    <div className="grid md:grid-cols-2 gap-8">
      <div className="rounded-3xl p-6 bg-white border shadow">
        <h1 className="text-xl font-semibold mb-4">Register via Admin API</h1>

        <Section title="Server & Admin">
          <Input label="AS Base" value={asBase} setValue={setAsBase} />
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Admin Username"
              value={adminUser}
              setValue={setAdminUser}
            />
            <Input
              label="Admin Password"
              type="password"
              value={adminPass}
              setValue={setAdminPass}
            />
          </div>
        </Section>

        <Section title="Client">
          <div className="grid grid-cols-2 gap-3">
            <Input label="Client ID" value={clientId} setValue={setClientId} />
            <Input
              label="Client Name"
              value={clientName}
              setValue={setClientName}
            />
          </div>
          <Textarea
            label="Redirect URIs (comma/newline)"
            value={redirectUris}
            setValue={setRedirectUris}
          />
          <Input
            label="Scopes (space-separated)"
            value={scopes}
            setValue={setScopes}
          />
          <label className="inline-flex items-center gap-2 mt-2">
            <input
              type="checkbox"
              checked={isPublic}
              onChange={(e) => setIsPublic(e.target.checked)}
            />
            <span>Public (PKCE, no secret)</span>
          </label>
        </Section>

        <div className="mt-4 flex gap-3">
          <Button onClick={registerAdmin} icon={<PlusCircle size={16} />}>
            Create via Admin API
          </Button>
          <Button onClick={registerDcr} variant="secondary">
            Create via DCR
          </Button>
        </div>
      </div>

      <div className="rounded-3xl p-6 bg-slate-900 text-slate-50 shadow">
        <h2 className="text-lg font-semibold mb-2">Response</h2>
        <pre className="bg-black/40 rounded-xl p-4 text-xs overflow-auto min-h-[360px]">
          {out || "// results will appear here"}
        </pre>

        <Section title="DCR Token" dark>
          <Input
            label="X-Initial-Access"
            value={dcrToken}
            setValue={setDcrToken}
          />
        </Section>
      </div>
    </div>
  );
}

function splitLines(str: string) {
  return str
    .split(/\n|,/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function Section({
  title,
  children,
  dark = false,
}: {
  title: string;
  children: any;
  dark?: boolean;
}) {
  return (
    <div className={`mt-4 ${dark ? "" : ""}`}>
      <div
        className={`text-sm font-semibold ${
          dark ? "text-slate-200" : "text-slate-700"
        }`}
      >
        {title}
      </div>
      <div className="mt-2 space-y-3">{children}</div>
    </div>
  );
}

function Input({ label, value, setValue, type = "text" }: any) {
  return (
    <label className="block">
      <span className="text-sm text-slate-600">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        className="mt-1 w-full border rounded-xl px-3 py-2 focus:outline-none focus:ring"
      />
    </label>
  );
}

function Textarea({ label, value, setValue }: any) {
  return (
    <label className="block">
      <span className="text-sm text-slate-600">{label}</span>
      <textarea
        value={value}
        onChange={(e) => setValue(e.target.value)}
        rows={4}
        className="mt-1 w-full border rounded-xl px-3 py-2 focus:outline-none focus:ring"
      />
    </label>
  );
}

function Button({ children, onClick, icon, variant = "primary" }: any) {
  const cls =
    variant === "primary"
      ? "bg-emerald-600 hover:bg-emerald-700 text-white"
      : "bg-slate-700 hover:bg-slate-800 text-white";
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl ${cls}`}
    >
      {icon}
      {children}
    </button>
  );
}
