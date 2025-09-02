// import { useEffect, useState } from "react";
// import { LogOut, RefreshCw } from "lucide-react";

// interface ClientSummary {
//   clientId: string;
//   clientName: string;
//   publicClient: boolean;
// }

// export default function AdminClients() {
//   const [clients, setClients] = useState<ClientSummary[]>([]);
//   const [loading, setLoading] = useState(true);
//   const [error, setError] = useState("");

//   async function loadClients() {
//     setLoading(true);
//     setError("");
//     try {
//       const res = await fetch("http://localhost:9000/admin/clients", {
//         credentials: "include", // send cookies/session
//       });
//       if (res.status === 401 || res.status === 403) {
//         window.location.href = "http://localhost:9000/auth/login";
//         return;
//       }
//       if (!res.ok) throw new Error(await res.text());
//       setClients(await res.json());
//     } catch (err: any) {
//       setError(err.message);
//     } finally {
//       setLoading(false);
//     }
//   }

//   useEffect(() => {
//     loadClients();
//   }, []);

//   return (
//     <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-200 p-8">
//       <div className="max-w-5xl mx-auto">
//         <header className="flex items-center justify-between mb-8">
//           <h1 className="text-3xl font-bold text-slate-800">
//             OAuth2 Registered Clients
//           </h1>
//           <div className="flex gap-3">
//             <button
//               onClick={loadClients}
//               className="flex items-center gap-2 bg-slate-800 text-white px-4 py-2 rounded-xl hover:bg-slate-700 transition"
//             >
//               <RefreshCw size={18} /> Refresh
//             </button>
//             <a
//               href="http://localhost:9000/logout"
//               className="flex items-center gap-2 bg-red-600 text-white px-4 py-2 rounded-xl hover:bg-red-500 transition"
//             >
//               <LogOut size={18} /> Logout
//             </a>
//           </div>
//         </header>

//         {loading && <p className="text-slate-600">Loading clients…</p>}
//         {error && (
//           <p className="bg-red-100 text-red-700 px-4 py-2 rounded-xl">
//             {error}
//           </p>
//         )}

//         {!loading && clients.length === 0 && (
//           <p className="text-slate-600">
//             No clients registered yet. Use the registration page to add one.
//           </p>
//         )}

//         <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
//           {clients.map((c) => (
//             <div
//               key={c.clientId}
//               className="rounded-2xl bg-white shadow hover:shadow-lg transition p-6 border border-slate-200"
//             >
//               <h2 className="text-xl font-semibold text-slate-800">
//                 {c.clientName}
//               </h2>
//               <p className="text-slate-500 text-sm mb-3">
//                 Client ID:{" "}
//                 <span className="font-mono text-slate-700">{c.clientId}</span>
//               </p>
//               <span
//                 className={`inline-block px-3 py-1 rounded-full text-xs font-medium ${
//                   c.publicClient
//                     ? "bg-green-100 text-green-700"
//                     : "bg-blue-100 text-blue-700"
//                 }`}
//               >
//                 {c.publicClient ? "Public Client" : "Confidential Client"}
//               </span>
//             </div>
//           ))}
//         </div>
//       </div>
//     </div>
//   );
// }

// src/pages/AdminClients.tsx
import { useEffect, useState } from "react";

interface ClientSummary {
  clientId: string;
  clientName: string;
  publicClient: boolean;
}

export default function AdminClients() {
  const [clients, setClients] = useState<ClientSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [csrf, setCsrf] = useState<string>("");

  // load CSRF token when component mounts
  useEffect(() => {
    fetch("http://localhost:9000/auth/csrf", { credentials: "include" })
      .then((r) => r.json())
      .then((t) => setCsrf(t.token))
      .catch((e) => setError("Failed to fetch CSRF token: " + e));
  }, []);

  // load all clients
  useEffect(() => {
    fetch("http://localhost:9000/admin/clients", { credentials: "include" })
      .then((r) => {
        if (!r.ok) throw new Error("Failed to load clients: " + r.status);
        return r.json();
      })
      .then((data) => setClients(data))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  async function registerClient() {
    const payload = {
      clientId: "client-" + Math.random().toString(36).substring(2, 8),
      clientName: "New Client " + new Date().toISOString(),
      redirectUris: ["http://localhost:5173/clients"],
      grantTypes: ["authorization_code", "refresh_token"],
      scopes: ["openid", "profile", "email", "api.read"],
      publicClient: false,
      clientSecret: "client-secret",
    };

    try {
      const res = await fetch("http://localhost:9000/admin/clients", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-XSRF-TOKEN": csrf, // Spring requires cookie + header pair
        },
        credentials: "include",
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error("Failed to register client: " + res.status);
      const newClient = await res.json();
      setClients((prev) => [...prev, newClient]);
    } catch (e: any) {
      setError(e.message);
    }
  }

  if (loading) return <div className="p-6">Loading clients...</div>;
  if (error) return <div className="p-6 text-red-600">Error: {error}</div>;

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-6">Registered Clients</h1>

      <button
        onClick={registerClient}
        className="mb-6 rounded-lg bg-slate-900 px-4 py-2 text-white hover:bg-slate-700"
      >
        + Register New Client
      </button>

      <table className="w-full border-collapse border border-slate-300">
        <thead className="bg-slate-100">
          <tr>
            <th className="border border-slate-300 px-3 py-2 text-left">
              Client ID
            </th>
            <th className="border border-slate-300 px-3 py-2 text-left">
              Client Name
            </th>
            <th className="border border-slate-300 px-3 py-2 text-left">
              Public Client?
            </th>
          </tr>
        </thead>
        <tbody>
          {clients.map((c) => (
            <tr key={c.clientId} className="hover:bg-slate-50">
              <td className="border border-slate-300 px-3 py-2">
                {c.clientId}
              </td>
              <td className="border border-slate-300 px-3 py-2">
                {c.clientName}
              </td>
              <td className="border border-slate-300 px-3 py-2">
                {c.publicClient ? "Yes" : "No"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
