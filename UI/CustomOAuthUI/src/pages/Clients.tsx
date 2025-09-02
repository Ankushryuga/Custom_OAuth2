import { useEffect, useState } from "react";
import { apiFetch, basicAuth, cfg } from "../lib/api";
import { RefreshCw } from "lucide-react";

type ClientSummaryDto = {
  clientId: string;
  clientName: string;
  publicClient: boolean;
};

export default function ClientsPage() {
  const [asBase, setAsBase] = useState(cfg.asBase);
  const [u, setU] = useState(cfg.adminUser);
  const [p, setP] = useState(cfg.adminPass);
  const [rows, setRows] = useState<ClientSummaryDto[]>([]);
  const [err, setErr] = useState<string>("");

  async function load() {
    setErr("");
    try {
      const data = await apiFetch(`${asBase}/admin/clients`, {
        headers: { Authorization: basicAuth(u, p) },
      });
      setRows(data);
    } catch (e: any) {
      setErr(String(e));
      setRows([]);
    }
  }

  useEffect(() => {
    load(); /* eslint-disable-next-line */
  }, []);

  return (
    <div className="space-y-4">
      <div className="rounded-3xl p-6 bg-white border shadow">
        <div className="flex flex-wrap items-end gap-3">
          <Field label="AS Base" value={asBase} setValue={setAsBase} />
          <Field label="Admin User" value={u} setValue={setU} />
          <Field label="Admin Pass" type="password" value={p} setValue={setP} />
          <button
            onClick={load}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 text-white"
          >
            <RefreshCw size={16} /> Refresh
          </button>
        </div>
      </div>

      <div className="rounded-3xl border shadow overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-white">
            <tr>
              <Th>Client ID</Th>
              <Th>Client Name</Th>
              <Th>Type</Th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {rows.map((r) => (
              <tr key={r.clientId} className="bg-white hover:bg-slate-50">
                <Td mono>{r.clientId}</Td>
                <Td>{r.clientName}</Td>
                <Td>
                  <span
                    className={`px-2 py-1 rounded-full text-xs ${
                      r.publicClient
                        ? "bg-amber-100 text-amber-800"
                        : "bg-emerald-100 text-emerald-800"
                    }`}
                  >
                    {r.publicClient ? "Public (PKCE)" : "Confidential"}
                  </span>
                </Td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={3} className="p-6 text-center text-slate-500">
                  {err ? (
                    <span className="text-red-600">{err}</span>
                  ) : (
                    "No clients found yet."
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Field({ label, value, setValue, type = "text" }: any) {
  return (
    <label className="text-sm">
      <div className="text-slate-600">{label}</div>
      <input
        type={type}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        className="mt-1 border rounded-xl px-3 py-2"
      />
    </label>
  );
}
function Th({ children }: any) {
  return <th className="text-left px-4 py-3">{children}</th>;
}
function Td({ children, mono = false }: any) {
  return <td className={`px-4 py-3 ${mono ? "font-mono" : ""}`}>{children}</td>;
}
