// export const cfg = {
//   asBase: import.meta.env.VITE_AS_BASE || "http://localhost:9000",
//   adminUser: import.meta.env.VITE_ADMIN_USER || "admin",
//   adminPass: import.meta.env.VITE_ADMIN_PASS || "admin123",
//   dcrToken: import.meta.env.VITE_DCR_TOKEN || "dev-dcr-token-123",
//   clientId: import.meta.env.VITE_CLIENT_ID || "client-app",
//   redirectUri:
//     import.meta.env.VITE_REDIRECT_URI ||
//     "http://localhost:8082/login/oauth2/code/client-app",
//   scopes: import.meta.env.VITE_SCOPES || "openid profile email api.read",
// };

// export const basicAuth = (u: string, p: string) => "Basic " + btoa(`${u}:${p}`);

// export async function apiFetch(
//   path: string,
//   init: RequestInit = {},
//   parseJson = true
// ) {
//   const res = await fetch(path, init);
//   const text = await res.text();
//   if (!res.ok) {
//     throw new Error(`${res.status} ${res.statusText}\n${text}`);
//   }
//   return parseJson ? (text ? JSON.parse(text) : null) : text;
// }
// src/lib/api.ts
export const cfg = {
  asBase: import.meta.env.VITE_AS_BASE || "http://localhost:9000",
  adminUser: import.meta.env.VITE_ADMIN_USER || "admin",
  adminPass: import.meta.env.VITE_ADMIN_PASS || "admin123",
  dcrToken: import.meta.env.VITE_DCR_TOKEN || "dev-dcr-token-123",
  clientId: import.meta.env.VITE_CLIENT_ID || "client-app",
  redirectUri:
    import.meta.env.VITE_REDIRECT_URI ||
    "http://localhost:8082/login/oauth2/code/client-app",
  scopes: import.meta.env.VITE_SCOPES || "openid profile email api.read",
};

export const basicAuth = (u: string, p: string) => "Basic " + btoa(`${u}:${p}`);

export async function getCsrfToken(asBase = cfg.asBase): Promise<string> {
  const r = await fetch(`${asBase}/auth/csrf`, { credentials: "include" });
  if (!r.ok) throw new Error(`CSRF fetch failed: ${r.status}`);
  const t = await r.json();
  return t.token as string;
}

type ApiInit = RequestInit & { csrf?: string | false };

export async function apiFetch(
  url: string,
  init: ApiInit = {},
  parseJson = true
) {
  const finalInit: RequestInit = {
    credentials: "include", // ALWAYS include cookies
    ...init,
    headers: {
      ...(init.headers || {}),
    },
  };

  // If csrf === false, skip. If string, use it. If undefined, try to add automatically for state-changing methods.
  const method = (finalInit.method || "GET").toUpperCase();
  if (
    init.csrf !== false &&
    ["POST", "PUT", "PATCH", "DELETE"].includes(method)
  ) {
    const token =
      typeof init.csrf === "string"
        ? init.csrf
        : await getCsrfToken(new URL(url, cfg.asBase).origin);
    (finalInit.headers as Record<string, string>)["X-XSRF-TOKEN"] = token;
  }

  const res = await fetch(url, finalInit);
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}\n${text}`);
  }
  return parseJson ? (text ? JSON.parse(text) : null) : text;
}
