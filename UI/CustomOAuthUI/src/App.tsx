import { Routes, Route, NavLink, Navigate } from "react-router-dom";
import LoginPage from "./pages/LoginPage";
import RegisterClientPage from "./pages/RegisterClient";
import ClientsPage from "./pages/Clients";
import { Settings } from "lucide-react";
import ClientsDashboard from "./pages/ClientsDashboard";

export default function App() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 text-slate-900">
      <nav className="sticky top-0 z-10 backdrop-blur bg-white/70 border-b border-slate-200">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4">
          <div className="font-semibold tracking-tight">OAuth2 Admin</div>
          <div className="flex-1" />
          <NavLink className={link} to="/">
            Login
          </NavLink>
          <NavLink className={link} to="/register">
            Register Client
          </NavLink>
          <NavLink className={link} to="/clients">
            All Clients
          </NavLink>
          <a
            className="inline-flex items-center gap-1 text-slate-600 hover:text-slate-900"
            href="http://localhost:9000/.well-known/openid-configuration"
            target="_blank"
          >
            <Settings size={16} /> OIDC
          </a>
        </div>
      </nav>
      <main className="max-w-6xl mx-auto px-4 py-8">
        <Routes>
          <Route path="/" element={<LoginPage />} />
          <Route path="/dashboard" element={<ClientsDashboard />} />
          <Route path="/register" element={<RegisterClientPage />} />
          <Route path="/clients" element={<ClientsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <footer className="text-center text-xs text-slate-500 py-8">
        © {new Date().getFullYear()} OAuth2 Admin UI
      </footer>
    </div>
  );
}

const link = ({ isActive }: { isActive: boolean }) =>
  `px-3 py-1 rounded-lg text-sm ${
    isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-200"
  }`;
