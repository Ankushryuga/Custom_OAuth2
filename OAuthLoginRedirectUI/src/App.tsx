import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import LoginPage from "./pages/LoginApp";
import AdminClients from "./pages/AdminClients";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Root goes to login */}
        <Route path="/" element={<LoginPage />} />

        {/* Admin clients list */}
        <Route path="/admin/clients" element={<AdminClients />} />

        {/* Catch-all: redirect unknown paths to login */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
