// React Login Component
// Create this file: src/components/Login.jsx

import React, { useState, useEffect } from "react";
import authService from "../services/authService";

const Login = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    checkAuthStatus();

    // Handle OAuth callback
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("code")) {
      handleOAuthCallback();
    }
  }, []);

  const checkAuthStatus = async () => {
    try {
      const currentUser = await authService.getCurrentUser();
      setUser(currentUser);
    } catch (error) {
      console.error("Auth check failed:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleOAuthCallback = async () => {
    try {
      setLoading(true);
      await authService.handleCallback();
      await checkAuthStatus();
      // Clear URL parameters
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch (error) {
      setError(error.message);
      setLoading(false);
    }
  };

  const handleLogin = () => {
    // Use backend proxy method (recommended)
    authService.initiateBackendLogin();

    // OR use direct method:
    // authService.initiateDirectLogin();
  };

  const handleLogout = async () => {
    try {
      await authService.logout();
      setUser(null);
    } catch (error) {
      console.error("Logout failed:", error);
    }
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  if (error) {
    return (
      <div style={{ color: "red", padding: "20px" }}>
        <h3>Authentication Error</h3>
        <p>{error}</p>
        <button onClick={() => setError(null)}>Retry</button>
      </div>
    );
  }

  return (
    <div style={{ padding: "20px", maxWidth: "600px", margin: "0 auto" }}>
      <h1>OAuth2 Demo App</h1>

      {user ? (
        <div>
          <h2>Welcome!</h2>
          <div
            style={{
              background: "#f5f5f5",
              padding: "15px",
              borderRadius: "5px",
              marginBottom: "20px",
            }}
          >
            <h3>User Information:</h3>
            <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {JSON.stringify(user, null, 2)}
            </pre>
          </div>
          <button
            onClick={handleLogout}
            style={{
              padding: "10px 20px",
              backgroundColor: "#dc3545",
              color: "white",
              border: "none",
              borderRadius: "5px",
              cursor: "pointer",
            }}
          >
            Logout
          </button>
        </div>
      ) : (
        <div>
          <p>Please log in to access the application.</p>
          <button
            onClick={handleLogin}
            style={{
              padding: "10px 20px",
              backgroundColor: "#007bff",
              color: "white",
              border: "none",
              borderRadius: "5px",
              cursor: "pointer",
              fontSize: "16px",
            }}
          >
            Login with OAuth2
          </button>
        </div>
      )}

      <div style={{ marginTop: "40px", fontSize: "12px", color: "#666" }}>
        <h4>Test URLs:</h4>
        <ul>
          <li>
            Authorization Server:{" "}
            <a href="http://localhost:9000" target="_blank">
              http://localhost:9000
            </a>
          </li>
          <li>
            Backend API:{" "}
            <a href="http://localhost:3001" target="_blank">
              http://localhost:3001
            </a>
          </li>
          <li>
            Resource Server:{" "}
            <a href="http://localhost:8082" target="_blank">
              http://localhost:8082
            </a>
          </li>
        </ul>
      </div>
    </div>
  );
};

export default Login;
