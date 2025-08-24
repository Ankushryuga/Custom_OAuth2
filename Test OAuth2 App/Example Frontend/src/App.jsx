import React, { useEffect, useState } from "react";
import authService from "./services/authService";

/**
 * Main application component for the example front‑end.  This implementation
 * delegates all OAuth2 interactions to the Spring Boot backend on port 3001.
 * It initiates the authorisation flow via the backend, handles the callback
 * to exchange an authorization code for tokens, and exposes a simple login
 * and logout UI.
 */
const App = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Check authentication status on initial load
    checkAuthStatus();

    // If the URL contains an authorization code, handle the OAuth2 callback.
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("code")) {
      handleOAuthCallback();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /**
   * Queries the backend to determine whether the current session is
   * authenticated and to retrieve user details if so.
   */
  const checkAuthStatus = async () => {
    try {
      const currentUser = await authService.getCurrentUser();
      setUser(currentUser);
    } catch (err) {
      console.error("Auth check failed:", err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * Handles the OAuth2 callback by exchanging the authorization code for a
   * token via the backend and then refreshing the current user.
   */
  const handleOAuthCallback = async () => {
    try {
      setLoading(true);
      await authService.handleCallback();
      await checkAuthStatus();
      // Clear the query parameters from the URL after successful callback
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  /**
   * Initiates the login flow.  Uses the backend proxy method so that the
   * browser never needs to know the client secret or construct the
   * authorisation request itself.
   */
  const handleLogin = () => {
    authService.initiateBackendLogin();
  };

  /**
   * Logs out by clearing the session on the backend and resetting the
   * application state.
   */
  const handleLogout = async () => {
    try {
      await authService.logout();
      setUser(null);
    } catch (err) {
      console.error("Logout failed:", err);
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
            Authorization Server: <a href="http://localhost:9000" target="_blank" rel="noreferrer">http://localhost:9000</a>
          </li>
          <li>
            Backend API: <a href="http://localhost:3001" target="_blank" rel="noreferrer">http://localhost:3001</a>
          </li>
          <li>
            Resource Server: <a href="http://localhost:8082" target="_blank" rel="noreferrer">http://localhost:8082</a>
          </li>
        </ul>
      </div>
    </div>
  );
};

export default App;