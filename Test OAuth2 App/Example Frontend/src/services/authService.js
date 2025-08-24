// React App OAuth2 Configuration
// Create this file: src/services/authService.js

class AuthService {
  constructor() {
    // Base URL of the Spring Boot backend.  This module proxies all OAuth2
    // interactions (authorisation request and token exchange) so the
    // browser never needs to know the client secret.  Update this value
    // if your backend runs on a different host or port.
    this.baseURL = "http://localhost:3001";
    // Base URL of the authorisation server.  Only used when initiating
    // direct logins via the auth server (see initiateDirectLogin), which
    // is generally discouraged in favour of initiateBackendLogin().
    this.authServerURL = "http://localhost:9000";
  }

  // Method 1: Direct Authorization Server redirect (if you want to handle OAuth directly).
  // This method constructs the authorisation request on the client and sends the user
  // straight to the authorisation server.  The redirect_uri MUST match one of the
  // values registered for your client in the database (e.g. http://localhost:3001/login/oauth2/code/client-app)
  // Otherwise the authorisation server will reject the request with a 400 Bad Request.
  initiateDirectLogin() {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: "client-app",
      redirect_uri: "http://localhost:3001/login/oauth2/code/client-app",
      scope: "openid profile api.read orders.read",
      state: this.generateState(),
    });

    // Store state for validation
    sessionStorage.setItem("oauth_state", params.get("state"));

    // Redirect to authorization server
    window.location.href = `${
      this.authServerURL
    }/oauth2/authorize?${params.toString()}`;
  }

  // Method 2: Use your Spring Boot backend as proxy (Recommended)
  async initiateBackendLogin() {
    try {
      // This will redirect to your backend which handles OAuth2 flow
      window.location.href = `${this.baseURL}/api/auth/login`;
    } catch (error) {
      console.error("Login failed:", error);
    }
  }

  // Handle callback from authorization server (for Method 1)
  async handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const state = urlParams.get("state");
    const storedState = sessionStorage.getItem("oauth_state");

    if (state !== storedState) {
      throw new Error("State mismatch - possible CSRF attack");
    }

    if (code) {
      // Exchange code for token via your backend.  The redirect_uri parameter
      // MUST match the value registered on the server.  We use the backend's
      // callback endpoint (http://localhost:3001/login/oauth2/code/client-app)
      // so that the backend can perform the token exchange securely.
      const response = await fetch(`${this.baseURL}/api/auth/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({
          code,
          redirect_uri: "http://localhost:3001/login/oauth2/code/client-app",
        }),
      });

      if (response.ok) {
        const tokens = await response.json();
        // Store tokens securely
        sessionStorage.setItem("access_token", tokens.access_token);
        return tokens;
      } else {
        throw new Error("Token exchange failed");
      }
    }
  }

  // Get current user info
  async getCurrentUser() {
    try {
      const response = await fetch(`${this.baseURL}/api/auth/user`, {
        credentials: "include",
        headers: {
          Authorization: `Bearer ${sessionStorage.getItem("access_token")}`,
        },
      });

      if (response.ok) {
        return await response.json();
      }
      return null;
    } catch (error) {
      console.error("Failed to get user:", error);
      return null;
    }
  }

  // Logout
  async logout() {
    try {
      await fetch(`${this.baseURL}/api/auth/logout`, {
        method: "POST",
        credentials: "include",
      });

      // Clear local storage
      sessionStorage.removeItem("access_token");
      sessionStorage.removeItem("oauth_state");

      // Redirect to home
      window.location.href = "/";
    } catch (error) {
      console.error("Logout failed:", error);
    }
  }

  generateState() {
    return (
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15)
    );
  }

  isAuthenticated() {
    return !!sessionStorage.getItem("access_token");
  }
}

export default new AuthService();
