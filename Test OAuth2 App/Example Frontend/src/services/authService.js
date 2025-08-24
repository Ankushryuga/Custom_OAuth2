// React App OAuth2 Configuration
// Create this file: src/services/authService.js

class AuthService {
  constructor() {
    this.baseURL = "http://localhost:3001"; // Your Spring Boot backend
    this.authServerURL = "http://localhost:9000"; // Authorization server
  }

  // Method 1: Direct Authorization Server redirect (if you want to handle OAuth directly)
  initiateDirectLogin() {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: "client-app",
      redirect_uri: "http://localhost:3000/callback",
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
      // Exchange code for token via your backend
      const response = await fetch(`${this.baseURL}/api/auth/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({
          code,
          redirect_uri: "http://localhost:3000/callback",
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
