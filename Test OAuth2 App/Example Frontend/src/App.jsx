import React, { useEffect, useState } from "react";
import axios from "axios";

function App() {
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(null);

  // OAuth2 redirect URI
  const redirectUri = "http://localhost:8081/login/oauth2/code/client-app";

  useEffect(() => {
    handleOAuthRedirect();
  }, []);

  // 1️⃣ Handle redirect after Authorization Code login
  const handleOAuthRedirect = async () => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");

    if (code && !accessToken) {
      try {
        // Exchange code for access token via backend
        const res = await axios.post(
          "http://localhost:8082/oauth2/token", // Your backend endpoint to exchange code
          { code, redirectUri },
          { withCredentials: true }
        );

        setAccessToken(res.data.access_token);
        fetchUser(res.data.access_token);
        window.history.replaceState({}, document.title, "/"); // remove ?code from URL
      } catch (err) {
        console.error("Error exchanging code for token:", err);
      }
    } else {
      // No code, redirect to Authorization Server
      redirectToLogin();
    }
  };

  // 2️⃣ Fetch user info from Resource Server
  const fetchUser = async (token) => {
    try {
      const res = await axios.get("http://localhost:8082/api/userinfo", {
        headers: { Authorization: `Bearer ${token}` },
      });
      setUser(res.data);
    } catch (err) {
      console.error("Error fetching user info:", err);
    }
  };

  // 3️⃣ Redirect to login
  const redirectToLogin = () => {
    const authUrl = `http://localhost:9000/oauth2/authorize?response_type=code&client_id=client-app&redirect_uri=${encodeURIComponent(
      redirectUri
    )}&scope=openid profile api.read`;
    window.location.href = authUrl;
  };

  // 4️⃣ Logout
  const logout = () => {
    setUser(null);
    setAccessToken(null);
    window.location.href =
      "http://localhost:9000/logout?redirect_uri=http://localhost:8081";
  };

  if (!user) return <div>Loading or redirecting to login...</div>;

  return (
    <div>
      <h1>Welcome, {user.name || user.username}</h1>
      <pre>{JSON.stringify(user, null, 2)}</pre>
      <button onClick={logout}>Logout</button>
    </div>
  );
}

export default App;
