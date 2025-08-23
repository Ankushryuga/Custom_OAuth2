import React, { useEffect, useState } from "react";

const App = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await fetch("http://localhost:8091/me", {
          credentials: "include", // send cookies/session info
        });

        if (res.status === 401) {
          // User not authenticated → redirect to OAuth2 login
          window.location.href = "/oauth2/authorization/client-app";
          return;
        }

        if (res.ok) {
          const data = await res.json();
          setUser(data);
        } else {
          console.error("Unexpected response:", res.status);
        }
      } catch (err) {
        console.error("Error fetching user:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, []);

  if (loading) return <p>Loading...</p>;

  return (
    <div style={{ padding: "2rem", fontFamily: "Arial" }}>
      <h1>React OAuth2 Client</h1>
      {user ? (
        <div>
          <h2>Logged In User Info</h2>
          <pre
            style={{
              background: "#f0f0f0",
              padding: "1rem",
              borderRadius: "8px",
            }}
          >
            {JSON.stringify(user, null, 2)}
          </pre>
        </div>
      ) : (
        <p>User not authenticated</p>
      )}
    </div>
  );
};

export default App;
