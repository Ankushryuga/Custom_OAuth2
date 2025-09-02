import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// https://vite.dev/config/
export default defineConfig({
  base: "/auth/login/", // <-- CRITICAL when hosting under a sub-path
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist", // default, fine
    assetsDir: "assets", // default, fine
  },
  server: {
    port: 3000,
    proxy: {
      "/login": "http://localhost:9000",
      "/oauth2": "http://localhost:9000",
      "/.well-known": "http://localhost:9000",
    },
  },
});
