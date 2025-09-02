// import { defineConfig } from "vite";
// import react from "@vitejs/plugin-react";
// import tailwindcss from "@tailwindcss/vite";

// // https://vite.dev/config/
// export default defineConfig({
//   base: "/auth/login/", // <-- CRITICAL when hosting under a sub-path
//   plugins: [react(), tailwindcss()],
//   server: {
//     proxy: {
//       "/oauth2": "http://localhost:9000",
//       "/connect": "http://localhost:9000",
//       "/admin": "http://localhost:9000",
//       "/.well-known": "http://localhost:9000",
//     },
//   },
// });

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  base: "/", // SPA at root on dev server
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173, // or 3000 if you prefer
    proxy: {
      // These help if you fetch AS routes from dev server (optional)
      "/login": "http://localhost:9000",
      "/oauth2": "http://localhost:9000",
      "/.well-known": "http://localhost:9000",
    },
  },
  build: {
    outDir: "dist",
    assetsDir: "assets",
  },
});
