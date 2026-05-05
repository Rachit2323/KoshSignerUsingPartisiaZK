import { defineConfig } from "vite";

export default defineConfig({
  server: {
    port: 5173,
    proxy: {
      // Proxy all /api calls to the Go gateway — avoids CORS in local dev
      "/api": {
        target: "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
});
