import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build output lands in backend/static so Flask can serve the compiled
// frontend directly in production. In dev, API calls are proxied to the
// Flask server running on localhost:5000.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../backend/static",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": { target: "http://localhost:5000", timeout: 300000, proxyTimeout: 300000 },
      "/ingest": { target: "http://localhost:5000", timeout: 300000, proxyTimeout: 300000 },
      "/chat": { target: "http://localhost:5000", timeout: 300000, proxyTimeout: 300000 },
      "/projects": { target: "http://localhost:5000", timeout: 300000, proxyTimeout: 300000 },
    },
  },
});
