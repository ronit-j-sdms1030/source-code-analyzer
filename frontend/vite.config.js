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
      "/ingest": "http://localhost:5000",
      "/chat": "http://localhost:5000",
      "/projects": "http://localhost:5000",
    },
  },
});
