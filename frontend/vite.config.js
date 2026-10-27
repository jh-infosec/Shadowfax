import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the dashboard (Vite on :5173) talks to the API on :8000
// directly; the API's CORS allowlist names this origin. In the packaged image
// the API serves the built dashboard itself, so there is no cross-origin call.
// v0.28: Vite 8 (Rolldown) and @vitejs/plugin-react 6; npm audit is clean.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
});
