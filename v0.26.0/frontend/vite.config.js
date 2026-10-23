import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dashboard talks to the Shadowfax API over HTTP; no proxy needed in
// development since the backend already sends permissive CORS headers.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
});
