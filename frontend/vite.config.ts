import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

// In dev, /api is proxied to FastAPI so the browser sees one origin.
// The backend port must match. Default 8001 (port 8000 is blocked on some Windows machines).
// Use another port without editing this file:  $env:SAD_API_URL = "http://127.0.0.1:8000"; npm run dev
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "SAD_");
  const target = env.SAD_API_URL || "http://127.0.0.1:8001";
  return {
    plugins: [react()],
    server: { port: 5173, proxy: { "/api": target } },
  };
});
