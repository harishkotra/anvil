import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The spec pins the API to :3001. Set ANVIL_API_PORT when that port is already taken.
const apiPort = process.env.ANVIL_API_PORT || "3001";

export default defineConfig({
  plugins: [react()],
  server: {
    // Bind IPv4 explicitly: a second Vite on :5173 must not silently succeed on ::1 while
    // another process holds 127.0.0.1, which would make the proxy target ambiguous.
    host: "127.0.0.1",
    port: 5173,
    strictPort: false,
    proxy: {
      "/api": {
        target: `http://127.0.0.1:${apiPort}`,
        changeOrigin: true,
      },
    },
  },
});
