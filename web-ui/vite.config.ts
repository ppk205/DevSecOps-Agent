/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// PIT WALL web UI. Served by FastAPI at /app/* (SPA fallback).
// VITE_MOCK=1 (or --mode mock) runs the scripted mock layer, no backend needed.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: "/app/",
  define: {
    // Bake mock mode into the bundle for `dev:mock` / `vite --mode mock`.
    ...(mode === "mock" ? { "import.meta.env.VITE_MOCK": JSON.stringify("1") } : {}),
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 800,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
  },
}));
