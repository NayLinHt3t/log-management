import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// In development the UI runs on :5173 and forwards /api to the backend on :3000,
// so the browser sees one origin (same as production behind Caddy).
export default defineConfig({
  plugins: [react()],
  // one bundle (React + Recharts) is ~200 kB gzipped; fine for an internal console
  build: { chunkSizeWarningLimit: 800 },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: process.env.API_URL ?? 'http://localhost:3000', changeOrigin: true },
    },
  },
  preview: {
    port: 4173,
    proxy: {
      '/api': { target: process.env.API_URL ?? 'http://localhost:3000', changeOrigin: true },
    },
  },
})
