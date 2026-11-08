import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The console always talks to the control plane on the same origin:
// `/api/v1/*` (JSON API), `/mock-cloud/*` (demo cloud) and `/healthz`.
// In dev, Vite proxies those prefixes to a locally running `csg serve`
// (default loopback address from docs/CONTRACT.md §1).
const apiTarget = process.env.CSG_API_PROXY ?? 'http://127.0.0.1:8787'

export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    port: 18803,
    strictPort: true,
    proxy: {
      '/api': { target: apiTarget, changeOrigin: true },
      '/mock-cloud': { target: apiTarget, changeOrigin: true },
      '/healthz': { target: apiTarget, changeOrigin: true },
    },
  },
  preview: {
    port: 18803,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2020',
  },
})
