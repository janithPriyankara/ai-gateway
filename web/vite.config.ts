import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
// The Go binary embeds web/dist and serves it at /admin/ (see web/embed.go).
// During `npm run dev`, API calls are proxied to a local gateway.
export default defineConfig({
  base: '/admin/',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    // No inline scripts or data-URI modules: the dashboard runs under a strict CSP.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  server: {
    proxy: {
      '/admin/api': { target: process.env.GW_URL ?? 'http://localhost:8787', changeOrigin: false },
    },
  },
});
