import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

/**
 * CSP for development: no inline scripts, no eval.
 * Production CSP should be set by the backend (e.g. nonces for scripts).
 */
const cspDirectives = [
  "default-src 'self'",
  "script-src 'self'", // no 'unsafe-inline'; use nonces in production
  "style-src 'self' 'unsafe-inline'", // Vite/React may inject styles in dev
  "img-src 'self' data: https:",
  "connect-src 'self' ws: wss:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
]

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
    headers: {
      'Content-Security-Policy': cspDirectives.join('; '),
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
  },
})
