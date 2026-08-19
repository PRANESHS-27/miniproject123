import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true,
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
  // react-hot-toast 2.x has a CommonJS/ESM interop quirk with Vite that
  // can produce two React instances at dev time. Forcing it into the
  // optimizeDeps pre-bundle (and using a single React/ReactDOM alias)
  // guarantees a single dispatcher across the app and the toast library.
  resolve: {
    dedupe: ['react', 'react-dom'],
  },
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-dom/client',
      'react-hot-toast',
      'react-router-dom',
    ],
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
