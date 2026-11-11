import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: 'https://localhost:8444', secure: false },
      '/healthz': { target: 'https://localhost:8444', secure: false },
    },
  },
})
