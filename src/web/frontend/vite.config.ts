import path from "path"
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Servido por FastAPI bajo /ui/ (es la única UI). El base debe matchear el path
// de montaje para que los assets resuelvan.
// https://vite.dev/config/
export default defineConfig({
  base: '/ui/',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
})
