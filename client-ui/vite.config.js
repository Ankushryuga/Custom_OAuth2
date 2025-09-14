import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({
  plugins:[react()],
  server:{ host:true, port:5174, allowedHosts:['localhost'] },
  preview:{ host:true, port:5174, allowedHosts:['localhost'] }
})

