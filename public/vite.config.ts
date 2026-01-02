import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'


// https://vite.dev/config/
export default defineConfig({
  plugins: [
    tailwindcss(),
    react({
      babel: {
        plugins: [['babel-plugin-react-compiler']],
      },
    }),
  ],
  define: {
    HCAPTCHA_SITE_KEY: JSON.stringify(process.env.HCAPTCHA_SITE_KEY || ""),
  }
})

declare global {
  const HCAPTCHA_SITE_KEY: string
}