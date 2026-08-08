import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The gateway embeds this build's output via go:embed and serves it at
// /ui/ -- base must match so every asset URL the built index.html
// emits resolves correctly under that prefix, not root. Build output
// goes directly to internal/webui/dist, not web/dist -- go:embed can
// only embed files at or below the directory containing the .go file
// with the directive, and that file (internal/webui/webui.go) can't
// reach up and across to a sibling web/ directory with a "../" pattern
// (go:embed doesn't allow them), so the frontend's own build output
// has to physically live inside the Go package that embeds it.
// The dev server proxies /admin/* to a locally-running gateway
// (`go run ./cmd/spidercob`, default :8080) so `npm run dev` talks to
// the real backend without a second process/CORS setup during local
// frontend work.
export default defineConfig({
  base: '/ui/',
  plugins: [react()],
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/admin': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
