// Package webui embeds and serves the admin UI's built static assets
// (issue #17, Phase 4c-1) -- the second use of go:embed in this repo,
// after internal/store/migrate.go's migrations.
//
// dist/ holds the frontend's build output (web/'s Vite project builds
// directly into this directory, not web/dist -- go:embed can only
// embed files at or below the directory containing the .go file with
// the directive, and can't reach across to a sibling web/ directory
// with a "../" pattern). dist/ is gitignored except for a tracked
// .gitkeep placeholder, so `go build ./...`/`go vet ./...`/`go test
// ./...` all still succeed on a fresh clone without Node.js installed
// -- see automation/README.md for the `npm run build` step required
// before a real, UI-serving binary.
package webui

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
)

// embeddedDist embeds every file under dist/, regardless of a leading
// "." or "_" in its name (the "all:" prefix) -- harmless today (Vite's
// output has none), but a smaller surprise later than the default
// pattern's silent exclusion would be if that ever changes.
//
//go:embed all:dist
var embeddedDist embed.FS

// Handler serves the embedded UI at /ui/, stripped of its dist/
// prefix. If dist/ was never actually built (a fresh clone with only
// the tracked .gitkeep placeholder), this serves 404s for every /ui/
// request rather than failing the gateway to start -- the real MCP
// data plane, /token, and /admin/* are all completely unaffected
// either way.
func Handler() http.Handler {
	sub, err := fs.Sub(embeddedDist, "dist")
	if err != nil {
		// Only possible if the embed itself is structurally broken (the
		// directory didn't exist at build time) -- go:embed would
		// already have failed the build in that case, so this is
		// unreachable in practice, not a real runtime condition.
		slog.Error("admin UI embed is broken", "err", err)
		return http.NotFoundHandler()
	}
	return http.StripPrefix("/ui/", http.FileServerFS(sub))
}
