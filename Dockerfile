# Three stages (issue #39): a Node stage builds the real admin UI (the
# exact `npm ci && npm run build` steps `make web` already runs locally),
# a Go stage builds the binary against a base matching go.mod's own `go
# 1.25.0` directive, and copies the first stage's built
# internal/webui/dist output in before compiling -- go:embed only
# captures whatever's on disk at build time, and without this step it
# would bake in nothing but dist/'s tracked .gitkeep placeholder, shipping
# a binary whose /ui/ 404s for every request. The final distroless stage
# never sees Node.js, npm, or a source tree -- only the compiled binary.

FROM node:24-alpine AS web
WORKDIR /src
COPY web/ ./web/
COPY internal/webui/ ./internal/webui/
WORKDIR /src/web
RUN npm ci && npm run build

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
COPY --from=web /src/internal/webui/dist ./internal/webui/dist
# -ldflags="-s -w" strips the symbol table and DWARF debug info -- a
# standard, safe production-build trim (no behavior change, just no
# `go tool` postmortem debugging inside this image, which distroless
# never had the tooling for anyway) that keeps the final image
# comfortably under the ~30MB target (MASTER_PLAN.md §11) despite
# modernc.org/sqlite's pure-Go (no cgo) footprint.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /spidercob ./cmd/spidercob

FROM gcr.io/distroless/static-debian12
COPY --from=build /spidercob /spidercob
ENTRYPOINT ["/spidercob"]
CMD ["-config", "/config.json"]
