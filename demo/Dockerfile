# Demo image: the gateway plus the demo's leaky MCP server, wired together
# over stdio by demo/config.json. Same build as the main Dockerfile (admin
# UI included), with one extra binary. Build context is the repo root.
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
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /spidercob ./cmd/spidercob \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /leakyserver ./demo/leakyserver

FROM gcr.io/distroless/static-debian12
COPY --from=build /spidercob /spidercob
COPY --from=build /leakyserver /leakyserver
COPY demo/config.json /config.json
COPY demo/users.csv /users.csv
ENTRYPOINT ["/spidercob"]
CMD ["-config", "/config.json"]
