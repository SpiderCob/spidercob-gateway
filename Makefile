.PHONY: build web test e2e e2e-idjag e2e-pin e2e-schema e2e-adminapi e2e-nodes e2e-adminui-session e2e-adminui-nodes e2e-seed-users e2e-audit e2e-mcp-audit e2e-docker e2e-standalone-admin ci ci-interop ci-docker run docker

# web builds the admin UI's static assets into internal/webui/dist
# (issue #17) -- required before `go build`/`go vet`/`go test ./...`
# will produce a UI-serving binary; without it, the repo still builds
# fine (internal/webui/dist/.gitkeep keeps the go:embed directive
# happy), it just serves 404s under /ui/. `make build` and `make ci`
# both depend on this so a fresh clone gets a complete build by
# default; run it manually after frontend-only changes if you're not
# going through `make build`/`make ci`.
web:
	cd web && npm ci && npm run build

build: web
	go build -o spidercob ./cmd/spidercob

test:
	./automation/run-tests.sh

e2e:
	./automation/run-e2e.sh

e2e-idjag:
	./automation/run-e2e-idjag.sh

e2e-pin:
	./automation/run-e2e-pin.sh

e2e-schema:
	./automation/run-e2e-schema.sh

e2e-adminapi:
	./automation/run-e2e-adminapi.sh

e2e-nodes:
	./automation/run-e2e-nodes.sh

e2e-adminui-session:
	./automation/run-e2e-adminui-session.sh

e2e-adminui-nodes:
	./automation/run-e2e-adminui-nodes.sh

e2e-seed-users:
	./automation/run-e2e-seed-users.sh

e2e-audit:
	./automation/run-e2e-audit.sh

e2e-mcp-audit:
	./automation/run-e2e-mcp-audit.sh

e2e-docker:
	./automation/run-e2e-docker.sh

e2e-standalone-admin:
	./automation/run-e2e-standalone-admin.sh

ci: web ## fast suite + real end-to-end validation -- run before opening a PR (builds the admin UI first, issue #17)
	./automation/run-all.sh

ci-interop: ## real Keycloak ID-JAG interop (issue #5) -- needs Docker; required before a Phase 2b PR, separate from `ci` since not every environment has Docker
	./automation/run-e2e-idjag.sh

ci-docker: ## real production Docker image build + run (issue #39) -- needs Docker; separate from ci-interop, which tests Keycloak protocol interop, not this repo's own packaged artifact
	./automation/run-e2e-docker.sh

run: build
	./spidercob -config config.json

docker:
	docker build -t spidercob-gateway .
