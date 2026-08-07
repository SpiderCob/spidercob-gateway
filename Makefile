.PHONY: build test e2e e2e-idjag ci ci-interop run docker

build:
	go build -o spidercob ./cmd/spidercob

test:
	./automation/run-tests.sh

e2e:
	./automation/run-e2e.sh

e2e-idjag:
	./automation/run-e2e-idjag.sh

ci: ## fast suite + real end-to-end validation -- run before opening a PR
	./automation/run-all.sh

ci-interop: ## real Keycloak ID-JAG interop (issue #5) -- needs Docker; required before a Phase 2b PR, separate from `ci` since not every environment has Docker
	./automation/run-e2e-idjag.sh

run: build
	./spidercob -config config.json

docker:
	docker build -t spidercob-gateway .
