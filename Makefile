.PHONY: build test e2e ci run docker

build:
	go build -o spidercob ./cmd/spidercob

test:
	./automation/run-tests.sh

e2e:
	./automation/run-e2e.sh

ci: ## fast suite + real end-to-end validation -- run before opening a PR
	./automation/run-all.sh

run: build
	./spidercob -config config.json

docker:
	docker build -t spidercob-gateway .
