.PHONY: build test run docker

build:
	go build -o spidercob ./cmd/spidercob

test:
	go vet ./... && go test ./...

run: build
	./spidercob -config config.json

docker:
	docker build -t spidercob-gateway .
