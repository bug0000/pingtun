.PHONY: build test vet fmt fuzz

build:
	go build -trimpath -o bin/pingtun ./cmd/pingtun

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

fuzz:
	go test ./internal/wire -run '^$$' -fuzz FuzzDecode -fuzztime 10s -parallel 2
