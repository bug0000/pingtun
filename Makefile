.PHONY: build test vet fmt fuzz lab

build:
	go build -trimpath -o bin/pingtun ./cmd/pingtun

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal mobile/jni

fuzz:
	go test ./internal/wire -run '^$$' -fuzz '^FuzzDecode$$' -fuzztime 10s -parallel 2
	go test ./internal/wire -run '^$$' -fuzz '^FuzzDecodeProbe$$' -fuzztime 10s -parallel 2
	go test ./internal/wire -run '^$$' -fuzz '^FuzzDecodeAdaptive$$' -fuzztime 10s -parallel 2

lab: build
	./tests/netns.sh
