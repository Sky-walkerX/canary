.PHONY: test vet vectors

test:
	go test ./...

vet:
	go vet ./...

# Regenerates testdata/vectors from a local regtest node. Dev-time only —
# CI consumes the committed JSON and never runs this (§7.4).
vectors:
	go run ./internal/testvector/cmd/genvectors
