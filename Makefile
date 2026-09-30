.DEFAULT_GOAL := help
.PHONY: help test vet vectors

help: ## List the available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-8s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run all tests (no Bitcoin Core node, network or relay needed)
	go test ./...

vet: ## Run go vet on every package
	go vet ./...

# The generator that would rebuild testdata/vectors from a local regtest node has
# not been written yet. Tests and CI read the committed JSON files directly, so
# nothing depends on this target.
vectors: ## Regenerate testdata/vectors from a regtest node (not implemented yet)
	@echo "make vectors: not implemented yet." >&2
	@echo "No generator exists to rebuild testdata/vectors from a regtest node." >&2
	@echo "The tests read the committed files in testdata/vectors, so 'make test' still works." >&2
	@exit 1
