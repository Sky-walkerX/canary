.DEFAULT_GOAL := help
.PHONY: help test vet vectors wasm

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

# The browser checker. It builds into bin/wasm, outside the site's output, so
# it runs before or after the site generator and never trips its check on the
# output directory. The site generator copies both files into the hashed asset
# folder beside checker.js, which loads them from there. The module and
# wasm_exec.js must come from the same Go release, so both come from this
# toolchain. The brotli sizes need node; a CDN compresses on the fly at about
# gzip -6 or brotli 4, so those two are the sizes a reader downloads.
WASM_DIR := bin/wasm

wasm: ## Build the browser checker into bin/wasm and print its sizes
	@mkdir -p $(WASM_DIR)
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o $(WASM_DIR)/canary.wasm ./cmd/verify-wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" $(WASM_DIR)/wasm_exec.js
	@w=$(WASM_DIR)/canary.wasm; \
	printf 'canary.wasm, %s: %s bytes raw\n' "$$(go env GOVERSION)" "$$(wc -c < $$w | tr -d ' ')"; \
	printf '  gzip -9 %s, gzip -6 %s\n' "$$(gzip -9 -c $$w | wc -c | tr -d ' ')" "$$(gzip -6 -c $$w | wc -c | tr -d ' ')"; \
	if command -v node >/dev/null 2>&1; then \
		node -e 'const z = require("zlib"), b = require("fs").readFileSync(process.argv[1]); const q = (n) => z.brotliCompressSync(b, { params: { [z.constants.BROTLI_PARAM_QUALITY]: n } }).length; console.log("  brotli 11 " + q(11) + ", brotli 4 " + q(4));' $$w; \
	else \
		echo "  brotli sizes skipped: node is not installed"; \
	fi
