# Build CLI release binary
build:
    cargo build --release

# Build WASM module for web
wasm:
    wasm-pack build --target web --out-dir web/pkg

# Build everything (CLI + WASM)
all: build wasm

# Serve web app locally (builds WASM first if needed)
serve: wasm
    miniserve web --index index.html -p 8080

# Clean build artifacts
clean:
    cargo clean
    rm -rf web/pkg

# List available categories
list:
    cargo run -- --list

# List categories with details
list-verbose:
    cargo run -- --list --verbose
