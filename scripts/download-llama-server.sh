#!/usr/bin/env bash
set -euo pipefail

# Downloads PrismML's llama.cpp fork (with Q1_0 1-bit kernel support)
# and the Bonsai-8B GGUF model file.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../src-tauri/llama-server"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

LLAMA_CPP_REPO="https://github.com/PrismML-Eng/llama.cpp"
MODEL_URL="https://huggingface.co/prism-ml/Bonsai-8B-gguf/resolve/main/Bonsai-8B.gguf"
MODEL_FILE="Bonsai-8B.gguf"

detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux)   echo "linux" ;;
        Darwin)  echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT) echo "windows" ;;
        *) echo "Unsupported OS: $os" >&2; exit 1 ;;
    esac
}

build_llama_server() {
    local os="$1"
    local tmpdir
    tmpdir="$(mktemp -d)"

    echo "Cloning PrismML llama.cpp fork..."
    git clone --depth 1 "$LLAMA_CPP_REPO" "$tmpdir/llama.cpp"
    cd "$tmpdir/llama.cpp"

    echo "Building llama-server (static)..."
    case "$os" in
        linux)
            cmake -B build -DBUILD_SHARED_LIBS=OFF -DLLAMA_CURL=OFF -DLLAMA_SERVER_SSL=OFF -DGGML_CUDA=ON 2>/dev/null \
                || cmake -B build -DBUILD_SHARED_LIBS=OFF -DLLAMA_CURL=OFF -DLLAMA_SERVER_SSL=OFF
            cmake --build build -j --target llama-server
            cp build/bin/llama-server "$OUT_DIR/llama-server"
            # Copy any shared libs that ended up alongside the binary
            cp build/bin/*.so "$OUT_DIR/" 2>/dev/null || true
            cp build/lib/*.so "$OUT_DIR/" 2>/dev/null || true
            ;;
        macos)
            cmake -B build -DBUILD_SHARED_LIBS=OFF -DLLAMA_CURL=OFF -DLLAMA_SERVER_SSL=OFF
            cmake --build build -j --target llama-server
            cp build/bin/llama-server "$OUT_DIR/llama-server"
            cp build/bin/*.dylib "$OUT_DIR/" 2>/dev/null || true
            cp build/lib/*.dylib "$OUT_DIR/" 2>/dev/null || true
            ;;
        windows)
            cmake -B build -DBUILD_SHARED_LIBS=OFF -DLLAMA_CURL=OFF -DLLAMA_SERVER_SSL=OFF
            cmake --build build -j --target llama-server --config Release
            local bindir="build/bin/Release"
            [ ! -d "$bindir" ] && bindir="build/bin"
            cp "$bindir/llama-server.exe" "$OUT_DIR/llama-server.exe"
            cp "$bindir"/*.dll "$OUT_DIR/" 2>/dev/null || true
            cp build/bin/*.dll "$OUT_DIR/" 2>/dev/null || true
            cp build/lib/Release/*.dll "$OUT_DIR/" 2>/dev/null || true
            cp build/lib/*.dll "$OUT_DIR/" 2>/dev/null || true
            ;;
    esac

    chmod +x "$OUT_DIR"/llama-server* 2>/dev/null || true
    rm -rf "$tmpdir"
    echo "llama-server built successfully."
    echo "Bundled files:"
    ls -lh "$OUT_DIR"/
}

download_model() {
    local dest="$OUT_DIR/$MODEL_FILE"
    if [ -f "$dest" ]; then
        echo "Model already exists: $dest"
        return
    fi

    echo "Downloading Bonsai-8B model (~1.16 GB)..."
    curl -fSL --progress-bar -o "$dest" "$MODEL_URL"
    echo "Model downloaded: $dest"
}

OS="$(detect_os)"

SERVER_BIN="$OUT_DIR/llama-server"
[ "$OS" = "windows" ] && SERVER_BIN="$OUT_DIR/llama-server.exe"

if [ -f "$SERVER_BIN" ]; then
    echo "llama-server already exists: $SERVER_BIN"
    echo "Delete it to rebuild."
else
    build_llama_server "$OS"
fi

download_model

echo ""
echo "Done! Files in: $OUT_DIR"
ls -lh "$OUT_DIR"
