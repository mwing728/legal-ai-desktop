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

    echo "Building llama-server..."
    case "$os" in
        linux)
            cmake -B build -DGGML_CUDA=ON 2>/dev/null || cmake -B build
            cmake --build build -j --target llama-server
            cp build/bin/llama-server "$OUT_DIR/llama-server"
            ;;
        macos)
            cmake -B build
            cmake --build build -j --target llama-server
            cp build/bin/llama-server "$OUT_DIR/llama-server"
            ;;
        windows)
            cmake -B build
            cmake --build build -j --target llama-server --config Release
            cp build/bin/Release/llama-server.exe "$OUT_DIR/llama-server.exe" 2>/dev/null \
                || cp build/bin/llama-server.exe "$OUT_DIR/llama-server.exe"
            ;;
    esac

    chmod +x "$OUT_DIR"/llama-server* 2>/dev/null || true
    rm -rf "$tmpdir"
    echo "llama-server built successfully."
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
