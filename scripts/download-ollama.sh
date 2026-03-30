#!/usr/bin/env bash
set -euo pipefail

OLLAMA_VERSION="${OLLAMA_VERSION:-0.19.0}"
BASE_URL="https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$(cd "${SCRIPT_DIR}/../src-tauri/binaries" && pwd)"

mkdir -p "$OUT_DIR"

detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)
            case "$arch" in
                x86_64)  echo "x86_64-unknown-linux-gnu" ;;
                aarch64) echo "aarch64-unknown-linux-gnu" ;;
                *) echo "Unsupported Linux arch: $arch" >&2; exit 1 ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                x86_64)  echo "x86_64-apple-darwin" ;;
                arm64)   echo "aarch64-apple-darwin" ;;
                *) echo "Unsupported macOS arch: $arch" >&2; exit 1 ;;
            esac
            ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            echo "x86_64-pc-windows-msvc"
            ;;
        *)
            echo "Unsupported OS: $os" >&2
            exit 1
            ;;
    esac
}

target_to_asset() {
    local target="$1"
    case "$target" in
        x86_64-unknown-linux-gnu)   echo "ollama-linux-amd64.tar.zst" ;;
        aarch64-unknown-linux-gnu)  echo "ollama-linux-arm64.tar.zst" ;;
        x86_64-apple-darwin|aarch64-apple-darwin)
            echo "ollama-darwin.tgz" ;;
        x86_64-pc-windows-msvc)     echo "ollama-windows-amd64.zip" ;;
        *) echo "Unknown target: $target" >&2; exit 1 ;;
    esac
}

sidecar_filename() {
    local target="$1"
    case "$target" in
        *windows*) echo "ollama-${target}.exe" ;;
        *)         echo "ollama-${target}" ;;
    esac
}

extract_ollama_binary() {
    local archive="$1" target="$2" dest="$3"
    local tmpdir
    tmpdir="$(mktemp -d)"

    echo "Extracting..."
    case "$archive" in
        *.tar.zst)
            zstd -d "$archive" --stdout | tar xf - -C "$tmpdir"
            ;;
        *.tgz|*.tar.gz)
            tar xzf "$archive" -C "$tmpdir"
            ;;
        *.zip)
            unzip -q "$archive" -d "$tmpdir"
            ;;
    esac

    local bin_name="ollama"
    case "$target" in
        *windows*) bin_name="ollama.exe" ;;
    esac

    local found=""
    found=$(find "$tmpdir" -name "$bin_name" -type f | head -1)
    if [ -z "$found" ]; then
        echo "Could not find '$bin_name' inside archive. Contents:" >&2
        find "$tmpdir" -type f >&2
        rm -rf "$tmpdir"
        exit 1
    fi

    cp "$found" "$dest"
    chmod +x "$dest"
    rm -rf "$tmpdir"
}

TARGET="${1:-$(detect_target)}"
ASSET="$(target_to_asset "$TARGET")"
SIDECAR="$(sidecar_filename "$TARGET")"
URL="${BASE_URL}/${ASSET}"
DEST="${OUT_DIR}/${SIDECAR}"

if [ -f "$DEST" ]; then
    echo "Ollama sidecar already exists: $DEST"
    echo "Delete it to re-download, or set OLLAMA_VERSION to change version."
    exit 0
fi

ARCHIVE="/tmp/ollama-download-${ASSET}"

echo "Downloading Ollama v${OLLAMA_VERSION} for ${TARGET}..."
echo "  URL:  ${URL}"
echo "  Dest: ${DEST}"

curl -fSL --progress-bar -o "$ARCHIVE" "$URL"
extract_ollama_binary "$ARCHIVE" "$TARGET" "$DEST"
rm -f "$ARCHIVE"

echo "Done! Ollama sidecar ready at: ${DEST}"
ls -lh "$DEST"
