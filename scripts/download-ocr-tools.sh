#!/usr/bin/env bash
set -euo pipefail

POPPLER_VERSION="25.12.0-0"
TESSERACT_VERSION="5.5.0"
TESSERACT_DATE="20241111"
TESSDATA_URL="https://github.com/tesseract-ocr/tessdata_fast/raw/main/eng.traineddata"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../src-tauri/ocr-tools"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux)   echo "linux" ;;
        Darwin)  echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT) echo "windows" ;;
        *) echo "unknown" ;;
    esac
}

OS="${1:-$(detect_os)}"

if [ -f "$OUT_DIR/.downloaded-${OS}" ]; then
    echo "OCR tools already downloaded for ${OS}. Delete $OUT_DIR to re-download."
    exit 0
fi

echo "Downloading OCR tools for ${OS}..."

case "$OS" in
    linux)
        echo "Linux uses system packages (tesseract-ocr, poppler-utils)."
        echo "They will be installed as deb dependencies."
        mkdir -p "$OUT_DIR"
        touch "$OUT_DIR/.downloaded-${OS}"
        ;;

    macos)
        echo "macOS: checking for Homebrew-installed tools..."
        for tool in tesseract pdftoppm; do
            if ! command -v "$tool" &>/dev/null; then
                echo "Installing ${tool} via Homebrew..."
                if [ "$tool" = "tesseract" ]; then
                    brew install tesseract
                else
                    brew install poppler
                fi
            fi
        done

        TESS_BIN="$(command -v tesseract)"
        PDFTOPPM_BIN="$(command -v pdftoppm)"
        cp "$TESS_BIN" "$OUT_DIR/tesseract"
        cp "$PDFTOPPM_BIN" "$OUT_DIR/pdftoppm"
        chmod +x "$OUT_DIR/tesseract" "$OUT_DIR/pdftoppm"

        mkdir -p "$OUT_DIR/tessdata"
        TESS_PREFIX="$(tesseract --print-parameters 2>/dev/null | head -1 || true)"
        BREW_TESSDATA="$(brew --prefix)/share/tessdata"
        if [ -f "$BREW_TESSDATA/eng.traineddata" ]; then
            cp "$BREW_TESSDATA/eng.traineddata" "$OUT_DIR/tessdata/"
        else
            echo "Downloading eng.traineddata..."
            curl -fSL -o "$OUT_DIR/tessdata/eng.traineddata" "$TESSDATA_URL"
        fi

        echo "Copying dylib dependencies..."
        for bin in "$OUT_DIR/tesseract" "$OUT_DIR/pdftoppm"; do
            otool -L "$bin" 2>/dev/null | grep "$(brew --prefix)" | awk '{print $1}' | while read -r lib; do
                libname="$(basename "$lib")"
                if [ ! -f "$OUT_DIR/$libname" ]; then
                    cp "$lib" "$OUT_DIR/$libname" 2>/dev/null || true
                fi
            done
        done

        touch "$OUT_DIR/.downloaded-${OS}"
        ;;

    windows)
        TMPDIR="$(mktemp -d)"

        echo "Downloading Poppler ${POPPLER_VERSION} for Windows..."
        POPPLER_URL="https://github.com/oschwartz10612/poppler-windows/releases/download/v${POPPLER_VERSION}/Release-${POPPLER_VERSION}.zip"
        curl -fSL --progress-bar -o "$TMPDIR/poppler.zip" "$POPPLER_URL"
        unzip -q "$TMPDIR/poppler.zip" -d "$TMPDIR/poppler"
        POPPLER_BIN=$(find "$TMPDIR/poppler" -name "pdftoppm.exe" -type f | head -1)
        if [ -z "$POPPLER_BIN" ]; then
            echo "ERROR: pdftoppm.exe not found in Poppler archive" >&2
            exit 1
        fi
        POPPLER_BIN_DIR="$(dirname "$POPPLER_BIN")"
        cp "$POPPLER_BIN_DIR"/*.exe "$OUT_DIR/" 2>/dev/null || true
        cp "$POPPLER_BIN_DIR"/*.dll "$OUT_DIR/" 2>/dev/null || true

        echo "Downloading Tesseract ${TESSERACT_VERSION} for Windows..."
        TESS_URL="https://github.com/tesseract-ocr/tesseract/releases/download/${TESSERACT_VERSION}/tesseract-ocr-w64-setup-${TESSERACT_VERSION}.${TESSERACT_DATE}.exe"
        curl -fSL --progress-bar -o "$TMPDIR/tesseract-setup.exe" "$TESS_URL"
        7z x -o"$TMPDIR/tesseract" "$TMPDIR/tesseract-setup.exe" -y > /dev/null 2>&1 || {
            echo "7z extraction failed, trying innoextract..."
            innoextract -d "$TMPDIR/tesseract" "$TMPDIR/tesseract-setup.exe" 2>/dev/null || {
                echo "ERROR: Could not extract Tesseract installer. Install 7z or innoextract." >&2
                exit 1
            }
        }
        TESS_EXE=$(find "$TMPDIR/tesseract" -name "tesseract.exe" -type f | head -1)
        if [ -z "$TESS_EXE" ]; then
            echo "ERROR: tesseract.exe not found after extraction" >&2
            exit 1
        fi
        TESS_DIR="$(dirname "$TESS_EXE")"
        cp "$TESS_EXE" "$OUT_DIR/"
        cp "$TESS_DIR"/*.dll "$OUT_DIR/" 2>/dev/null || true

        mkdir -p "$OUT_DIR/tessdata"
        TESS_TRAINEDDATA=$(find "$TMPDIR/tesseract" -name "eng.traineddata" -type f | head -1)
        if [ -n "$TESS_TRAINEDDATA" ]; then
            cp "$TESS_TRAINEDDATA" "$OUT_DIR/tessdata/"
        else
            echo "Downloading eng.traineddata..."
            curl -fSL -o "$OUT_DIR/tessdata/eng.traineddata" "$TESSDATA_URL"
        fi

        rm -rf "$TMPDIR"
        touch "$OUT_DIR/.downloaded-${OS}"
        ;;

    *)
        echo "Unsupported OS: ${OS}" >&2
        exit 1
        ;;
esac

echo "OCR tools ready at: ${OUT_DIR}"
ls -la "$OUT_DIR/"
