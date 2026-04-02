#!/usr/bin/env bash
set -euo pipefail

# Builds llama-server from upstream llama.cpp and downloads
# the Phi-4 Mini Instruct Q4_K_M GGUF model file.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../src-tauri/llama-server"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

LLAMA_CPP_REPO="https://github.com/ggml-org/llama.cpp"
MODEL_URL="https://huggingface.co/bartowski/microsoft_Phi-4-mini-instruct-GGUF/resolve/main/microsoft_Phi-4-mini-instruct-Q4_K_M.gguf"
MODEL_FILE="phi-4-mini-instruct-q4_k_m.gguf"

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

    echo "Cloning llama.cpp..."
    git clone --depth 1 "$LLAMA_CPP_REPO" "$tmpdir/llama.cpp"
    cd "$tmpdir/llama.cpp"

    echo "Building llama-server (static)..."
    case "$os" in
        linux)
            if command -v nvcc &>/dev/null; then
                cmake -B build -DBUILD_SHARED_LIBS=OFF -DGGML_CUDA=ON
            else
                cmake -B build -DBUILD_SHARED_LIBS=OFF
            fi
            cmake --build build -j --target llama-server
            cp build/bin/llama-server "$OUT_DIR/llama-server"

            # Copy all .so files from the build tree
            find build -name '*.so*' -exec cp {} "$OUT_DIR/" \; 2>/dev/null || true

            # Discover all shared library dependencies via ldd and bundle non-system ones
            local system_so_patterns="linux-vdso linux-gate ld-linux libc.so libm.so libpthread.so libdl.so librt.so libgcc_s.so libstdc++ libresolv.so libnss libnsl libcrypt.so libutil.so"

            ldd "$OUT_DIR/llama-server" 2>/dev/null | grep '=> /' | awk '{print $3}' | while read -r lib; do
                local libname
                libname="$(basename "$lib")"
                # Skip system libraries
                local is_system=0
                for pat in $system_so_patterns; do
                    case "$libname" in
                        ${pat}*) is_system=1; break ;;
                    esac
                done
                [ "$is_system" = "1" ] && continue
                # Already bundled
                [ -f "$OUT_DIR/$libname" ] && continue
                cp "$lib" "$OUT_DIR/"
                echo "Bundled $libname from $lib"
            done
            ;;
        macos)
            cmake -B build -DBUILD_SHARED_LIBS=OFF
            cmake --build build -j --target llama-server
            cp build/bin/llama-server "$OUT_DIR/llama-server"

            # Copy all .dylib files from the build tree
            find build -name '*.dylib' -exec cp {} "$OUT_DIR/" \; 2>/dev/null || true

            # Discover all dylib dependencies via otool and bundle non-system ones
            otool -L "$OUT_DIR/llama-server" 2>/dev/null | tail -n +2 | awk '{print $1}' | while read -r lib; do
                # Skip system frameworks and libraries
                case "$lib" in
                    /usr/lib/*|/System/*|@rpath/*|@executable_path/*|@loader_path/*) continue ;;
                esac
                local libname
                libname="$(basename "$lib")"
                [ -f "$OUT_DIR/$libname" ] && continue
                if [ -f "$lib" ]; then
                    cp "$lib" "$OUT_DIR/"
                    echo "Bundled $libname from $lib"
                fi
            done

            # Rewrite dylib load paths to @loader_path/ so the binary finds bundled libs
            for dylib_path in $(otool -L "$OUT_DIR/llama-server" 2>/dev/null | tail -n +2 | awk '{print $1}'); do
                local dylib_name
                dylib_name="$(basename "$dylib_path")"
                if [ -f "$OUT_DIR/$dylib_name" ] && [ "$dylib_path" != "@loader_path/$dylib_name" ]; then
                    install_name_tool -change "$dylib_path" "@loader_path/$dylib_name" "$OUT_DIR/llama-server" 2>/dev/null || true
                fi
            done
            # Also fix IDs on bundled dylibs
            for bundled in "$OUT_DIR"/*.dylib; do
                [ -f "$bundled" ] || continue
                local bname
                bname="$(basename "$bundled")"
                install_name_tool -id "@loader_path/$bname" "$bundled" 2>/dev/null || true
            done
            ;;
        windows)
            cmake -B build -DBUILD_SHARED_LIBS=OFF
            cmake --build build -j --target llama-server --config Release
            local bindir="build/bin/Release"
            [ ! -d "$bindir" ] && bindir="build/bin"
            cp "$bindir/llama-server.exe" "$OUT_DIR/llama-server.exe"

            # Copy all DLLs from the entire build tree
            find build -name '*.dll' -exec cp {} "$OUT_DIR/" \; 2>/dev/null || true

            # Discover runtime DLL dependencies via dumpbin and bundle non-system ones
            local deps_found=0
            local deps_missing=0
            local system_patterns="kernel32 user32 advapi32 ws2_32 bcrypt crypt32 secur32 ntdll msvcrt ucrtbase vcruntime msvcp api-ms-win ext-ms-win ole32 oleaut32 shell32 gdi32 comctl32 comdlg32 shlwapi rpcrt4 imm32 winmm version setupapi cfgmgr32 winspool"
            local search_dirs="/c/Program\ Files/OpenSSL-Win64/bin /c/Program\ Files/OpenSSL/bin /c/Windows/System32 /c/ProgramData/chocolatey/bin /mingw64/bin /usr/bin"

            if command -v dumpbin.exe &>/dev/null; then
                local dep_dlls
                dep_dlls="$(dumpbin.exe //dependents "$OUT_DIR/llama-server.exe" 2>/dev/null \
                    | grep -iE '^\s+\S+\.dll$' | tr -d ' ' | tr '[:upper:]' '[:lower:]')" || true
            elif command -v objdump &>/dev/null; then
                local dep_dlls
                dep_dlls="$(objdump -p "$OUT_DIR/llama-server.exe" 2>/dev/null \
                    | grep 'DLL Name:' | awk '{print $3}' | tr '[:upper:]' '[:lower:]')" || true
            else
                echo "WARNING: Neither dumpbin nor objdump found, falling back to known DLL list"
                local dep_dlls="libssl-3-x64.dll libcrypto-3-x64.dll llama.dll ggml.dll mtmd.dll"
            fi

            for dll in $dep_dlls; do
                # Skip system DLLs
                local is_system=0
                for pat in $system_patterns; do
                    case "$dll" in
                        ${pat}*) is_system=1; break ;;
                    esac
                done
                [ "$is_system" = "1" ] && continue

                # Already bundled from build tree
                [ -f "$OUT_DIR/$dll" ] && continue

                # Try where.exe
                local found
                found="$(where.exe "$dll" 2>/dev/null | head -1)" || true
                if [ -n "$found" ] && [ -f "$found" ]; then
                    cp "$found" "$OUT_DIR/"
                    echo "Bundled $dll from $found"
                    deps_found=$((deps_found + 1))
                    continue
                fi

                # Search known directories
                local located=0
                for search_dir in \
                    "/c/Program Files/OpenSSL-Win64/bin" \
                    "/c/Program Files/OpenSSL/bin" \
                    "/c/Windows/System32" \
                    "/c/ProgramData/chocolatey/bin" \
                    "/mingw64/bin" \
                    "/usr/bin"; do
                    if [ -f "$search_dir/$dll" ]; then
                        cp "$search_dir/$dll" "$OUT_DIR/"
                        echo "Bundled $dll from $search_dir"
                        located=1
                        deps_found=$((deps_found + 1))
                        break
                    fi
                done

                if [ "$located" = "0" ]; then
                    echo "ERROR: $dll not found. Install OpenSSL: choco install openssl"
                    deps_missing=$((deps_missing + 1))
                fi
            done

            if [ "$deps_missing" -gt 0 ]; then
                echo ""
                echo "========================================="
                echo "  $deps_missing DLL(s) could not be found."
                echo "  Install OpenSSL and retry:"
                echo "    choco install openssl"
                echo "========================================="
            fi
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

    echo "Downloading Phi-4 Mini model (~2.5 GB)..."
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

# Model is downloaded on first launch by the app, not at build time.
# For local development, run: download_model
if [ "${1:-}" = "--with-model" ]; then
    download_model
fi

echo ""
echo "Done! Files in: $OUT_DIR"
ls -lh "$OUT_DIR"
