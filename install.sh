#!/bin/sh
set -e

REPO="MakFly/ksec"
INSTALL_DIR="${KSEC_INSTALL_DIR:-$HOME/.local/bin}"

main() {
    detect_platform
    fetch_latest_version
    download_binary
    install_binary
    print_success
}

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  PLATFORM="linux" ;;
        Darwin) PLATFORM="darwin" ;;
        *)      err "unsupported OS: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)             err "unsupported architecture: $ARCH" ;;
    esac

    ARTIFACT="ksec-${PLATFORM}-${ARCH}"
    log "detected platform: ${PLATFORM}/${ARCH}"
}

fetch_latest_version() {
    log "fetching latest version..."
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"//;s/".*//')"

    if [ -z "$VERSION" ]; then
        err "could not determine latest version. Check https://github.com/${REPO}/releases"
    fi

    log "latest version: ${VERSION}"
}

download_binary() {
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARTIFACT}"
    TMPDIR="$(mktemp -d)"
    TMPFILE="${TMPDIR}/ksec"

    log "downloading ${URL}..."
    if ! curl -fsSL -o "$TMPFILE" "$URL"; then
        rm -rf "$TMPDIR"
        err "download failed. Binary may not exist for ${PLATFORM}/${ARCH}."
    fi

    chmod +x "$TMPFILE"
}

install_binary() {
    mkdir -p "$INSTALL_DIR"
    mv "$TMPFILE" "${INSTALL_DIR}/ksec"
    rm -rf "$TMPDIR"
}

print_success() {
    log "installed ksec ${VERSION} to ${INSTALL_DIR}/ksec"

    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        echo ""
        log "add to your PATH:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        echo ""
    fi

    "${INSTALL_DIR}/ksec" --version 2>/dev/null || true
}

log() {
    echo "  → $1"
}

err() {
    echo "  ✗ $1" >&2
    exit 1
}

main
