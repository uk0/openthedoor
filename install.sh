#!/bin/bash
#
# fwctl - Universal Firewall Control Tool
# One-click installation script
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/firshme/fwctl/main/install.sh | sudo bash
#

set -e

REPO="uk0/openthedoor"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="fwctl"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (use sudo)"
    fi
}

# Detect architecture
detect_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        *)
            error "Unsupported architecture: $arch"
            ;;
    esac
}

# Detect OS
detect_os() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case $os in
        linux)
            echo "linux"
            ;;
        *)
            error "Unsupported OS: $os (only Linux is supported)"
            ;;
    esac
}

# Download and install
install_fwctl() {
    local os=$(detect_os)
    local arch=$(detect_arch)
    local binary="fwctl-${os}-${arch}"
    local url="https://github.com/${REPO}/releases/download/latest/${binary}"

    info "Detected: ${os}/${arch}"
    info "Downloading ${binary}..."

    # Create temp directory
    local tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    # Download binary
    if command -v curl &> /dev/null; then
        curl -fsSL "$url" -o "$tmp_dir/$BINARY_NAME" || error "Download failed. Check your network connection."
    elif command -v wget &> /dev/null; then
        wget -q "$url" -O "$tmp_dir/$BINARY_NAME" || error "Download failed. Check your network connection."
    else
        error "Neither curl nor wget found. Please install one of them."
    fi

    # Install binary
    info "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
    mv "$tmp_dir/$BINARY_NAME" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

    success "Installation complete!"
}

# Verify installation
verify_install() {
    echo ""
    info "Verifying installation..."
    echo ""

    # Check if binary exists and is executable
    if [ -x "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        ${INSTALL_DIR}/${BINARY_NAME} --help
        echo ""
        success "fwctl is ready to use!"
        echo ""
        echo -e "  ${CYAN}Quick Start:${NC}"
        echo "    fwctl scan          # Scan open ports"
        echo "    fwctl scan -i       # Interactive mode"
        echo "    fwctl block <port>  # Block a port"
        echo "    fwctl status        # Show firewall status"
        echo ""
    else
        error "Installation verification failed"
    fi
}

# Main
main() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           fwctl - Universal Firewall Control              ║${NC}"
    echo -e "${CYAN}║              Installation Script                          ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    check_root
    install_fwctl
    verify_install
}

main "$@"
