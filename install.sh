#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

REPO_URL="https://github.com/pikpikcu/airecon"
BRANCH="main"

# ── Detect local vs remote (curl|bash) mode ─────────────────────────────────
# When piped via curl, BASH_SOURCE[0] is empty/stdin and pyproject.toml won't exist
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-/tmp}")" && pwd 2>/dev/null || echo /tmp)"
PYPROJECT="$SCRIPT_DIR/pyproject.toml"

if [ ! -f "$PYPROJECT" ]; then
    echo -e "${CYAN}[*] Remote install detected — cloning repository...${NC}"

    if ! command -v git &> /dev/null; then
        echo -e "${RED}[!] git is required but not installed.${NC}"
        exit 1
    fi

    TMP_DIR=$(mktemp -d)
    # Clean up temp dir on exit (only if we created it)
    trap 'rm -rf "$TMP_DIR"' EXIT

    git clone --depth=1 --branch "$BRANCH" "$REPO_URL" "$TMP_DIR" 2>&1 \
        || { echo -e "${RED}[!] Failed to clone repository.${NC}"; exit 1; }

    SCRIPT_DIR="$TMP_DIR"
    PYPROJECT="$SCRIPT_DIR/pyproject.toml"
fi

cd "$SCRIPT_DIR"

# ── Detect version from pyproject.toml ──────────────────────────────────────
if [ -f "$PYPROJECT" ]; then
    NEW_VERSION=$(grep -m1 '^version' "$PYPROJECT" | sed 's/version = "\(.*\)"/\1/')
else
    NEW_VERSION="unknown"
fi

echo -e ""
echo -e "${CYAN}${BOLD}  ▄▖▄▖▄▖${NC}"
echo -e "${CYAN}${BOLD}  ▌▌▐ ▙▘█▌▛▘▛▌▛▌${NC}"
echo -e "${CYAN}${BOLD}  ▛▌▟▖▌▌▙▖▙▖▙▌▌▌${NC}"
echo -e "${CYAN}  v${NEW_VERSION} — AI-Powered Security Reconnaissance${NC}"
echo -e ""

# ── Check currently installed version ───────────────────────────────────────
CURRENT_VERSION=""
if command -v airecon &> /dev/null; then
    CURRENT_VERSION=$(airecon --version 2>/dev/null | awk '{print $NF}' || true)
fi

if [ -n "$CURRENT_VERSION" ]; then
    if [ "$CURRENT_VERSION" = "$NEW_VERSION" ]; then
        echo -e "${YELLOW}[!] v${CURRENT_VERSION} is already installed. Reinstalling...${NC}"
    else
        echo -e "${YELLOW}[!] Upgrading: v${CURRENT_VERSION} → v${NEW_VERSION}${NC}"
    fi
else
    echo -e "${GREEN}[+] Installing AIRecon v${NEW_VERSION}...${NC}"
fi

echo -e "${GREEN}[+] Checking environment...${NC}"

# Define system python
PYTHON_CMD="python3"
if [ -f "/usr/bin/python3" ]; then
    PYTHON_CMD="/usr/bin/python3"
fi

echo -e "${GREEN}[+] Using Python: $PYTHON_CMD${NC}"

# Function to uninstall airecon completely
uninstall_airecon() {
    echo -e "${YELLOW}[!] Cleaning previous installations...${NC}"

    # 1. Uninstall from current environment (venv or otherwise)
    if pip show airecon &> /dev/null; then
        echo -e "${YELLOW}[!] Found existing AIRecon in current environment. Removing...${NC}"
        pip uninstall -y airecon --break-system-packages 2>/dev/null || pip uninstall -y airecon 2>/dev/null
    fi

    # 2. Uninstall from system python user site (force clean slate)
    if $PYTHON_CMD -m pip show airecon &> /dev/null; then
        echo -e "${YELLOW}[!] Found existing AIRecon in user site ($PYTHON_CMD). Removing...${NC}"
        $PYTHON_CMD -m pip uninstall -y airecon --break-system-packages 2>/dev/null || true
    fi

    # Try to clear pip cache for airecon
    echo -e "${YELLOW}[!] Clearing pip cache...${NC}"
    pip cache remove airecon &> /dev/null || true
    $PYTHON_CMD -m pip cache remove airecon &> /dev/null || true

    # Also remove build artifacts
    echo -e "${YELLOW}[!] Cleaning build artifacts...${NC}"
    rm -rf dist/ build/ *.egg-info
}

# Check Poetry
if ! command -v poetry &> /dev/null; then
    echo -e "${YELLOW}[!] Poetry not found. Installing via pip...${NC}"
    if command -v pip3 &> /dev/null; then
        pip3 install poetry --break-system-packages
    elif command -v pip &> /dev/null; then
        pip install poetry --break-system-packages
    else
        echo -e "${RED}[!] pip not found. Cannot install poetry.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[+] Poetry is already installed.${NC}"
fi

# Clean previous installs
uninstall_airecon

echo -e "${GREEN}[+] Updating dependencies...${NC}"
poetry install

echo -e "${GREEN}[+] Installing Playwright browsers...${NC}"
poetry run playwright install chromium

echo -e "${GREEN}[+] Building package...${NC}"
poetry build

echo -e "${GREEN}[+] Installing to ~/.local/bin...${NC}"
mkdir -p "$HOME/.local/bin"

# Find the built wheel
WHEEL_FILE=$(find dist -name "airecon-*.whl" | head -n 1)
if [ -z "$WHEEL_FILE" ]; then
    echo -e "${RED}[!] Build failed. No wheel file found.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Installing wheel globally to user site...${NC}"
if $PYTHON_CMD -m pip install "$WHEEL_FILE" --user --no-cache-dir --force-reinstall --break-system-packages; then
    echo -e "${GREEN}[+] Package installed successfully to user site.${NC}"
else
    echo -e "${RED}[!] Installation failed.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Done!${NC}"

# Check location - verify using the INSTALLER path
INSTALLED_BIN="$HOME/.local/bin/airecon"
if [ ! -f "$INSTALLED_BIN" ]; then
    echo -e "${YELLOW}[!] 'airecon' binary not found at $INSTALLED_BIN.${NC}"
    echo -e "${YELLOW}[!] Checking where it might be...${NC}"
    $PYTHON_CMD -m pip show -f airecon | grep "bin/airecon" || true
else
    echo -e "${GREEN}[+] Verified: $INSTALLED_BIN exists.${NC}"
    INSTALLED_VERSION=$($INSTALLED_BIN --version 2>/dev/null | awk '{print $NF}' || true)
    # Normalize PEP 440: "0.1.6-beta" == "0.1.6b0" — strip dashes/dots for comparison
    normalize_ver() { echo "$1" | sed 's/-//g; s/\.//g' | tr '[:upper:]' '[:lower:]'; }
    if [ "$(normalize_ver "$INSTALLED_VERSION")" = "$(normalize_ver "$NEW_VERSION")" ]; then
        echo -e "${GREEN}[+] Version: ${BOLD}v${INSTALLED_VERSION}${NC}${GREEN} ✓${NC}"
    else
        echo -e "${YELLOW}[!] Version mismatch — expected v${NEW_VERSION}, got v${INSTALLED_VERSION}${NC}"
    fi

    if command -v airecon &> /dev/null; then
        echo -e "${GREEN}[+] 'airecon' is in your PATH.${NC}"
    else
        echo -e "${YELLOW}[!] 'airecon' is installed but NOT in your PATH.${NC}"
        echo -e "You need to add ~/.local/bin to your PATH."
        echo -e "Add this to your .bashrc or .zshrc:"
        echo -e "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi
