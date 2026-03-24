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

# Normalize PEP 440 version: "0.1.6-beta" → "0.1.6b0", "0.1.6-alpha" → "0.1.6a0"
normalize_ver() {
    echo "$1" | sed 's/-beta$/b0/; s/-alpha$/a0/; s/-rc\([0-9]*\)$/rc\1/'
}

# ── Check Python >= 3.12 ─────────────────────────────────────────────────────
PYTHON_CMD="python3"
if [ -f "/usr/bin/python3" ]; then
    PYTHON_CMD="/usr/bin/python3"
fi

PY_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
PY_OK=$($PYTHON_CMD -c "import sys; print('yes' if sys.version_info >= (3,12) else 'no')" 2>/dev/null || echo "no")
if [ "$PY_OK" != "yes" ]; then
    echo -e "${RED}[!] Python >= 3.12 required, found $PY_VERSION${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Using Python $PY_VERSION ($PYTHON_CMD)${NC}"

# ── Check currently installed version ───────────────────────────────────────
CURRENT_VERSION=""
if command -v airecon &> /dev/null; then
    CURRENT_VERSION=$(airecon --version 2>/dev/null | awk '{print $NF}' || true)
fi

if [ -n "$CURRENT_VERSION" ]; then
    if [ "$(normalize_ver "$CURRENT_VERSION")" = "$(normalize_ver "$NEW_VERSION")" ]; then
        echo -e "${YELLOW}[!] v${CURRENT_VERSION} is already installed. Reinstalling...${NC}"
    else
        echo -e "${YELLOW}[!] Upgrading: v${CURRENT_VERSION} → v${NEW_VERSION}${NC}"
    fi
else
    echo -e "${GREEN}[+] Installing AIRecon v${NEW_VERSION}...${NC}"
fi

# Function to uninstall airecon completely
uninstall_airecon() {
    echo -e "${YELLOW}[!] Cleaning previous installations...${NC}"

    if pip show airecon &> /dev/null 2>&1; then
        echo -e "${YELLOW}[!] Found existing AIRecon in current environment. Removing...${NC}"
        pip uninstall -y airecon --break-system-packages 2>/dev/null || pip uninstall -y airecon 2>/dev/null || true
    fi

    if $PYTHON_CMD -m pip show airecon &> /dev/null 2>&1; then
        echo -e "${YELLOW}[!] Found existing AIRecon in user site. Removing...${NC}"
        $PYTHON_CMD -m pip uninstall -y airecon --break-system-packages 2>/dev/null || true
    fi

    pip cache remove airecon &> /dev/null 2>&1 || true
    $PYTHON_CMD -m pip cache remove airecon &> /dev/null 2>&1 || true
    rm -rf dist/ build/ *.egg-info
}

# ── Check Poetry ─────────────────────────────────────────────────────────────
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

# ── Build wheel (no venv needed — Poetry just packages the source) ───────────
echo -e "${GREEN}[+] Building package...${NC}"
POETRY_VIRTUALENVS_CREATE=false poetry build --quiet

# ── Install wheel to user site ───────────────────────────────────────────────
mkdir -p "$HOME/.local/bin"

WHEEL_FILE=$(find dist -name "airecon-*.whl" | head -n 1)
if [ -z "$WHEEL_FILE" ]; then
    echo -e "${RED}[!] Build failed. No wheel file found.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Installing to user site (~/.local)...${NC}"
# Suppress unrelated Kali tool dependency conflict warnings
if $PYTHON_CMD -m pip install "$WHEEL_FILE" \
    --user --no-cache-dir --force-reinstall --break-system-packages \
    --quiet 2>/dev/null; then
    echo -e "${GREEN}[+] Package installed successfully.${NC}"
else
    echo -e "${RED}[!] Installation failed.${NC}"
    exit 1
fi

# ── Install Playwright browser (after pip install, uses installed package) ───
echo -e "${GREEN}[+] Installing Playwright browsers...${NC}"
$PYTHON_CMD -m playwright install chromium 2>/dev/null \
    || echo -e "${YELLOW}[!] Playwright browser install failed (optional — browser features may not work).${NC}"

echo -e "${GREEN}[+] Done!${NC}"
echo -e ""

# ── Verify installation ───────────────────────────────────────────────────────
INSTALLED_BIN="$HOME/.local/bin/airecon"
if [ ! -f "$INSTALLED_BIN" ]; then
    echo -e "${YELLOW}[!] 'airecon' binary not found at $INSTALLED_BIN.${NC}"
    $PYTHON_CMD -m pip show -f airecon 2>/dev/null | grep "bin/airecon" || true
else
    INSTALLED_VERSION=$($INSTALLED_BIN --version 2>/dev/null | awk '{print $NF}' || true)
    if [ "$(normalize_ver "$INSTALLED_VERSION")" = "$(normalize_ver "$NEW_VERSION")" ]; then
        echo -e "${GREEN}[+] Version: ${BOLD}v${INSTALLED_VERSION}${NC}${GREEN} ✓${NC}"
    else
        echo -e "${YELLOW}[!] Version mismatch — expected v${NEW_VERSION}, got v${INSTALLED_VERSION}${NC}"
    fi

    if command -v airecon &> /dev/null; then
        echo -e "${GREEN}[+] 'airecon' is in your PATH. Run: airecon${NC}"
    else
        echo -e "${YELLOW}[!] 'airecon' is installed but NOT in your PATH.${NC}"
        echo -e "    Add this to your .bashrc or .zshrc:"
        echo -e "    ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    fi
fi
