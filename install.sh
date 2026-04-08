#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
ORANGE='\033[38;5;214m'
CYAN='\033[0;36m'
BOLD='\033[1m'
MUTED='\033[0;2m'
NC='\033[0m'

REPO_URL="https://github.com/pikpikcu/airecon"
BRANCH="main"

# ── Print helpers ────────────────────────────────────────────────────────────
print_progress() {
    local bytes="$1"
    local length="$2"
    [ "$length" -gt 0 ] || return 0

    local width=50
    local percent=$(( bytes * 100 / length ))
    [ "$percent" -gt 100 ] && percent=100
    local on=$(( percent * width / 100 ))
    local off=$(( width - on ))

    local filled=$(printf "%*s" "$on" "")
    filled=${filled// /■}
    local empty=$(printf "%*s" "$off" "")
    empty=${empty// /·}

    printf "\r${ORANGE}%s%s %3d%%${NC}" "$filled" "$empty" "$percent" >&4
}

unbuffered_sed() {
    if echo | sed -u -e "" >/dev/null 2>&1; then
        sed -nu "$@"
    elif echo | sed -l -e "" >/dev/null 2>&1; then
        sed -nl "$@"
    else
        local pad="$(printf "\n%512s" "")"
        sed -ne "s/$/\\${pad}/" "$@"
    fi
}

download_with_progress() {
    local url="$1"
    local output="$2"

    if [ -t 2 ]; then
        exec 4>&2
    else
        exec 4>/dev/null
    fi

    local tmp_dir=${TMPDIR:-/tmp}
    local tracebase="${tmp_dir}/airecon_install_$$"
    local tracefile="${tracebase}.trace"

    rm -f "$tracefile"
    mkfifo "$tracefile"

    printf "\033[?25l" >&4

    trap "trap - RETURN; rm -f \"$tracefile\"; printf '\033[?25h' >&4; exec 4>&-" RETURN

    (
        curl --trace-ascii "$tracefile" -s -L -o "$output" "$url"
    ) &
    local curl_pid=$!

    unbuffered_sed \
        -e 'y/ACDEGHLNORTV/acdeghlnortv/' \
        -e '/^0000: content-length:/p' \
        -e '/^<= recv data/p' \
        "$tracefile" | \
    {
        local length=0
        local bytes=0

        while IFS=" " read -r -a line; do
            [ "${#line[@]}" -lt 2 ] && continue
            local tag="${line[0]} ${line[1]}"

            if [ "$tag" = "0000: content-length:" ]; then
                length="${line[2]}"
                length=$(echo "$length" | tr -d '\r')
                bytes=0
            elif [ "$tag" = "<= recv" ]; then
                local size="${line[3]}"
                bytes=$(( bytes + size ))
                if [ "$length" -gt 0 ]; then
                    print_progress "$bytes" "$length"
                fi
            fi
        done
    }

    wait "$curl_pid"
    local exit_code=$?
    echo "" >&4
    rm -f "$tracefile"
    return "$exit_code"
}

# ── Detect local vs remote (curl|bash) mode ─────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-/tmp}")" && pwd 2>/dev/null || echo /tmp)"
PYPROJECT="$SCRIPT_DIR/pyproject.toml"

if [ ! -f "$PYPROJECT" ]; then
    if ! command -v git &> /dev/null; then
        echo -e "${RED}[!] git is required but not installed.${NC}"
        exit 1
    fi

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    echo -e "${MUTED}[*] Cloning repository...${NC}"

    git clone --quiet --depth=1 --branch "$BRANCH" "$REPO_URL" "$TMP_DIR" 2>&1 \
        || { echo -e "${RED}[!] Failed to clone repository.${NC}"; exit 1; }

    SCRIPT_DIR="$TMP_DIR"
    PYPROJECT="$SCRIPT_DIR/pyproject.toml"
fi

cd "$SCRIPT_DIR"

# ── Detect version ──────────────────────────────────────────────────────────
NEW_VERSION=$(grep -m1 '^version' "$PYPROJECT" | sed 's/version = "\(.*\)"/\1/')

normalize_ver() {
    echo "$1" | sed 's/-beta$/b0/; s/-alpha$/a0/; s/-rc\([0-9]*\)$/rc\1/'
}

PYTHON_CMD="python3"
[ -f "/usr/bin/python3" ] && PYTHON_CMD="/usr/bin/python3"

# ── Show currently installed version ───────────────────────────────────────
CURRENT_VERSION=""
if command -v airecon &> /dev/null; then
    CURRENT_VERSION=$(airecon --version 2>/dev/null | awk '{print $NF}' || true)
fi
if [ -n "$CURRENT_VERSION" ]; then
    echo -e "Installed AIRecon version: ${BOLD}v${CURRENT_VERSION}${NC}"
fi
echo -e "Installing airecon version: ${BOLD}${NEW_VERSION}${NC}"

# ── Check Python >= 3.12 ─────────────────────────────────────────────────────
PY_OK=$($PYTHON_CMD -c "import sys; print('yes' if sys.version_info >= (3,12) else 'no')" 2>/dev/null || echo "no")
if [ "$PY_OK" != "yes" ]; then
    PY_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
    echo -e "${RED}[!] Python >= 3.12 required, found $PY_VERSION${NC}"
    exit 1
fi

# ── Version comparison ───────────────────────────────────────────────────
if [ -n "$CURRENT_VERSION" ]; then
    if [ "$(normalize_ver "$CURRENT_VERSION")" = "$(normalize_ver "$NEW_VERSION")" ]; then
        echo -e "${MUTED}  Already installed, reinstalling...${NC}"
    else
        echo -e "${MUTED}  Upgrading v${CURRENT_VERSION} → v${NEW_VERSION}${NC}"
    fi
fi

# ── Check Poetry ─────────────────────────────────────────────────────────────
if ! command -v poetry &> /dev/null; then
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}[!] curl is required to install Poetry.${NC}"
        exit 1
    fi
    curl -sSL https://install.python-poetry.org | python3 - > /dev/null 2>&1
    export PATH="$HOME/.local/bin:$PATH"
fi

# ── Uninstall previous (quiet) ───────────────────────────────────────────────
pip uninstall -y airecon > /dev/null 2>&1 || true
rm -rf dist/ build/ *.egg-info

# ── Build wheel (quiet) ──────────────────────────────────────────────────────
POETRY_VIRTUALENVS_CREATE=false poetry build > /dev/null 2>&1

# ── Install wheel to user site with real download progress ──────────────────
mkdir -p "$HOME/.local/bin"

WHEEL_FILE=$(find dist -name "airecon-*.whl" | head -n 1)
if [ -z "$WHEEL_FILE" ]; then
    echo -e "${RED}[!] Build failed. No wheel file found.${NC}"
    exit 1
fi

echo -e "${MUTED}Installing...${NC}"

# Run pip in background, show animated progress bar
$PYTHON_CMD -m pip install "$WHEEL_FILE" --user --no-cache-dir --force-reinstall --break-system-packages --quiet > /dev/null 2>&1 &
_PIP_PID=$!

_width=50
_i=0
while kill -0 "$_PIP_PID" 2>/dev/null; do
    _i=$(( _i + 1 ))
    [ "$_i" -gt "$_width" ] && _i=$_width
    _pct=$(( (_i * 100) / _width ))
    _f=$(printf "%${_i}s" "")
    _f=${_f// /■}
    _e=$(printf "%$(( _width - _i ))s" "")
    _e=${_e// /·}
    printf "\r${BOLD}%s%s %3d%%${NC}" "$_f" "$_e" "$_pct"
    sleep 0.15
done
wait "$_PIP_PID"
_PIP_RC=$?

# Clear progress line
printf '\r\033[K'
echo ""

echo -e "${GREEN}Installing Complete!${NC}"
echo -e ""

# ── Install Playwright (quiet) ──────────────────────────────────────────────
$PYTHON_CMD -m playwright install chromium > /dev/null 2>&1 || true

# ── Print banner ───────────────────────────────────────────────────────────
INSTALLED_VERSION=$($PYTHON_CMD -c "
try:
    from airecon._version import __version__
    print(__version__)
except:
    print('${NEW_VERSION}')
" 2>/dev/null || echo "$NEW_VERSION")

echo -e "     █████████   █████ ███████████"
echo -e "    ███▒▒▒▒▒███ ▒▒███ ▒▒███▒▒▒▒▒███"
echo -e "   ▒███    ▒███  ▒███  ▒███    ▒███   ██████   ██████   ██████  ████████"
echo -e "   ▒███████████  ▒███  ▒██████████   ███▒▒███ ███▒▒███ ███▒▒███▒▒███▒▒███"
echo -e "   ▒███▒▒▒▒▒███  ▒███  ▒███▒▒▒▒▒███ ▒███████ ▒███ ▒▒▒ ▒███ ▒███ ▒███ ▒███"
echo -e "   ▒███    ▒███  ▒███  ▒███    ▒███ ▒███▒▒▒  ▒███  ███▒███ ▒███ ▒███ ▒███"
echo -e "   █████   █████ █████ █████   █████▒▒██████ ▒▒██████ ▒▒██████  ████ █████"
echo -e "   ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒  ▒▒▒▒▒▒   ▒▒▒▒▒▒   ▒▒▒▒▒▒  ▒▒▒▒ ▒▒▒▒▒"
echo -e ""
echo -e "${MUTED}            v${INSTALLED_VERSION} — AI-Powered Security Reconnaissance${NC}"
echo -e ""
echo -e "  ${MUTED}Quick start:${NC} ${CYAN}airecon start${NC}"
echo -e "  ${MUTED}See all options:${NC} ${CYAN}airecon -h${NC}"
echo -e ""
echo -e "  ${MUTED}For more information visit ${CYAN}https://pikpikcu.github.io/airecon/${NC}"
echo -e ""

# ── Verify PATH ───────────────────────────────────────────────────────────
if command -v airecon &> /dev/null; then
    echo -e "${GREEN}[+] airecon is in your PATH. Run: airecon start${NC}"
else
    echo -e "${MUTED}Add to your .bashrc/.zshrc:${NC}"
    echo -e "    ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
fi
echo -e ""
