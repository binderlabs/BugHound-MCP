#!/usr/bin/env bash
# BugHound — Security Tools Installer
# Installs external tools required for full BugHound coverage.
#
# Design:
#   - No `set -e` — we continue past failures and report at the end.
#   - Every install is verified by actually running `command -v <binary>`
#     AFTER the install step. `[+]` only prints on real success.
#   - Idempotent — re-running skips tools already in PATH.
#   - Python tools try pipx first (clean PEP 668 handling), then fall back
#     to `pip install --break-system-packages --user`.
#
# Usage:
#   ./scripts/install-tools.sh           # core + recon + python + seclists
#   ./scripts/install-tools.sh --full    # above + assetnote wordlists (~1GB)
#   ./scripts/install-tools.sh --minimal # core Go tools only (httpx/nuclei/katana/subfinder/ffuf)

set -u  # unset vars = error. Deliberately NOT set -e.

# ---------------------------------------------------------------------------
# Colors + helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; BLUE=''; BOLD=''; DIM=''; NC=''
fi

MODE="default"
for arg in "$@"; do
    case "$arg" in
        --full) MODE="full" ;;
        --minimal) MODE="minimal" ;;
        -h|--help)
            echo "Usage: $0 [--minimal|--full]"
            echo "  --minimal: core Go tools only"
            echo "  --full:    everything + assetnote wordlists (~1GB)"
            exit 0 ;;
    esac
done

INSTALLED=()
FAILED=()
SKIPPED=()

log_ok()   { printf "  ${GREEN}[+]${NC} %s\n" "$1"; }
log_skip() { printf "  ${DIM}[=]${NC} %s ${DIM}(already installed)${NC}\n" "$1"; }
log_fail() { printf "  ${RED}[x]${NC} %s ${DIM}(%s)${NC}\n" "$1" "$2"; }
log_warn() { printf "  ${YELLOW}[!]${NC} %s\n" "$1"; }
log_info() { printf "${BLUE}[*]${NC} %s\n" "$1"; }
log_step() { printf "\n${BOLD}${BLUE}==>${NC} ${BOLD}%s${NC}\n" "$1"; }

# ---------------------------------------------------------------------------
# PATH bootstrap — must happen BEFORE any install so `command -v` works
# ---------------------------------------------------------------------------
GOBIN="${GOBIN:-$HOME/go/bin}"
LOCAL_BIN="$HOME/.local/bin"

case ":$PATH:" in
    *":$GOBIN:"*) ;;
    *) export PATH="$GOBIN:$PATH" ;;
esac
case ":$PATH:" in
    *":$LOCAL_BIN:"*) ;;
    *) export PATH="$LOCAL_BIN:$PATH" ;;
esac

# ---------------------------------------------------------------------------
# Preflight: Go must exist
# ---------------------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
    printf "${RED}[!]${NC} Go not found. Install Go 1.21+ first:\n"
    echo "    wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz"
    echo "    sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz"
    echo "    export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin"
    exit 1
fi
log_info "Go found: $(go version | awk '{print $3}')"
log_info "GOBIN:    $GOBIN"
log_info "Mode:     $MODE"
mkdir -p "$GOBIN"

# ---------------------------------------------------------------------------
# install_go_tool <binary_name> <module_path>
#   Installs via `go install` iff binary not already in PATH.
#   Verifies install by checking binary afterwards.
# ---------------------------------------------------------------------------
install_go_tool() {
    local bin="$1"
    local module="$2"

    if command -v "$bin" >/dev/null 2>&1; then
        log_skip "$bin"
        SKIPPED+=("$bin")
        return 0
    fi

    # Run go install, capture error output for diagnostics
    local err
    if err=$(go install -v "$module" 2>&1); then
        if command -v "$bin" >/dev/null 2>&1; then
            log_ok "$bin"
            INSTALLED+=("$bin")
            return 0
        else
            log_fail "$bin" "go install succeeded but $bin not in \$PATH — check GOBIN"
            FAILED+=("$bin")
            return 1
        fi
    else
        # Truncate error for readability
        local short_err
        short_err=$(echo "$err" | tail -1 | cut -c1-80)
        log_fail "$bin" "$short_err"
        FAILED+=("$bin")
        return 1
    fi
}

# ---------------------------------------------------------------------------
# install_pip_tool <binary_name> <pypi_name>
#   Tries pipx first (clean), then `pip install --user --break-system-packages`.
# ---------------------------------------------------------------------------
install_pip_tool() {
    local bin="$1"
    local pkg="${2:-$1}"

    if command -v "$bin" >/dev/null 2>&1; then
        log_skip "$bin"
        SKIPPED+=("$bin")
        return 0
    fi

    # Prefer pipx — handles PEP 668 cleanly, isolated envs per tool
    if command -v pipx >/dev/null 2>&1; then
        if pipx install --quiet "$pkg" >/dev/null 2>&1; then
            if command -v "$bin" >/dev/null 2>&1; then
                log_ok "$bin"
                INSTALLED+=("$bin")
                return 0
            fi
        fi
    fi

    # Fallback: pip with --break-system-packages (PEP 668 workaround)
    local pip_cmd
    for pip_cmd in pip3 pip; do
        if command -v "$pip_cmd" >/dev/null 2>&1; then
            if $pip_cmd install --quiet --user --break-system-packages "$pkg" >/dev/null 2>&1; then
                if command -v "$bin" >/dev/null 2>&1; then
                    log_ok "$bin"
                    INSTALLED+=("$bin")
                    return 0
                fi
            elif $pip_cmd install --quiet --user "$pkg" >/dev/null 2>&1; then
                if command -v "$bin" >/dev/null 2>&1; then
                    log_ok "$bin"
                    INSTALLED+=("$bin")
                    return 0
                fi
            fi
        fi
    done

    log_fail "$bin" "pip/pipx install failed — try manually: pipx install $pkg"
    FAILED+=("$bin")
    return 1
}

# ---------------------------------------------------------------------------
# install_apt <package> — silently skip if apt unavailable or package missing
# ---------------------------------------------------------------------------
install_apt() {
    local pkg="$1"
    local bin="${2:-$1}"

    if command -v "$bin" >/dev/null 2>&1; then
        log_skip "$bin"
        SKIPPED+=("$bin")
        return 0
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        log_fail "$bin" "apt-get not available on this system"
        FAILED+=("$bin")
        return 1
    fi

    if sudo -n apt-get install -y "$pkg" >/dev/null 2>&1; then
        if command -v "$bin" >/dev/null 2>&1; then
            log_ok "$bin"
            INSTALLED+=("$bin")
            return 0
        fi
    fi

    log_fail "$bin" "apt install $pkg failed — may need: sudo apt install $pkg"
    FAILED+=("$bin")
    return 1
}

# ---------------------------------------------------------------------------
# Python httpx shadow check — MUST run early so warnings show
# ---------------------------------------------------------------------------
check_httpx_shadow() {
    local httpx_path
    httpx_path=$(command -v httpx 2>/dev/null)
    if [ -n "$httpx_path" ]; then
        # Heuristic: Go httpx prints "projectdiscovery" in version
        if ! "$httpx_path" -version 2>&1 | grep -qi "projectdiscovery\|current version"; then
            log_warn "Python httpx detected at $httpx_path — will shadow Go httpx"
            log_warn "Fix: pip uninstall httpx   OR   prepend \$HOME/go/bin to PATH"
        fi
    fi
}
check_httpx_shadow

# ---------------------------------------------------------------------------
# Core Go tools (always install, even in --minimal)
# ---------------------------------------------------------------------------
log_step "Core tools (httpx, nuclei, katana, subfinder, ffuf, dnsx)"
install_go_tool httpx          github.com/projectdiscovery/httpx/cmd/httpx@latest
install_go_tool nuclei         github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
install_go_tool katana         github.com/projectdiscovery/katana/cmd/katana@latest
install_go_tool subfinder      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_go_tool ffuf           github.com/ffuf/ffuf/v2@latest
install_go_tool dnsx           github.com/projectdiscovery/dnsx/cmd/dnsx@latest

if [ "$MODE" = "minimal" ]; then
    log_info "Minimal mode — skipping recon/discovery/python tools."
else

# ---------------------------------------------------------------------------
# Recon tools
# ---------------------------------------------------------------------------
log_step "Recon tools (gau, waybackurls, assetfinder, gospider, puredns, alterx, chaos-client)"
install_go_tool gau            github.com/lc/gau/v2/cmd/gau@latest
install_go_tool waybackurls    github.com/tomnomnom/waybackurls@latest
install_go_tool assetfinder    github.com/tomnomnom/assetfinder@latest
install_go_tool gospider       github.com/jaeles-project/gospider@latest
install_go_tool gotator        github.com/Josue87/gotator@latest
install_go_tool puredns        github.com/d3mondev/puredns/v2@latest
install_go_tool alterx         github.com/projectdiscovery/alterx/cmd/alterx@latest
install_go_tool chaos          github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# ---------------------------------------------------------------------------
# Discovery / scanning tools
# ---------------------------------------------------------------------------
log_step "Discovery / scanning tools (dalfox, interactsh-client)"
install_go_tool dalfox             github.com/hahwul/dalfox/v2@latest
install_go_tool interactsh-client  github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# ---------------------------------------------------------------------------
# One-liner pipeline tools (TomNomNom + friends)
# ---------------------------------------------------------------------------
log_step "Pipeline tools (qsreplace, kxss, Gxss, gf, unfurl, anew, urldedupe, bhedak)"
install_go_tool qsreplace      github.com/tomnomnom/qsreplace@latest
install_go_tool kxss           github.com/Emoe/kxss@latest
install_go_tool Gxss           github.com/KathanP19/Gxss@latest
install_go_tool gf             github.com/tomnomnom/gf@latest
install_go_tool unfurl         github.com/tomnomnom/unfurl@latest
install_go_tool anew           github.com/tomnomnom/anew@latest
install_go_tool urldedupe      github.com/ameenmaali/urldedupe@latest
install_go_tool bhedak         github.com/R0X4R/bhedak@latest

# ---------------------------------------------------------------------------
# trufflehog — official shell installer (the go install path is broken)
# ---------------------------------------------------------------------------
log_step "trufflehog (verified secret detection)"
if command -v trufflehog >/dev/null 2>&1; then
    log_skip trufflehog
    SKIPPED+=("trufflehog")
else
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b "$GOBIN" >/dev/null 2>&1; then
        if command -v trufflehog >/dev/null 2>&1; then
            log_ok trufflehog
            INSTALLED+=("trufflehog")
        else
            log_fail trufflehog "installer ran but binary missing from $GOBIN"
            FAILED+=("trufflehog")
        fi
    else
        log_fail trufflehog "official installer failed — install manually from github.com/trufflesecurity/trufflehog"
        FAILED+=("trufflehog")
    fi
fi

# ---------------------------------------------------------------------------
# Python tools — sqlmap, arjun, wafw00f, uro
# ---------------------------------------------------------------------------
log_step "Python tools (sqlmap, arjun, wafw00f, uro)"
# Ensure pipx is available where possible
if ! command -v pipx >/dev/null 2>&1; then
    log_info "pipx not found — trying to install it for cleaner Python tool installs"
    if command -v apt-get >/dev/null 2>&1 && sudo -n apt-get install -y pipx >/dev/null 2>&1; then
        log_info "pipx installed via apt"
    elif command -v pip3 >/dev/null 2>&1; then
        pip3 install --user --break-system-packages pipx >/dev/null 2>&1 || \
            pip3 install --user pipx >/dev/null 2>&1 || true
    fi
    # Ensure pipx is on PATH
    if command -v pipx >/dev/null 2>&1; then
        pipx ensurepath >/dev/null 2>&1 || true
    fi
fi
install_pip_tool sqlmap        sqlmap
install_pip_tool arjun         arjun
install_pip_tool wafw00f       wafw00f
install_pip_tool uro           uro

# ---------------------------------------------------------------------------
# Playwright (Python + chromium browser for DOM XSS / workflow capture)
# ---------------------------------------------------------------------------
log_step "Playwright (DOM XSS + agent mode browser)"
PW_OK=0
if python3 -c "import playwright" 2>/dev/null; then
    log_skip "playwright (python module)"
    PW_OK=1
else
    for pip_cmd in pip3 pip; do
        if command -v "$pip_cmd" >/dev/null 2>&1; then
            if $pip_cmd install --quiet --user --break-system-packages playwright >/dev/null 2>&1 || \
               $pip_cmd install --quiet --user playwright >/dev/null 2>&1; then
                if python3 -c "import playwright" 2>/dev/null; then
                    log_ok "playwright (python module)"
                    INSTALLED+=("playwright")
                    PW_OK=1
                    break
                fi
            fi
        fi
    done
fi
if [ "$PW_OK" = "1" ]; then
    # Install the chromium browser itself
    if python3 -m playwright install chromium >/dev/null 2>&1; then
        log_ok "playwright chromium browser"
    else
        log_warn "playwright installed but chromium browser install failed — run: python3 -m playwright install chromium"
    fi
else
    log_fail playwright "pip install failed"
    FAILED+=("playwright")
fi

# ---------------------------------------------------------------------------
# SecLists + wordlists (for ffuf tiers)
# ---------------------------------------------------------------------------
log_step "Wordlists (seclists + optionally assetnote)"
if [ -d /usr/share/seclists ] || [ -d /usr/share/SecLists ]; then
    log_skip "seclists"
    SKIPPED+=("seclists")
else
    install_apt seclists seclists || \
        log_warn "install manually: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists"
fi

if [ "$MODE" = "full" ]; then
    ASSETNOTE_DIR="/usr/share/wordlists/assetnote"
    if [ -d "$ASSETNOTE_DIR" ] && [ -n "$(ls -A "$ASSETNOTE_DIR" 2>/dev/null)" ]; then
        log_skip "assetnote wordlists"
    else
        log_info "Fetching assetnote wordlists (~1GB — may take a while)"
        if sudo -n mkdir -p "$ASSETNOTE_DIR" >/dev/null 2>&1; then
            for url in \
                "https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2024_05_28.txt" \
                "https://wordlists-cdn.assetnote.io/data/manual/parameters.txt" \
                "https://wordlists-cdn.assetnote.io/data/manual/api_endpoints.txt" \
                "https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt"
            do
                fname=$(basename "$url")
                dest="$ASSETNOTE_DIR/$fname"
                if [ ! -s "$dest" ]; then
                    sudo curl -sL -o "$dest" "$url" && log_ok "assetnote: $fname"
                fi
            done
        else
            log_warn "sudo unavailable — fetch assetnote wordlists manually from wordlists.assetnote.io"
        fi
    fi
fi

fi  # end not-minimal

# ---------------------------------------------------------------------------
# Optional tools listing
# ---------------------------------------------------------------------------
log_step "Optional tools (install manually if needed)"
echo "  findomain  — apt install findomain  OR  github.com/Edu4rdSHL/findomain"
echo "  amass      — go install github.com/owasp-amass/amass/v4/...@latest"
echo "  wpscan     — gem install wpscan  OR  apt install wpscan"
echo "  massdns    — apt install massdns  (needed by puredns)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_step "Summary"
printf "  ${GREEN}Installed: %d${NC}    ${DIM}Skipped (already present): %d${NC}    ${RED}Failed: %d${NC}\n" \
    "${#INSTALLED[@]}" "${#SKIPPED[@]}" "${#FAILED[@]}"
echo ""

if [ ${#FAILED[@]} -gt 0 ]; then
    printf "${RED}${BOLD}Failed installs:${NC}\n"
    for t in "${FAILED[@]}"; do printf "  ${RED}[x]${NC} %s\n" "$t"; done
    echo ""
    printf "${YELLOW}Re-run this script after addressing the failures above.${NC}\n"
    printf "${YELLOW}Common fixes:${NC}\n"
    echo "  - Network issue? Retry the script."
    echo "  - Go module missing? Check your Go version: go version (need 1.21+)"
    echo "  - Python install blocked? Install pipx: sudo apt install pipx"
    echo "  - PATH issue? Ensure \$HOME/go/bin and \$HOME/.local/bin are in \$PATH"
fi

# ---------------------------------------------------------------------------
# Final persistent PATH reminder
# ---------------------------------------------------------------------------
case ":$PATH:" in
    *":$GOBIN:"*) : ;;
    *)
        echo ""
        log_warn "Add Go bin to your shell rc so the tools persist across sessions:"
        echo "    echo 'export PATH=\$PATH:\$HOME/go/bin:\$HOME/.local/bin' >> ~/.zshrc"
        echo "    source ~/.zshrc"
        ;;
esac

echo ""
log_info "Next step: ./bhound scan --help"
