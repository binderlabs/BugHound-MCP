#!/bin/bash
# BugHound — Security Tools Installer
# Installs all external tools for full BugHound coverage (27 tools)

set -e

echo "BugHound — Installing security tools..."
echo ""

# ── Check Go ──
if ! command -v go &>/dev/null; then
    echo "[!] Go not found. Install Go first: https://go.dev/dl/"
    echo "    wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz"
    echo "    sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz"
    echo "    export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin"
    exit 1
fi

echo "[*] Go found: $(go version)"
echo ""

# ── Core tools (critical for scanning) ──
echo "[*] Installing core tools..."

go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
echo "  [+] httpx — HTTP probing"

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
echo "  [+] nuclei — Vulnerability scanning"

go install -v github.com/projectdiscovery/katana/cmd/katana@latest
echo "  [+] katana — Web crawling"

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo "  [+] subfinder — Subdomain discovery"

# ── Recon tools ──
echo ""
echo "[*] Installing recon tools..."

go install -v github.com/lc/gau/v2/cmd/gau@latest
echo "  [+] gau — Historical URL discovery"

go install -v github.com/tomnomnom/waybackurls@latest
echo "  [+] waybackurls — Wayback Machine URLs"

go install -v github.com/tomnomnom/assetfinder@latest
echo "  [+] assetfinder — Subdomain discovery"

go install -v github.com/jaeles-project/gospider@latest
echo "  [+] gospider — Web crawling"

go install -v github.com/Josue87/gotator@latest
echo "  [+] gotator — Subdomain permutation"

go install -v github.com/d3mondev/puredns/v2@latest
echo "  [+] puredns — DNS resolution/bruteforce"

# ── Discovery tools ──
echo ""
echo "[*] Installing discovery tools..."

go install -v github.com/ffuf/ffuf/v2@latest
echo "  [+] ffuf — Directory fuzzing"

go install -v github.com/hahwul/dalfox/v2@latest
echo "  [+] dalfox — XSS scanner"

# ── One-liner pipeline tools ──
echo ""
echo "[*] Installing one-liner pipeline tools..."

go install -v github.com/tomnomnom/qsreplace@latest
echo "  [+] qsreplace — Query string replacement"

go install -v github.com/Emoe/kxss@latest
echo "  [+] kxss — XSS reflection detection"

go install -v github.com/KathanP19/Gxss@latest
echo "  [+] Gxss — XSS reflection + context"

go install -v github.com/tomnomnom/gf@latest
echo "  [+] gf — URL pattern matching"

go install -v github.com/tomnomnom/unfurl@latest
echo "  [+] unfurl — URL component extraction"

go install -v github.com/tomnomnom/anew@latest
echo "  [+] anew — Unique line appending"

go install -v github.com/ameenmaali/urldedupe@latest
echo "  [+] urldedupe — Smart URL dedup"

go install -v github.com/R0X4R/bhedak@latest
echo "  [+] bhedak — Upgraded qsreplace"

# ── Python tools ──
echo ""
echo "[*] Installing Python tools..."

pip install sqlmap arjun wafw00f uro interlace 2>/dev/null || \
pip3 install sqlmap arjun wafw00f uro interlace 2>/dev/null || true
echo "  [+] sqlmap — SQLi validation"
echo "  [+] arjun — Parameter discovery"
echo "  [+] wafw00f — WAF detection"
echo "  [+] uro — URL deduplication"
echo "  [+] interlace — Parallel execution"

# ── Playwright (optional, for DOM XSS) ──
echo ""
echo "[*] Installing Playwright (DOM XSS detection)..."
pip install playwright 2>/dev/null || pip3 install playwright 2>/dev/null || true
python3 -m playwright install chromium 2>/dev/null || true
echo "  [+] playwright + chromium"

# ── Optional tools (not Go/pip — manual install) ──
echo ""
echo "[*] Optional tools (install manually if needed):"
echo "    findomain  — apt install findomain  OR  github.com/Edu4rdSHL/findomain"
echo "    amass      — go install -v github.com/owasp-amass/amass/v4/...@latest"
echo "    wpscan     — gem install wpscan  OR  apt install wpscan"
echo "    interactsh — go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

# ── Verify ──
echo ""
echo "[*] Verification:"
TOOLS="httpx nuclei katana subfinder gau waybackurls assetfinder gospider ffuf dalfox qsreplace kxss Gxss gf unfurl anew urldedupe bhedak sqlmap arjun wafw00f uro"
INSTALLED=0
TOTAL=0
for tool in $TOOLS; do
    TOTAL=$((TOTAL + 1))
    if command -v "$tool" &>/dev/null; then
        INSTALLED=$((INSTALLED + 1))
    else
        echo "  [!] $tool not found in PATH"
    fi
done
echo ""
echo "[+] $INSTALLED/$TOTAL tools installed. Run: ./bhound scan --help"

# Remind about PATH
echo ""
echo "[*] Make sure ~/go/bin is in your PATH:"
echo '    export PATH=$PATH:$HOME/go/bin'
echo '    echo "export PATH=\$PATH:\$HOME/go/bin" >> ~/.zshrc'
