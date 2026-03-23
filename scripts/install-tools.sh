#!/bin/bash
# BugHound — Security Tools Installer
# Installs Go-based security tools for full BugHound coverage

set -e

echo "BugHound — Installing security tools..."
echo ""

# Check Go
if ! command -v go &>/dev/null; then
    echo "[!] Go not found. Install Go first: https://go.dev/dl/"
    exit 1
fi

echo "[*] Installing Go tools..."

go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
echo "  [+] nuclei installed"

go install github.com/projectdiscovery/httpx/cmd/httpx@latest
echo "  [+] httpx installed"

go install github.com/projectdiscovery/katana/cmd/katana@latest
echo "  [+] katana installed"

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo "  [+] subfinder installed"

go install github.com/lc/gau/v2/cmd/gau@latest
echo "  [+] gau installed"

go install github.com/tomnomnom/waybackurls@latest
echo "  [+] waybackurls installed"

go install github.com/tomnomnom/assetfinder@latest
echo "  [+] assetfinder installed"

go install github.com/hahwul/dalfox/v2@latest
echo "  [+] dalfox installed"

go install github.com/ffuf/ffuf/v2@latest
echo "  [+] ffuf installed"

go install github.com/Josue87/gotator@latest
echo "  [+] gotator installed"

go install github.com/d3mondev/puredns/v2@latest
echo "  [+] puredns installed"

echo ""
echo "[*] Installing Python tools..."
pip install sqlmap arjun wafw00f 2>/dev/null || pip3 install sqlmap arjun wafw00f
echo "  [+] sqlmap, arjun, wafw00f installed"

echo ""
echo "[*] Installing Playwright (DOM XSS detection)..."
pip install playwright 2>/dev/null || pip3 install playwright
python3 -m playwright install chromium 2>/dev/null
echo "  [+] playwright + chromium installed"

echo ""
echo "[+] All tools installed. Run: ./bhound scan --help"
