#!/bin/bash
# Install Deep Scanning Tools for BugHound Phase 3

echo "🚀 Starting Deep Scan Tools Installation..."

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 1. Go Tools
echo "📦 Installing Go Tools..."

if ! command_exists gau; then
    echo "   Installing gau..."
    go install github.com/lc/gau/v2/cmd/gau@latest
fi

if ! command_exists dalfox; then
    echo "   Installing dalfox..."
    go install github.com/hahwul/dalfox/v2@latest
fi

if ! command_exists subjack; then
    echo "   Installing subjack..."
    go install github.com/haccer/subjack@latest
fi

if ! command_exists ffuf; then
    echo "   Installing ffuf..."
    go install github.com/ffuf/ffuf/v2@latest
fi

if ! command_exists trufflehog; then
    echo "   Installing trufflehog..."
    go install github.com/trufflesecurity/trufflehog/v3@latest
fi

# 2. APT Tools (SQLMap)
echo "📦 Installing APT Tools..."
echo "kali" | sudo -S apt-get update
echo "kali" | sudo -S apt-get install -y sqlmap

# 3. Python Tools (Arjun)
echo "📦 Installing Python Tools..."
pip3 install arjun --break-system-packages

echo "✅ Installation Complete!"
echo "   Make sure ~/go/bin is in your PATH."
