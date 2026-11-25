#!/usr/bin/env bash
set -euo pipefail

# MLBB Old VPN Checker — First-time Setup (Termux Native / Termux proot-distro / Linux / macOS)
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "[*] MLBB Old VPN Checker — First-time / Update Setup"

if [ -d .git ] && command -v git >/dev/null 2>&1; then
    echo "[*] Sync file terbaru dari origin/main..."
    git fetch origin main && git checkout origin/main -- old_browser_vpn.py vpn_pool.sh .gitignore .gitattributes || true
fi
[ -f vpn_pool.sh ] && chmod +x vpn_pool.sh

# 1. Termux Native (Android Bionic): pakai system Chromium + Playwright + OpenVPN
if [ -n "${TERMUX_VERSION:-}" ] && { [ ! -f /etc/os-release ] || [ "${PREFIX:-}" = "/data/data/com.termux/files/usr" ]; }; then
    echo "[*] Termux Native terdeteksi -> memasang python, chromium, dan openvpn..."
    pkg update -y
    pkg install -y python chromium openvpn
    python3 -m pip install --upgrade pip
    python3 -m pip install playwright pycryptodome zstandard colorama
    echo "[*] Menjalankan verifikasi..."
    python3 old_browser_vpn.py --selftest
    echo ""
    echo "[✓] Instalasi Termux Native selesai! Jalankan dengan:"
    echo "    python3 old_browser_vpn.py"
    exit 0
fi

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
fi

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "import ensurepip" >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1 || ! command -v openvpn >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1 || ! command -v microsocks >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ]; then
        if command -v apt-get >/dev/null 2>&1; then
            echo "[*] Memasang paket dasar apt (python3, venv, pip, curl, openvpn, iproute2, microsocks, iptables)..."
            $SUDO apt-get update -y
            $SUDO apt-get install -y python3 python3-venv python3-pip curl ca-certificates openvpn iproute2 microsocks iptables
        elif command -v dnf >/dev/null 2>&1; then
            $SUDO dnf install -y python3 python3-pip curl ca-certificates openvpn iproute iptables
        elif command -v pacman >/dev/null 2>&1; then
            $SUDO pacman -S --needed --noconfirm python python-pip curl ca-certificates openvpn iproute2 iptables
        fi
    fi
fi

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
    echo "[!] Python 3.10+ diperlukan."
    exit 1
fi

if [ ! -f ".venv_old/bin/activate" ]; then
    echo "[*] Membuat virtualenv .venv_old..."
    python3 -m venv .venv_old
fi
# shellcheck disable=SC1091
source .venv_old/bin/activate

echo "[*] Memasang dependensi Python dari requirements.txt..."
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

if [ "$(uname -s)" = "Linux" ]; then
    echo "[*] Memasang library sistem Chromium (playwright install-deps)..."
    if ! python -m playwright install-deps chromium; then
        if [ -n "$SUDO" ]; then
            $SUDO env "PATH=$PATH" python -m playwright install-deps chromium
        else
            echo "[!] Gagal memasang dependency OS Chromium (install-deps)."
            exit 1
        fi
    fi
fi

export CLOAKBROWSER_CACHE_DIR="$(pwd)/.cloak_old_cache"
echo "[*] Mengunduh binary CloakBrowser 0.6.5 keyless ke .cloak_old_cache..."
python -m cloakbrowser install

echo "[*] Menjalankan verifikasi..."
python old_browser_vpn.py --selftest

echo ""
echo "[✓] Instalasi selesai! Jalankan dengan:"
echo "    source .venv_old/bin/activate && sudo .venv_old/bin/python old_browser_vpn.py"
