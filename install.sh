#!/usr/bin/env bash
set -euo pipefail

# MLBB Old VPN Checker — First-time / Update Setup (Termux Native / Linux / macOS)
main() {
    cd "$(dirname "${BASH_SOURCE[0]}")"
    export PATH="$PATH:/usr/sbin:/sbin"

    echo "[*] MLBB Old VPN Checker — First-time / Update Setup"

    if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        # Avoid creating root-owned .git objects when running sudo on a non-root repo
        local repo_uid
        repo_uid=$(stat -c '%u' . 2>/dev/null || stat -f '%u' . 2>/dev/null || echo "")
        if [ -z "$repo_uid" ] || [ "$(id -u)" -eq "$repo_uid" ]; then
            echo "[*] Sync file terbaru dari origin/main..."
            if git fetch origin main 2>/dev/null; then
                if ! git pull --ff-only origin main 2>/dev/null; then
                    echo "[!] git pull --ff-only dilewati (ada perubahan/file lokal) -> update core files dari FETCH_HEAD..."
                    git checkout FETCH_HEAD -- old_browser_vpn.py vpn_pool.sh requirements.txt .gitignore .gitattributes 2>/dev/null || true
                fi
            fi
        else
            echo "[*] Repo bukan milik root -> lewati git sync otomatis."
        fi
    fi
    if [ -f vpn_pool.sh ] && [ ! -x vpn_pool.sh ]; then
        chmod +x vpn_pool.sh || true
    fi

    # 1. Termux Native (Android Bionic): pakai system Chromium + Playwright + OpenVPN
    if [ -n "${TERMUX_VERSION:-}" ] && { [ ! -f /etc/os-release ] || [ "${PREFIX:-}" = "/data/data/com.termux/files/usr" ]; }; then
        echo "[*] Termux Native terdeteksi -> memasang python, chromium, dan openvpn..."
        pkg update -y
        pkg install -y x11-repo tur-repo
        pkg install -y python chromium
        (pkg install -y root-repo && pkg install -y openvpn) || true
        python3 -m pip install playwright pycryptodome zstandard colorama
        echo "[*] Menjalankan verifikasi..."
        python3 old_browser_vpn.py --selftest
        echo ""
        echo "[✓] Instalasi Termux Native selesai! Jalankan dengan:"
        echo "    python3 old_browser_vpn.py"
        exit 0
    fi

    local SUDO=""
    if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi

    local apt_updated=0
    if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "import ensurepip" >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1 || ! command -v openvpn >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1 || ! command -v sysctl >/dev/null 2>&1 || ! command -v flock >/dev/null 2>&1; then
        if [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ]; then
            if command -v apt-get >/dev/null 2>&1; then
                echo "[*] Memasang paket dasar apt (python3, venv, pip, curl, openvpn, iproute2, iptables, procps, util-linux)..."
                $SUDO apt-get update -y
                apt_updated=1
                $SUDO apt-get install -y python3 python3-venv python3-pip curl ca-certificates openvpn iproute2 iptables procps util-linux
            elif command -v dnf >/dev/null 2>&1; then
                $SUDO dnf install -y python3 python3-pip curl ca-certificates openvpn iproute iptables procps-ng util-linux
            elif command -v pacman >/dev/null 2>&1; then
                $SUDO pacman -S --needed --noconfirm python python-pip curl ca-certificates openvpn iproute2 iptables procps-ng util-linux
            fi
        fi
    fi

    if ! command -v microsocks >/dev/null 2>&1 && { [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ]; }; then
        if command -v apt-get >/dev/null 2>&1; then
            echo "[*] Memasang microsocks (opsional untuk Multi-VPN pool)..."
            [ "$apt_updated" -eq 0 ] && { $SUDO apt-get update -y || true; }
            $SUDO apt-get install -y microsocks || echo "[!] microsocks tidak tersedia di repo; mode single-VPN tetap bisa dipakai."
        fi
    fi

    if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
        echo "[!] Python 3.10+ diperlukan."
        exit 1
    fi

    if [ ! -f ".venv_old/bin/activate" ] || ! .venv_old/bin/python -m pip --version >/dev/null 2>&1; then
        echo "[*] Membuat virtualenv .venv_old..."
        python3 -m venv --clear .venv_old
    fi
    # shellcheck disable=SC1091
    source .venv_old/bin/activate

    echo "[*] Memasang dependensi Python dari requirements.txt..."
    python -m pip install --upgrade pip setuptools wheel
    python -m pip install -r requirements.txt

    if [ "$(uname -s)" = "Linux" ]; then
        if command -v apt-get >/dev/null 2>&1; then
            echo "[*] Memasang library sistem Chromium (playwright install-deps)..."
            if ! python -m playwright install-deps chromium; then
                if [ -n "$SUDO" ]; then
                    $SUDO "$(pwd)/.venv_old/bin/python" -m playwright install-deps chromium
                else
                    echo "[!] Gagal memasang dependency OS Chromium (install-deps)."
                    exit 1
                fi
            fi
        else
            echo "[!] Non-apt Linux terdeteksi -> lewati playwright install-deps (pastikan lib Chromium terpasang)."
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
}

main "$@"
