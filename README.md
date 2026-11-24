# MLBB Checker — VPN & Cross-Platform Edition (Windows / Linux / Termux)

Checker VPN-first berbasis CloakBrowser `0.6.5` keyless (`Windows` / `Linux` / `Termux proot-distro`) dan system `Chromium` (`Termux Native`). Mendukung pre-test + auto-rotate OpenVPN `.ovpn`, `--vpn-cmd`, `--vpn-wait`, dan `--waf-cooldown`.

## Setup
- **Windows / Linux / Termux `proot-distro` Ubuntu:**
  ```bash
  uv venv .venv_old
  uv pip install --python .venv_old/Scripts/python.exe -r requirements.txt
  ```
- **Termux Native (Android):**
  ```bash
  pkg update && pkg install -y python chromium
  pip install playwright pycryptodome zstandard colorama
  ```

## Jalankan
- **OpenVPN `.ovpn` auto-rotate (Windows PowerShell Run as Administrator / Linux `sudo`):**
  - Taruh file `*.ovpn` dan `auth.txt` (2 baris: username & password) ke folder `vpns/`.
  ```powershell
  # Uji semua .ovpn ke API Moonton saja
  .\.venv_old\Scripts\python.exe old_browser_vpn.py --vpn-ovpn-dir vpns --test-ovpn-only

  # Jalankan full checker (auto pre-test, urut tercepat, rotasi saat WAF/RATE)
  .\.venv_old\Scripts\python.exe old_browser_vpn.py input\combo.txt --workers 4 --no-prompt --vpn-ovpn-dir vpns --vpn-waf-threshold 3
  ```
- **VPN App luar Termux / GUI (`--vpn-wait`):**
  ```bash
  python3 old_browser_vpn.py input/combo.txt --workers 2 --no-prompt --vpn-wait
  ```
- **CLI VPN lain (`--vpn-cmd`):**
  ```bash
  python3 old_browser_vpn.py input/combo.txt --workers 4 --no-prompt --vpn-cmd "mullvad reconnect"
  ```
