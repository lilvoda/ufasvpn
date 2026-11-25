#!/usr/bin/env bash
# ponytail: lightweight multi-VPN tunnel pool via Linux ip netns + microsocks (for --proxy-file); requires root + netns support (on Proxmox LXC needs nesting=1)
set -u

STATE_DIR="/run/vpn_pool"

die() { echo "[!] $*" >&2; exit 1; }

need_root() {
    [ "$(id -u)" -eq 0 ] || die "Jalankan sebagai root (sudo)."
    for bin in openvpn microsocks ip iptables awk; do
        command -v "$bin" >/dev/null 2>&1 || die "Command '$bin' belum ada. Install dulu: apt-get update && apt-get install -y openvpn microsocks iptables"
    done
    ip netns add _vp_chk 2>/dev/null || die "ip netns gagal (di Proxmox LXC pastikan nesting=1 aktif)."
    ip netns del _vp_chk 2>/dev/null || true
}

find_auth() {
    local dir="$1" f
    for f in "$dir/auth.txt" "$dir/.auth" "$dir/credentials.txt" "$dir/pass.txt"; do
        [ -f "$f" ] && { echo "$f"; return 0; }
    done
    f=$(find "$dir" -maxdepth 1 -type f -name '*.auth' 2>/dev/null | head -n1)
    [ -n "$f" ] && echo "$f"
}

stop_slot() {
    local i="$1" p
    for kind in socks ovpn; do
        [ -f "$STATE_DIR/${kind}_${i}.pid" ] || continue
        p=$(cat "$STATE_DIR/${kind}_${i}.pid" 2>/dev/null || true)
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
        rm -f "$STATE_DIR/${kind}_${i}.pid"
    done
    ip netns del "vpnpool${i}" 2>/dev/null || true
    ip link del "vpnh${i}" 2>/dev/null || true
    rm -rf "/etc/netns/vpnpool${i}"
}

start_slot() {
    local i="$1" cfg="$2" auth="$3"
    local ns="vpnpool${i}" h="vpnh${i}" w="vpnw${i}"
    stop_slot "$i"
    mkdir -p "/etc/netns/${ns}"
    printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > "/etc/netns/${ns}/resolv.conf"

    ip netns add "$ns" || return 1
    ip link add "$h" type veth peer name "$w" || return 1
    ip link set "$w" netns "$ns" || return 1
    ip addr add "10.200.${i}.1/30" dev "$h"
    ip link set "$h" up
    ip -n "$ns" link set lo up
    ip -n "$ns" addr add "10.200.${i}.2/30" dev "$w"
    ip -n "$ns" link set "$w" up
    ip -n "$ns" route replace default via "10.200.${i}.1" dev "$w"

    local cmd=(openvpn --cd "$(dirname "$cfg")" --config "$cfg" --auth-nocache
        --ignore-unknown-option block-outside-dns --pull-filter ignore block-outside-dns
        --connect-retry 1 2 --resolv-retry 2 --fast-io)
    [ -n "$auth" ] && cmd+=(--auth-user-pass "$(readlink -f "$auth")")

    ip netns exec "$ns" "${cmd[@]}" >"$STATE_DIR/ovpn_${i}.log" 2>&1 &
    echo $! > "$STATE_DIR/ovpn_${i}.pid"
    ip netns exec "$ns" microsocks -i "10.200.${i}.2" -p 1080 >"$STATE_DIR/socks_${i}.log" 2>&1 &
    echo $! > "$STATE_DIR/socks_${i}.pid"
    echo "$cfg" > "$STATE_DIR/cfg_${i}"
}

setup_nat() {
    local wan
    wan=$(ip route show default | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [ -n "$wan" ] || die "Default interface (WAN) tidak ditemukan."
    sysctl -qw net.ipv4.ip_forward=1
    iptables -t nat -C POSTROUTING -s 10.200.0.0/16 -o "$wan" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -o "$wan" -j MASQUERADE
    iptables -C FORWARD -s 10.200.0.0/16 -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -s 10.200.0.0/16 -j ACCEPT
    iptables -C FORWARD -d 10.200.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -d 10.200.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT
}

cmd_stop() {
    local f i
    for f in "$STATE_DIR"/ovpn_*.pid; do
        [ -e "$f" ] || continue
        i=${f##*/ovpn_}; i=${i%.pid}
        stop_slot "$i"
    done
    rm -f "$STATE_DIR"/cfg_* "$STATE_DIR"/*.log "$STATE_DIR"/count "$STATE_DIR"/dir "$STATE_DIR"/auth "$STATE_DIR"/out 2>/dev/null || true
    echo "[*] Semua slot VPN pool dimatikan."
}

wait_slots() {
    local n="$1" out_file="$2" deadline=$((SECONDS + 25))
    : > "$out_file"
    local -a ready=()
    while [ "$SECONDS" -lt "$deadline" ]; do
        local up=0
        for i in $(seq 1 "$n"); do
            if [ "${ready[$i]:-0}" = "1" ]; then
                up=$((up + 1)); continue
            fi
            if grep -q "Initialization Sequence Completed" "$STATE_DIR/ovpn_${i}.log" 2>/dev/null; then
                ready[$i]=1
                up=$((up + 1))
            fi
        done
        [ "$up" -ge "$n" ] && break
        sleep 1
    done
    local ok=0
    for i in $(seq 1 "$n"); do
        if [ "${ready[$i]:-0}" = "1" ]; then
            echo "socks5://10.200.${i}.2:1080" >> "$out_file"
            ok=$((ok + 1))
            echo "  [+] slot $i READY: socks5://10.200.${i}.2:1080 ($(basename "$(cat "$STATE_DIR/cfg_${i}")"))"
        else
            echo "  [!] slot $i GAGAL/TIMEOUT: $(tail -n 2 "$STATE_DIR/ovpn_${i}.log" 2>/dev/null | tr '\n' ' ')"
            stop_slot "$i"
        fi
    done
    echo "[*] Aktif: $ok/$n tunnel -> $out_file"
    [ "$ok" -gt 0 ]
}

cmd_start() {
    local dir="${1:-}" n="${2:-6}" out_file="${3:-vpn_proxies.txt}"
    [ -d "$dir" ] || die "Folder .ovpn tidak ditemukan: $dir"
    dir=$(readlink -f "$dir")
    [ "$n" -ge 1 ] && [ "$n" -le 50 ] || die "Jumlah tunnel harus 1..50"
    need_root
    mkdir -p "$STATE_DIR"
    cmd_stop >/dev/null 2>&1 || true
    setup_nat

    local auth; auth=$(find_auth "$dir" || true)
    mapfile -t cfgs < <(find "$dir" -maxdepth 1 -type f -name '*udp.ovpn' | shuf)
    [ "${#cfgs[@]}" -gt 0 ] || mapfile -t cfgs < <(find "$dir" -maxdepth 1 -type f -name '*.ovpn' | shuf)
    [ "${#cfgs[@]}" -gt 0 ] || die "Tidak ada file .ovpn di $dir"

    echo "$dir" > "$STATE_DIR/dir"
    echo "$auth" > "$STATE_DIR/auth"
    echo "$n" > "$STATE_DIR/count"
    echo "$out_file" > "$STATE_DIR/out"

    echo "[*] Menyalakan $n tunnel paralel dari $dir..."
    for i in $(seq 1 "$n"); do
        local idx=$(( (i - 1) % ${#cfgs[@]} ))
        start_slot "$i" "${cfgs[$idx]}" "$auth"
    done
    wait_slots "$n" "$out_file"
}

cmd_rotate() {
    need_root
    [ -f "$STATE_DIR/dir" ] || die "Pool belum jalan."
    local dir auth n out_file target="${1:-all}"
    dir=$(cat "$STATE_DIR/dir"); auth=$(cat "$STATE_DIR/auth" 2>/dev/null || true)
    n=$(cat "$STATE_DIR/count"); out_file=$(cat "$STATE_DIR/out")
    mapfile -t cfgs < <(find "$dir" -maxdepth 1 -type f -name '*udp.ovpn' | shuf)
    [ "${#cfgs[@]}" -gt 0 ] || mapfile -t cfgs < <(find "$dir" -maxdepth 1 -type f -name '*.ovpn' | shuf)
    [ "${#cfgs[@]}" -gt 0 ] || die "Tidak ada .ovpn di $dir"

    local slots
    [ "$target" = "all" ] && slots=$(seq 1 "$n") || slots="$target"
    for i in $slots; do
        local cfg="${cfgs[$((RANDOM % ${#cfgs[@]}))]}"
        echo "[*] Rotasi slot $i -> $(basename "$cfg")..."
        start_slot "$i" "$cfg" "$auth"
    done
    wait_slots "$n" "$out_file"
}

cmd_status() {
    [ -f "$STATE_DIR/count" ] || { echo "[*] VPN pool tidak aktif."; return 0; }
    local n; n=$(cat "$STATE_DIR/count")
    for i in $(seq 1 "$n"); do
        local pid; pid=$(cat "$STATE_DIR/ovpn_${i}.pid" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            local cfg; cfg=$(basename "$(cat "$STATE_DIR/cfg_${i}" 2>/dev/null || echo "-")")
            local st="CONNECTING"
            grep -q "Initialization Sequence Completed" "$STATE_DIR/ovpn_${i}.log" 2>/dev/null && st="UP"
            echo "  slot $i: $st | socks5://10.200.${i}.2:1080 | $cfg"
        else
            echo "  slot $i: DOWN"
        fi
    done
}

case "${1:-}" in
    start)  shift; cmd_start "$@" ;;
    stop)   cmd_stop ;;
    rotate) shift; cmd_rotate "${1:-all}" ;;
    status) cmd_status ;;
    *) echo "Usage: $0 {start <ovpn_dir> [count=6] [out=vpn_proxies.txt] | rotate [slot] | status | stop}"; exit 1 ;;
esac
