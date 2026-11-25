#!/usr/bin/env bash
# ponytail: multi-VPN tunnel pool via ip netns + microsocks + nobody uid kill-switch; requires root, /dev/net/tun, and netns support
set -u

STATE_DIR="/run/vpn_pool"
LOCK_FILE="$STATE_DIR/.lock"

die() { echo "[!] $*" >&2; exit 1; }

need_root() {
    [ "$(id -u)" -eq 0 ] || die "Jalankan sebagai root (sudo)."
    [ -c /dev/net/tun ] || die "/dev/net/tun tidak ada (di Proxmox LXC aktifkan TUN passthrough)."
    for bin in openvpn microsocks ip iptables awk sysctl flock; do
        command -v "$bin" >/dev/null 2>&1 || die "Command '$bin' belum ada. Install dulu: apt-get update && apt-get install -y openvpn microsocks iptables"
    done
    ip netns del _vp_chk 2>/dev/null || true
    ip netns add _vp_chk 2>/dev/null || die "ip netns gagal (di Proxmox LXC pastikan nesting=1 aktif)."
    ip netns del _vp_chk 2>/dev/null || true
    mkdir -p "$STATE_DIR"
}

find_auth() {
    local dir="$1" f
    for f in "$dir/auth.txt" "$dir/.auth" "$dir/credentials.txt" "$dir/pass.txt"; do
        [ -f "$f" ] && { readlink -f "$f"; return 0; }
    done
    f=$(find "$dir" -maxdepth 1 -type f -name '*.auth' 2>/dev/null | head -n1)
    [ -n "$f" ] && readlink -f "$f"
}

collect_cfgs() {
    local dir="$1"
    # Prefer UDP configs first, keep TCP configs as fallback
    find "$dir" -maxdepth 1 -type f -name '*udp.ovpn' | shuf
    find "$dir" -maxdepth 1 -type f -name '*.ovpn' ! -name '*udp.ovpn' | shuf
}

stop_slot() {
    local i="$1" kind p w
    for kind in socks ovpn; do
        [ -f "$STATE_DIR/${kind}_${i}.pid" ] || continue
        p=$(cat "$STATE_DIR/${kind}_${i}.pid" 2>/dev/null || true)
        if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
            kill "$p" 2>/dev/null || true
            for w in 1 2 3 4 5 6; do
                kill -0 "$p" 2>/dev/null || break
                sleep 0.1
            done
            kill -9 "$p" 2>/dev/null || true
        fi
        rm -f "$STATE_DIR/${kind}_${i}.pid"
    done
    ip netns del "vpnpool${i}" 2>/dev/null || true
    ip link del "vpnh${i}" 2>/dev/null || true
    rm -rf "/etc/netns/vpnpool${i}" "$STATE_DIR/ovpn_${i}.log" "$STATE_DIR/socks_${i}.log" "$STATE_DIR/cfg_${i}" "$STATE_DIR/socks_${i}.deferred"
}

slot_is_up() {
    local i="$1" opid spid
    opid=$(cat "$STATE_DIR/ovpn_${i}.pid" 2>/dev/null || true)
    spid=$(cat "$STATE_DIR/socks_${i}.pid" 2>/dev/null || true)
    [ -n "$opid" ] && kill -0 "$opid" 2>/dev/null || return 1
    [ -n "$spid" ] && kill -0 "$spid" 2>/dev/null || return 1
    grep -q "Initialization Sequence Completed" "$STATE_DIR/ovpn_${i}.log" 2>/dev/null || return 1
    ip -n "vpnpool${i}" -o link show 2>/dev/null | grep -qE '[0-9]+: tun[0-9]*[:@]'
}

start_slot() {
    local i="$1" cfg="$2" auth="$3"
    local ns="vpnpool${i}" h="vpnh${i}" w="vpnw${i}"
    stop_slot "$i"
    mkdir -p "/etc/netns/${ns}"
    printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > "/etc/netns/${ns}/resolv.conf"

    ip netns add "$ns" || { stop_slot "$i"; return 1; }
    ip link add "$h" type veth peer name "$w" || { stop_slot "$i"; return 1; }
    ip link set "$w" netns "$ns" || { stop_slot "$i"; return 1; }
    ip addr add "10.200.${i}.1/30" dev "$h" || { stop_slot "$i"; return 1; }
    ip link set "$h" up || { stop_slot "$i"; return 1; }
    ip -n "$ns" link set lo up || { stop_slot "$i"; return 1; }
    ip -n "$ns" addr add "10.200.${i}.2/30" dev "$w" || { stop_slot "$i"; return 1; }
    ip -n "$ns" link set "$w" up || { stop_slot "$i"; return 1; }
    ip -n "$ns" route replace default via "10.200.${i}.1" dev "$w" || { stop_slot "$i"; return 1; }
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true

    # Kill-switch: microsocks runs as uid nobody via setpriv (no fork); drop ANY non-tun outbound traffic from nobody
    local ms_uid
    ms_uid=$(id -u nobody 2>/dev/null || true)
    if command -v setpriv >/dev/null 2>&1 && [ -n "$ms_uid" ] && \
       ip netns exec "$ns" iptables -A OUTPUT -o "$w" -m owner --uid-owner "$ms_uid" -m conntrack --ctstate NEW -j DROP 2>/dev/null; then
        ip netns exec "$ns" setpriv --reuid="$ms_uid" --regid="$ms_uid" --clear-groups microsocks -i "10.200.${i}.2" -p 1080 >"$STATE_DIR/socks_${i}.log" 2>&1 9>&- &
        echo $! > "$STATE_DIR/socks_${i}.pid"
    else
        echo "WAIT_TUN" > "$STATE_DIR/socks_${i}.deferred"
    fi

    # --ignore-unknown-option MUST precede --config for Linux OpenVPN (Proton block-outside-dns)
    local cmd=(openvpn --cd "$(dirname "$cfg")"
        --ignore-unknown-option block-outside-dns --pull-filter ignore block-outside-dns
        --script-security 1 --ping-exit 60 --connect-retry 1 2 --resolv-retry 2 --fast-io
        --config "$cfg" --auth-nocache)
    [ -n "$auth" ] && cmd+=(--auth-user-pass "$auth")

    ip netns exec "$ns" "${cmd[@]}" >"$STATE_DIR/ovpn_${i}.log" 2>&1 9>&- &
    echo $! > "$STATE_DIR/ovpn_${i}.pid"
    echo "$cfg" > "$STATE_DIR/cfg_${i}"
}

ensure_socks_for_slot() {
    local i="$1" ns="vpnpool${i}"
    if [ -f "$STATE_DIR/socks_${i}.deferred" ]; then
        rm -f "$STATE_DIR/socks_${i}.deferred"
        ip netns exec "$ns" microsocks -i "10.200.${i}.2" -p 1080 >"$STATE_DIR/socks_${i}.log" 2>&1 9>&- &
        echo $! > "$STATE_DIR/socks_${i}.pid"
    fi
}

setup_nat() {
    local wan
    wan=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [ -n "$wan" ] || wan=$(ip route show default | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [ -n "$wan" ] || die "Default interface (WAN) tidak ditemukan."
    sysctl -qw net.ipv4.ip_forward=1 || die "Gagal mengaktifkan net.ipv4.ip_forward."
    iptables -t nat -C POSTROUTING -s 10.200.0.0/16 -o "$wan" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -o "$wan" -j MASQUERADE || die "iptables NAT gagal."
    iptables -C FORWARD -s 10.200.0.0/16 -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD 1 -s 10.200.0.0/16 -j ACCEPT || die "iptables FORWARD gagal."
    iptables -C FORWARD -d 10.200.0.0/16 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD 1 -d 10.200.0.0/16 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || die "iptables FORWARD conntrack gagal."
}

cleanup_all() {
    local f i
    declare -A seen=()
    for f in "$STATE_DIR"/ovpn_*.pid "$STATE_DIR"/socks_*.pid "$STATE_DIR"/cfg_*; do
        [ -e "$f" ] || continue
        i=${f##*_}; i=${i%.pid}
        [[ "$i" =~ ^[0-9]+$ ]] && seen[$i]=1
    done
    while read -r ns _; do
        if [[ "$ns" =~ ^vpnpool([0-9]+)$ ]]; then
            seen[${BASH_REMATCH[1]}]=1
        fi
    done < <(ip netns list 2>/dev/null || true)
    for i in "${!seen[@]}"; do
        stop_slot "$i"
    done
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^vpnh[0-9]+$' | while read -r l; do
        ip link del "$l" 2>/dev/null || true
    done
    rm -f "$STATE_DIR"/socks_*.deferred "$STATE_DIR"/count "$STATE_DIR"/dir "$STATE_DIR"/auth "$STATE_DIR"/out 2>/dev/null || true
}

cmd_stop() {
    mkdir -p "$STATE_DIR"
    exec 9>"$LOCK_FILE"
    flock -w 15 9 || true
    cleanup_all
    echo "[*] Semua slot VPN pool dimatikan."
}

write_out_file() {
    local n="$1" out_file="$2" tmp i ok=0
    mkdir -p "$(dirname "$out_file")"
    tmp=$(mktemp "${out_file}.XXXXXX") || return 1
    for i in $(seq 1 "$n"); do
        if slot_is_up "$i"; then
            echo "socks5://10.200.${i}.2:1080" >> "$tmp"
            ok=$((ok + 1))
        fi
    done
    chmod 0644 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$out_file"
    return 0
}

wait_target_slots() {
    local deadline=$((SECONDS + 25)) slots=("$@") i all_ok opid
    declare -A ready=()
    while [ "$SECONDS" -lt "$deadline" ]; do
        all_ok=1
        for i in "${slots[@]}"; do
            [ "${ready[$i]:-0}" = "1" ] && continue
            opid=$(cat "$STATE_DIR/ovpn_${i}.pid" 2>/dev/null || true)
            if [ -z "$opid" ] || ! kill -0 "$opid" 2>/dev/null; then
                ready[$i]=-1
                continue
            fi
            if grep -q "Initialization Sequence Completed" "$STATE_DIR/ovpn_${i}.log" 2>/dev/null && \
               ip -n "vpnpool${i}" -o link show 2>/dev/null | grep -qE '[0-9]+: tun[0-9]*[:@]'; then
                ensure_socks_for_slot "$i"
                if slot_is_up "$i"; then
                    ready[$i]=1
                    continue
                fi
            fi
            all_ok=0
        done
        [ "$all_ok" -eq 1 ] && break
        sleep 1
    done
    local ok=0
    for i in "${slots[@]}"; do
        if [ "${ready[$i]:-0}" = "1" ] && slot_is_up "$i"; then
            ok=$((ok + 1))
            echo "  [+] slot $i READY: socks5://10.200.${i}.2:1080 ($(basename "$(cat "$STATE_DIR/cfg_${i}")"))"
        else
            echo "  [!] slot $i GAGAL/TIMEOUT: $(tail -n 2 "$STATE_DIR/ovpn_${i}.log" 2>/dev/null | tr '\n' ' ')"
            stop_slot "$i"
        fi
    done
    [ "$ok" -gt 0 ]
}

cmd_start() {
    local dir="${1:-}" n="${2:-6}" out_file="${3:-vpn_proxies.txt}"
    [ -d "$dir" ] || die "Folder .ovpn tidak ditemukan: $dir"
    dir=$(readlink -f "$dir")
    out_file=$(readlink -m "$out_file")
    [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le 50 ] || die "Jumlah tunnel harus 1..50"
    need_root
    exec 9>"$LOCK_FILE"
    flock -w 30 9 || die "Gagal mengunci VPN pool."
    cleanup_all
    setup_nat

    local auth; auth=$(find_auth "$dir" || true)
    mapfile -t cfgs < <(collect_cfgs "$dir")
    [ "${#cfgs[@]}" -gt 0 ] || die "Tidak ada file .ovpn di $dir"
    if [ -z "$auth" ] && grep -qi '^auth-user-pass' "${cfgs[0]}" 2>/dev/null; then
        die "auth.txt tidak ditemukan di $dir (dibutuhkan oleh config .ovpn)."
    fi

    echo "$dir" > "$STATE_DIR/dir"
    echo "$auth" > "$STATE_DIR/auth"
    echo "$n" > "$STATE_DIR/count"
    echo "$out_file" > "$STATE_DIR/out"

    echo "[*] Menyalakan $n tunnel paralel dari $dir..."
    local -a slots=()
    local i
    for i in $(seq 1 "$n"); do
        local idx=$(( (i - 1) % ${#cfgs[@]} ))
        start_slot "$i" "${cfgs[$idx]}" "$auth"
        slots+=("$i")
    done
    wait_target_slots "${slots[@]}" || true
    write_out_file "$n" "$out_file"
    local active; active=$(wc -l < "$out_file" | tr -d ' ')
    echo "[*] Aktif: $active/$n tunnel -> $out_file"
    [ "$active" -gt 0 ]
}

cmd_rotate() {
    need_root
    exec 9>"$LOCK_FILE"
    flock -w 30 9 || die "Gagal mengunci VPN pool."
    [ -f "$STATE_DIR/dir" ] || die "Pool belum jalan."
    local dir auth n out_file target="${1:-all}"
    dir=$(cat "$STATE_DIR/dir"); auth=$(cat "$STATE_DIR/auth" 2>/dev/null || true)
    n=$(cat "$STATE_DIR/count"); out_file=$(cat "$STATE_DIR/out")
    mapfile -t cfgs < <(collect_cfgs "$dir")
    [ "${#cfgs[@]}" -gt 0 ] || die "Tidak ada .ovpn di $dir"

    local -a slots=()
    if [ "$target" = "all" ]; then
        mapfile -t slots < <(seq 1 "$n")
    else
        [[ "$target" =~ ^[0-9]+$ ]] && [ "$target" -ge 1 ] && [ "$target" -le "$n" ] || die "Slot tidak valid: $target (1..$n)"
        slots=("$target")
    fi

    local i old_cfg cfg cand ok_rot=1
    for i in "${slots[@]}"; do
        old_cfg=$(cat "$STATE_DIR/cfg_${i}" 2>/dev/null || true)
        cfg="${cfgs[$((RANDOM % ${#cfgs[@]}))]}"
        if [ "${#cfgs[@]}" -gt 1 ] && [ "$cfg" = "$old_cfg" ]; then
            for cand in "${cfgs[@]}"; do
                [ "$cand" != "$old_cfg" ] && { cfg="$cand"; break; }
            done
        fi
        echo "[*] Rotasi slot $i -> $(basename "$cfg")..."
        start_slot "$i" "$cfg" "$auth"
    done
    if ! wait_target_slots "${slots[@]}"; then
        ok_rot=0
        # 1 quick retry for single-slot rotation before giving up
        if [ "${#slots[@]}" -eq 1 ]; then
            i="${slots[0]}"
            local fail_cfg="$cfg"
            cfg="${cfgs[$((RANDOM % ${#cfgs[@]}))]}"
            if [ "${#cfgs[@]}" -gt 1 ] && [ "$cfg" = "$fail_cfg" ]; then
                for cand in "${cfgs[@]}"; do
                    [ "$cand" != "$fail_cfg" ] && { cfg="$cand"; break; }
                done
            fi
            echo "[*] Retry rotasi slot $i -> $(basename "$cfg")..."
            start_slot "$i" "$cfg" "$auth"
            wait_target_slots "$i" && ok_rot=1
        fi
    fi
    write_out_file "$n" "$out_file"
    [ "$ok_rot" -eq 1 ]
}

cmd_status() {
    [ -f "$STATE_DIR/count" ] || { echo "[*] VPN pool tidak aktif."; return 0; }
    local n i cfg
    n=$(cat "$STATE_DIR/count")
    for i in $(seq 1 "$n"); do
        if slot_is_up "$i"; then
            cfg=$(basename "$(cat "$STATE_DIR/cfg_${i}" 2>/dev/null || echo "-")")
            echo "  slot $i: UP | socks5://10.200.${i}.2:1080 | $cfg"
        elif [ -f "$STATE_DIR/ovpn_${i}.pid" ] && kill -0 "$(cat "$STATE_DIR/ovpn_${i}.pid" 2>/dev/null || echo 0)" 2>/dev/null; then
            cfg=$(basename "$(cat "$STATE_DIR/cfg_${i}" 2>/dev/null || echo "-")")
            echo "  slot $i: CONNECTING | socks5://10.200.${i}.2:1080 | $cfg"
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
