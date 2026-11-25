#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAN_IF="${1:-eth0}"
WAN_IF="${2:-wlan0}"
FWD_PORT="${3:-25000}"
FWD_LAN_IP="${4:-192.168.100.2}"
NAT_MIN=26000
NAT_MAX=31000

if [ "$(id -u)" -ne 0 ]; then
    echo "root 권한이 필요합니다: sudo $0 [lan_if] [wan_if] [fwd_port] [fwd_lan_ip]"
    exit 1
fi

cleanup() {
    nft delete table inet user_nat 2>/dev/null || true
}
trap cleanup EXIT

# 커널 IP 포워딩은 0 유지 (직접 구현한 server NAT + IDS 스레드가 모든 외부 패킷을 처리)
sysctl -w net.ipv4.ip_forward=0 >/dev/null

# 대용량 프레임 EMSGSIZE 방지를 위해 오프로딩 해제
ethtool -K "$LAN_IF" gro off gso off tso off 2>/dev/null || true
ethtool -K "$WAN_IF" gro off gso off tso off 2>/dev/null || true

# 젯슨 ARP 캐시 워밍업
ping -c 1 -W 1 "$FWD_LAN_IP" >/dev/null 2>&1 || true

# 커널 TCP RST / ICMP Port Unreachable 차단
# (AF_PACKET은 nftables보다 앞단에서 먼저 프레임을 수신하며,
#  25000 및 26000-31000은 리눅스 임시 포트 32768-60999와 겹치지 않아 Wi-Fi에 영향 없음)
nft delete table inet user_nat 2>/dev/null || true
nft -f - <<EOF
table inet user_nat {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "${WAN_IF}" tcp dport { ${FWD_PORT}, ${NAT_MIN}-${NAT_MAX} } drop
        iifname "${WAN_IF}" udp dport ${NAT_MIN}-${NAT_MAX} drop
    }
}
EOF

cd "$SCRIPT_DIR"
"$SCRIPT_DIR/server" "$LAN_IF" "$WAN_IF" "$FWD_PORT" "$FWD_LAN_IP"
