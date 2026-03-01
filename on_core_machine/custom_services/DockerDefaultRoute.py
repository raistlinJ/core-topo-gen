from core.services.base import CoreService, ShadowDir, ServiceMode


class DockerDefaultRouteService(CoreService):
    """Docker-safe default route service using absolute script paths.

    This avoids CORE built-in DefaultRoute relative-path behavior (defaultroute.sh)
    that can fail when Docker container working directories vary.
    """

    name: str = "DockerDefaultRoute"
    group: str = "Simple"
    files: list[str] = ["/defaultroute.sh"]
    executables: list[str] = []
    dependencies: list[str] = ["CoreTGPrereqs"]
    startup: list[str] = ["/bin/sh /defaultroute.sh"]
    validate: list[str] = ["ip route | grep -q '^default '"]
    shutdown: list[str] = []
    validation_mode: ServiceMode = ServiceMode.NON_BLOCKING
    shadow_directories: list[ShadowDir] = []

    def get_text_template(self, name: str) -> str:  # type: ignore[override]
        return r"""#!/bin/sh
set -eu

LOG=/tmp/coretg_docker_defaultroute.log

log() {
  echo "[DockerDefaultRoute] $*" >> "$LOG"
}

iface=""
cidr=""

if command -v ip >/dev/null 2>&1; then
  iface="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2}' | head -n1 || true)"
  if [ -n "$iface" ]; then
    cidr="$(ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | head -n1 || true)"
  fi
fi

if [ -z "$iface" ] || [ -z "$cidr" ]; then
  log "no global IPv4 interface found; skipping"
  exit 0
fi

ipaddr="$(printf '%s' "$cidr" | cut -d'/' -f1)"
prefix="$(printf '%s' "$cidr" | cut -d'/' -f2)"

IFS=. read -r a b c d <<EOF_IP
$ipaddr
EOF_IP

if [ -z "$a" ] || [ -z "$b" ] || [ -z "$c" ] || [ -z "$d" ]; then
  log "invalid IPv4 address parsed: $ipaddr"
  exit 0
fi

gw="$a.$b.$c.1"
if [ "$gw" = "$ipaddr" ]; then
  gw="$a.$b.$c.2"
fi

if command -v ip >/dev/null 2>&1; then
  if ip route replace default via "$gw" dev "$iface" >/dev/null 2>&1; then
    log "set default route via $gw dev $iface (addr=$ipaddr/$prefix)"
    exit 0
  fi
fi

log "failed to set default route via $gw dev $iface"
exit 0
"""
