from core.services.base import CoreService, ShadowDir, ServiceMode


class CoreTGPrereqsService(CoreService):
    """Best-effort dependency installer for CORE Topo Gen services.

    Ensures common tools exist inside the node namespace/container so that other
    custom services (Segmentation, Traffic) can run their generated scripts.

    Notes:
    - This is best-effort and logs to prereqs_output.txt.
    - Package installation requires root inside the node.
    - For Docker-based nodes, iptables availability/capabilities may depend on
      how the container is launched (e.g., CAP_NET_ADMIN/privileged).
    """

    name: str = "CoreTGPrereqs"
    group: str = "Simple"
    files: list[str] = ["runprereqs.sh"]
    executables: list[str] = []
    dependencies: list[str] = []
    startup: list[str] = ["/bin/sh runprereqs.sh"]
    validate: list[str] = []
    shutdown: list[str] = []
    validation_mode: ServiceMode = ServiceMode.NON_BLOCKING

    shadow_directories: list[ShadowDir] = []

    def get_text_template(self, name: str) -> str:  # type: ignore[override]
        return r"""#!/bin/sh
set -eu

LOG="prereqs_output.txt"

log() {
  echo "[CoreTGPrereqs] $*" >> "$LOG"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

as_root() {
  # Best-effort check: many CORE nodes run as root.
  if have id; then
    [ "$(id -u)" = "0" ]
    return
  fi
  # If id is missing, assume non-root.
  return 1
}

install_pkgs_apt() {
  # shellcheck disable=SC2039
  pkgs="$*"
  log "apt-get installing: $pkgs"
  DEBIAN_FRONTEND=noninteractive apt-get update >>"$LOG" 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs >>"$LOG" 2>&1 || true
}

install_pkgs_apk() {
  pkgs="$*"
  log "apk installing: $pkgs"
  apk add --no-cache $pkgs >>"$LOG" 2>&1 || true
}

install_pkgs_yum() {
  pkgs="$*"
  log "yum installing: $pkgs"
  yum install -y $pkgs >>"$LOG" 2>&1 || true
}

maybe_install() {
  if ! as_root; then
    log "not root; cannot install packages"
    return 0
  fi

  if have apt-get; then
    install_pkgs_apt "$@"
    return 0
  fi
  if have apk; then
    install_pkgs_apk "$@"
    return 0
  fi
  if have yum; then
    install_pkgs_yum "$@"
    return 0
  fi

  log "no supported package manager found (apt-get/apk/yum)"
  return 0
}

log "node id(${node.id}) name(${node.name}) starting prereq check"

# Ensure /bin/bash exists because other CORE TG services use it.
if [ ! -x /bin/bash ]; then
  log "/bin/bash missing; attempting to install bash"
  maybe_install bash
fi

# Ensure python3 for generated Traffic and Segmentation scripts.
if ! have python3; then
  log "python3 missing; attempting to install python3"
  maybe_install python3
fi

# Ensure iptables + iproute tooling for segmentation scripts.
if ! have iptables; then
  log "iptables missing; attempting to install iptables"
  maybe_install iptables
fi

if ! have ip; then
  log "ip (iproute2) missing; attempting to install iproute2/iproute"
  # distro package names differ
  maybe_install iproute2 iproute
fi

# Some images ship nftables instead of iptables; log it for debugging.
if have nft; then
  log "nft present"
fi

log "done"
"""
