from core.config import ConfigString, ConfigBool, Configuration
from core.services.base import CoreService, ShadowDir, ServiceMode


class DockerComposeService(CoreService):
    """Run a per-node docker-compose file on service start.

    Expects compose files at /tmp/vulns/docker-compose-<node.name>.yml
    """

    # unique name for service
    name: str = "DockerCompose"
    # group for GUI display
    group: str = "Containers"
    # files generated into the node context
    files: list[str] = ["runcompose.sh"]
    # required executables on PATH
    executables: list[str] = []
    # dependencies
    dependencies: list[str] = []
    # startup commands
    startup: list[str] = ["/bin/bash runcompose.sh &"]
    # validation/stop
    validate: list[str] = []
    shutdown: list[str] = []
    validation_mode: ServiceMode = ServiceMode.NON_BLOCKING

    shadow_directories: list[ShadowDir] = []

    def get_text_template(self, name: str) -> str:  # type: ignore[override]
        """Generate script to start docker compose for this node.

        NOTE: This script assumes the host docker daemon is reachable from the
        node context (e.g., via /var/run/docker.sock). If not, ensure host-side
        automation executes the same command.
        """
        return """
        #!/bin/bash
        set -euo pipefail
        LOG="compose_output.txt"
        YML="/tmp/vulns/docker-compose-${node.name}.yml"
        echo "[DockerCompose] node id(${node.id}) name(${node.name}) using $YML" >> "$LOG"
        if [ ! -f "$YML" ]; then
          echo "[DockerCompose] compose file not found: $YML" >> "$LOG"
          exit 0
        fi
        if ! command -v docker >/dev/null 2>&1; then
          echo "[DockerCompose] docker CLI not available in node; skipping" >> "$LOG"
          exit 0
        fi
        # Bring up services in detached mode
        docker compose -f "$YML" up -d >> "$LOG" 2>&1 || echo "[DockerCompose] docker compose failed" >> "$LOG"

        # --- CTF flag support (text only for now) ---
        # Generate a random flag, store a copy on the host, then copy it into the
        # vulnerability container filesystem. Container name is enforced by our
        # compose generator (container_name: <node.name>).
        FLAG_TYPE="text"
        FLAG_HOST_PATH="/tmp/vulns/flag-${node.name}.txt"
        FLAG_IN_CONTAINER_PRIMARY="/flag.txt"
        FLAG_IN_CONTAINER_FALLBACK="/tmp/flag.txt"

        mkdir -p /tmp/vulns >> "$LOG" 2>&1 || true
        # Write a random text flag to host path
        printf "FLAG{" > "$FLAG_HOST_PATH" 2>> "$LOG" || true
        tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 >> "$FLAG_HOST_PATH" 2>> "$LOG" || true
        printf "}\n" >> "$FLAG_HOST_PATH" 2>> "$LOG" || true
        echo "[DockerCompose] flag_type=${FLAG_TYPE} host_path=${FLAG_HOST_PATH}" >> "$LOG"

        # Wait briefly for container to appear
        for i in {1..20}; do
          if docker ps -a --format '{{.Names}}' | grep -qx "${node.name}"; then
            break
          fi
          sleep 0.5
        done

        if docker ps -a --format '{{.Names}}' | grep -qx "${node.name}"; then
          if docker cp "$FLAG_HOST_PATH" "${node.name}:${FLAG_IN_CONTAINER_PRIMARY}" >> "$LOG" 2>&1; then
            echo "[DockerCompose] flag copied to ${node.name}:${FLAG_IN_CONTAINER_PRIMARY}" >> "$LOG"
          else
            docker cp "$FLAG_HOST_PATH" "${node.name}:${FLAG_IN_CONTAINER_FALLBACK}" >> "$LOG" 2>&1 || true
            echo "[DockerCompose] flag copied to ${node.name}:${FLAG_IN_CONTAINER_FALLBACK}" >> "$LOG"
          fi
        else
          echo "[DockerCompose] container ${node.name} not found; flag not copied" >> "$LOG"
        fi

        exit 0
        """
