# coretg: ensure iproute2-like `ip` command present for CORE DefaultRoute
# Strategy: busybox injection (no package manager, offline-safe)
FROM busybox:1.36.1-musl AS coretg_iptools

FROM vulhub/apisix:2.11.0

USER root

# Preserve the base image WORKDIR; some upstream services rely on it.

# CORE may chmod relative service script paths (e.g., defaultroute.sh, runtraffic.sh).
# Ensure those relative names resolve from common runtime working directories.
RUN set -eu; \
	for d in / /root /tmp /home /home/core /home/ubuntu /app /opt /workspace /work; do \
		mkdir -p "$d" 2>/dev/null || true; \
		ln -sfn /defaultroute.sh "$d/defaultroute.sh" || true; \
		ln -sfn /runtraffic.sh "$d/runtraffic.sh" || true; \
	done

# If the base image already provides `ip`, keep it; otherwise inject busybox as `ip`.
# We avoid any RUN that relies on networked package repositories.
COPY --from=coretg_iptools /bin/busybox /usr/local/coretg/bin/busybox

RUN set -eu; \
	echo '[coretg-wrapper] STRICT=0 mode=busybox base=vulhub/apisix:2.11.0' >&2; \
	chmod 0755 /usr/local/coretg/bin/busybox; \
	if command -v ip >/dev/null 2>&1; then \
		echo '[coretg-wrapper] ip already present; leaving base image ip as-is' >&2; \
		exit 0; \
	fi; \
	mkdir -p /usr/sbin /sbin; \
	# Provide `ip` on common paths (CORE scripts typically call `ip` directly). \
	ln -sf /usr/local/coretg/bin/busybox /usr/sbin/ip; \
	ln -sf /usr/local/coretg/bin/busybox /sbin/ip; \
	/usr/sbin/ip -V >/dev/null 2>&1 || true
