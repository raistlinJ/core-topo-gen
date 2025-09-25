# Simple developer conveniences

.PHONY: dev-certs up clean force-certs host-web host-web-nginx host-web-envoy stop stop-host kill-backend

CERT_SANS?=DNS:localhost,IP:127.0.0.1
CERT_SUBJECT?=/CN=localhost
CERT_DAYS?=365

# Repo root (resolved when make runs) and backend pattern for process kill
REPO_ROOT?=$(shell pwd)
BACKEND_PATTERN?=$(REPO_ROOT)/webapp/app_backend.py

# Generate self-signed certs if missing
.dev-certs:
	@CERT_SANS="$(CERT_SANS)" CERT_SUBJECT="$(CERT_SUBJECT)" CERT_DAYS="$(CERT_DAYS)" bash scripts/dev_gen_certs.sh >/dev/null

dev-certs: .dev-certs
	@echo "Dev certs present (SUBJECT=$(CERT_SUBJECT), SANS=$(CERT_SANS))"

# Force regeneration
force-certs:
	@FORCE_REGEN=1 CERT_SANS="$(CERT_SANS)" CERT_SUBJECT="$(CERT_SUBJECT)" CERT_DAYS="$(CERT_DAYS)" bash scripts/dev_gen_certs.sh

# Bring up stack (ensures certs first)
up: dev-certs
	docker compose up --build

# Start the Web UI on the host and run only the nginx TLS proxy in Docker
PROXY?=nginx

host-web: dev-certs
	@echo "Starting host Web UI (interpreter via WEBUI_PY or core-python/python3)..."
	@bash scripts/run_host_webui.sh & \
	  sleep 2; \
	  echo "Launching $(PROXY) proxy..."; \
	  if [ "$(PROXY)" = "envoy" ]; then \
	    docker compose --profile envoy up --build envoy; \
	  else \
	    docker compose --profile nginx up --build nginx; \
	  fi

host-web-nginx:
	@$(MAKE) host-web PROXY=nginx

host-web-envoy:
	@$(MAKE) host-web PROXY=envoy

# Stop only: stop host process and stop docker containers (do not remove)
stop-host:
	@HOST_PID_FILE=server.pid; \
	if [ -f $$HOST_PID_FILE ]; then \
	  PID=$$(cat $$HOST_PID_FILE); \
	  if ps -p $$PID >/dev/null 2>&1; then \
	    echo "Stopping host Web UI (PID $$PID)..."; \
	    kill $$PID; \
	    for i in $$(seq 1 10); do \
	      if ps -p $$PID >/dev/null 2>&1; then sleep 0.3; else break; fi; \
	    done; \
	    if ps -p $$PID >/dev/null 2>&1; then \
	      echo "Force killing host Web UI (PID $$PID)..."; kill -9 $$PID; \
	    fi; \
	  else \
	    echo "PID $$PID from $$HOST_PID_FILE is not running"; \
	  fi; \
	  rm -f $$HOST_PID_FILE; \
	else \
	  echo "No host Web UI PID file found (server.pid)"; \
	fi

stop:
	@$(MAKE) stop-host
	@echo "Stopping docker containers (no removal)..."
	@docker compose stop || true

# Ensure any backend webserver processes are terminated even if no PID file exists
kill-backend:
	@echo "Ensuring backend webserver is stopped..."
	@# First attempt graceful stop via PID file logic
	@$(MAKE) -s stop-host
	@# Then, as a safety net, kill any leftover app_backend.py processes under this repo
	@PIDS=$$(pgrep -f "$(BACKEND_PATTERN)" || true); \
	 if [ -n "$$PIDS" ]; then \
	   echo "Killing backend webserver PIDs: $$PIDS"; \
	   kill $$PIDS || true; \
	   for i in $$(seq 1 10); do \
	     ALL_DONE=1; \
	     for PID in $$PIDS; do \
	       if ps -p $$PID >/dev/null 2>&1; then ALL_DONE=0; break; fi; \
	     done; \
	     if [ $$ALL_DONE -eq 1 ]; then break; fi; \
	     sleep 0.2; \
	   done; \
	   for PID in $$PIDS; do \
	     if ps -p $$PID >/dev/null 2>&1; then \
	       echo "Force killing $$PID"; kill -9 $$PID || true; \
	     fi; \
	   done; \
	 else \
	   echo "No backend webserver processes found by pattern: $(BACKEND_PATTERN)"; \
	 fi

# Clean: stop host process and stop+remove docker containers (and volumes)
clean:
	@$(MAKE) kill-backend
	@echo "Stopping and removing docker containers (and volumes)..."
	@docker compose down -v || true
	@echo "(certs preserved in nginx/certs; remove manually if desired)"
