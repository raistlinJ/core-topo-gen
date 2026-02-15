#!/usr/bin/env sh
set -eu

# This script runs inside the ubuntu:22.04 container at startup.
# It creates a little bit of realistic filesystem "noise" and light background activity.

rand_byte() {
  # prints an int 0..255
  od -An -N1 -tu1 /dev/urandom 2>/dev/null | tr -d ' '
}

rand_str() {
  # prints N chars [a-z0-9]
  n="${1:-8}"
  tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c "$n" || true
}

choose_mod() {
  # prints a number 0..(mod-1)
  mod="${1:-2}"
  b="$(rand_byte || echo 0)"
  if [ -z "$b" ]; then b=0; fi
  echo $((b % mod))
}

choose_mod_seeded() {
  # Deterministic choice based on INSTANCE_ID and a label.
  # This keeps per-container variance without producing obviously random filenames.
  label="${1:-default}"
  mod="${2:-2}"
  h="$(printf "%s-%s" "${INSTANCE_ID:-x}" "$label" | sha256sum 2>/dev/null | awk '{print $1}' | head -c 8)"
  if [ -z "$h" ]; then
    echo "$(choose_mod "$mod")"
    return 0
  fi
  # shellcheck disable=SC2003
  n=$((16#$h))
  echo $((n % mod))
}

# Derive a per-container stable seed so multiple containers created from the same
# image/compose template differ reliably.
#
# We intentionally avoid leaving behind obvious "bootstrap artifacts" (no persisted instance-id
# file). The container hostname is already unique per container instance, and we hash it to get
# stable (but not visibly random) branching.
HOST_TAG="$(echo "${HOSTNAME:-unknown}" | tr -dc 'a-zA-Z0-9' | tr 'A-Z' 'a-z' | head -c 32)"
INSTANCE_ID="$(printf "%s" "$HOST_TAG" | sha256sum 2>/dev/null | awk '{print $1}' | head -c 16)"
if [ -z "$INSTANCE_ID" ]; then
  INSTANCE_ID="$(rand_str 16)"
fi

# Internal labels used for slight content variation (not exposed in filenames).
V_APP_VARIANT="$(choose_mod_seeded app 3)"
V_HINT_PLACEMENT="$(choose_mod_seeded hint 3)"
V_EXTRA_USERS="$(choose_mod_seeded users 3)"

# A few realistic directories
mkdir -p \
  /opt/app \
  /opt/app/conf \
  /opt/app/bin \
  /srv/share \
  /srv/share/public \
  /var/tmp/cache \
  /var/tmp/sessions \
  /var/log/app \
  /var/log/audit \
  /etc/skel/Documents \
  /etc/skel/Downloads \
  /etc/skel/.ssh

# Some plausible config/log files (low-stakes, mostly decoys)
if [ ! -f /opt/app/conf/app.yml ]; then
  APP_NAME="inventory"
  if [ "$V_APP_VARIANT" -eq 1 ]; then APP_NAME="reporting"; fi
  if [ "$V_APP_VARIANT" -eq 2 ]; then APP_NAME="portal"; fi
  cat > /opt/app/conf/app.yml <<EOF
app:
  name: "${APP_NAME}"
  mode: "prod"
  cache_dir: "/var/tmp/cache"
  session_dir: "/var/tmp/sessions"
logging:
  file: "/var/log/app/app.log"
EOF
fi

if [ ! -f /opt/app/bin/healthcheck.sh ]; then
  cat > /opt/app/bin/healthcheck.sh <<'EOF'
#!/usr/bin/env sh
date +"%m/%d/%y/%H/%M/%S" && echo "OK"
EOF
  chmod +x /opt/app/bin/healthcheck.sh 2>/dev/null || true
fi

touch /var/log/app/app.log /var/log/audit/auth.log || true

# Create a couple of fake users (just entries + homedirs)
# (We avoid useradd/adduser to keep the image truly "generic".)
create_user() {
  u="$1"
  uid="$2"
  gid="$3"

  if ! grep -q "^${u}:" /etc/passwd 2>/dev/null; then
    echo "${u}:x:${uid}:${gid}:${u}:/home/${u}:/bin/bash" >> /etc/passwd || true
  fi
  if ! grep -q "^${u}:" /etc/group 2>/dev/null; then
    echo "${u}:x:${gid}:" >> /etc/group || true
  fi

  mkdir -p "/home/${u}" || true
  # Populate a small skeleton
  mkdir -p "/home/${u}/Documents" "/home/${u}/Downloads" "/home/${u}/.ssh" "/home/${u}/.config" || true

  # Simple user-ish files
  if [ ! -f "/home/${u}/.bash_history" ]; then
    cat > "/home/${u}/.bash_history" <<EOF
ls -la
cd ~/Documents
cat notes.txt
EOF
  fi

  if [ ! -f "/home/${u}/Documents/todo.txt" ]; then
    cat > "/home/${u}/Documents/todo.txt" <<EOF
- review logs in /var/log/app
- check /srv/share/public
- remember: backups are under /var/tmp
EOF
  fi

  if [ ! -f "/home/${u}/Documents/notes.txt" ]; then
    cat > "/home/${u}/Documents/notes.txt" <<EOF
FYI:
- app config: /opt/app/conf/app.yml
- public share: /srv/share/public/
EOF
  fi

  if [ ! -f "/home/${u}/.ssh/known_hosts" ]; then
    printf "# known_hosts seeded %s\n" "$(date +"%m/%d/%y/%H/%M/%S" 2>/dev/null || true)" > "/home/${u}/.ssh/known_hosts" || true
  fi

  # Best-effort ownership (works even without a user existing in NSS if numeric)
  chown -R "${uid}:${gid}" "/home/${u}" 2>/dev/null || true
}

# Base users should be consistent across containers.
create_user "alice" 1001 1001
create_user "bob" 1002 1002

# Optional extra users differ across containers, but look like plausible additional accounts.
# (No random-looking numeric suffixes; just extra names.)
if [ "$V_EXTRA_USERS" -ge 1 ]; then
  create_user "charlie" 1003 1003
fi
if [ "$V_EXTRA_USERS" -ge 2 ]; then
  create_user "dana" 1004 1004
fi

# Copy the mounted hint (if present) into a couple of varied places.
# We keep /hint.txt available too (mounted by compose).
copy_hint() {
  src="/hint.txt"
  [ -f "$src" ] || return 0

  # Always provide one "admin-ish" copy
  mkdir -p /var/tmp /srv/share/public /opt/app || true
  cp -f "$src" "/var/tmp/README.txt" 2>/dev/null || true

  # Vary a second placement (deterministic per-container).
  if [ "$V_HINT_PLACEMENT" -eq 0 ] && [ -d /home/alice ]; then
    cp -f "$src" "/home/alice/Documents/README.txt" 2>/dev/null || true
  elif [ "$V_HINT_PLACEMENT" -eq 1 ]; then
    cp -f "$src" "/srv/share/public/NOTICE.txt" 2>/dev/null || true
  else
    cp -f "$src" "/opt/app/NOTICE.txt" 2>/dev/null || true
  fi
}
copy_hint || true

place_hint_near_flag() {
  hint_src="/hint.txt"
  [ -f "$hint_src" ] || return 0

  # Common flag locations:
  # - Flow writes best-effort flag.txt under the run artifacts directory.
  # - Some templates may stage it under ./html mounted at /html.
  candidates="/flow_artifacts/flag.txt /flag.txt /html/flag.txt"
  flag_path=""
  for p in $candidates; do
    if [ -f "$p" ]; then
      flag_path="$p"
      break
    fi
  done
  [ -n "$flag_path" ] || return 0

  flag_dir="$(dirname "$flag_path")"

  # Try to place hint in the same directory if writable.
  if ( : > "$flag_dir/.writetest" ) 2>/dev/null; then
    rm -f "$flag_dir/.writetest" 2>/dev/null || true
    cp -f "$hint_src" "$flag_dir/hint.txt" 2>/dev/null || true
    return 0
  fi

  # Directory isn't writable (likely a read-only mount). Place hint immediately adjacent.
  base="$(basename "$flag_dir")"
  cp -f "$hint_src" "/${base}_hint.txt" 2>/dev/null || true

  # Provide a friendly symlink to the flag near that adjacent hint.
  ln -snf "$flag_path" "/${base}_flag.txt" 2>/dev/null || true
}

place_hint_near_flag || true

# If flow artifacts are mounted, create an extra pointer to them.
if [ -d /flow_artifacts ]; then
  mkdir -p /srv/share || true
  ln -snf /flow_artifacts "/srv/share/flow_artifacts" 2>/dev/null || true
fi

# Display the main hint (participant-friendly), then run a tiny activity loop.
if [ -f /hint.txt ]; then
  echo "==== Hint (/hint.txt) ===="
  cat /hint.txt || true
  echo "==========================="
fi

if [ -d /flow_artifacts ]; then
  echo "Flow artifacts mounted at /flow_artifacts"
  ls -la /flow_artifacts 2>/dev/null || true
fi

# Background: write a line to a log file and create a tmp file occasionally.
(
  while true; do
    ts="$(date +"%m/%d/%y/%H/%M/%S" 2>/dev/null || echo "unknown")"
    # Choose a small set of plausible actions.
    act="login"
    case "$(choose_mod 5)" in
      0) act="login";;
      1) act="opened";;
      2) act="edited";;
      3) act="downloaded";;
      4) act="checked";;
    esac
    target="/opt/app/conf/app.yml"
    case "$(choose_mod 4)" in
      0) target="/opt/app/conf/app.yml";;
      1) target="/srv/share/public";;
      2) target="/var/log/app/app.log";;
      3) target="/var/tmp";;
    esac
    who="alice"
    case "$(choose_mod 3)" in
      0) who="alice";;
      1) who="bob";;
      2) who="charlie";;
    esac
    printf "%s user=%s action=%s target=%s\n" "$ts" "$who" "$act" "$target" >> /var/log/app/app.log 2>/dev/null || true

    if [ "$(choose_mod 5)" -eq 0 ]; then
      f="/var/tmp/cache/.session"
      printf "created_at=%s\n" "$ts" > "$f" 2>/dev/null || true
    fi

    # sleep 10..30s
    s=$((10 + $(choose_mod 21)))
    sleep "$s"
  done
) &

exit 0
