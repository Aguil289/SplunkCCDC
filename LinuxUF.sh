#!/usr/bin/env bash
#
# Splunk Universal Forwarder installer (Linux)
# Prompts for indexer IP, admin username, and admin password.
# Auto-detects package manager: .deb -> .rpm -> .tgz fallback.
#

set -euo pipefail
IFS=$'\n\t'

# Re-run as root if needed
if [[ "${EUID}" -ne 0 ]]; then
    exec sudo -E "$0" "$@"
fi

# ---------- Config ----------
SPLUNK_HOME="/opt/splunkforwarder"
SPLUNK_USER="splunkfwd"
SPLUNK_GROUP="splunkfwd"
LOCAL_CONF="$SPLUNK_HOME/etc/system/local"
UF_BIN="$SPLUNK_HOME/bin/splunk"
WORK_DIR="/tmp/splunk-uf-install"
LOG_FILE="/var/log/uf-install.log"

# --- UF version: edit here if you need a different version ---
# IMPORTANT: UF major version must be <= indexer major version.
# If your indexer is 9.4.x and you stay on 10.x here, forwarding will fail.
UF_VERSION="10.2.0"
UF_HASH="d749cb17ea65"
UF_DEB_URL="https://download.splunk.com/products/universalforwarder/releases/${UF_VERSION}/linux/splunkforwarder-${UF_VERSION}-${UF_HASH}-linux-amd64.deb"
UF_RPM_URL="https://download.splunk.com/products/universalforwarder/releases/${UF_VERSION}/linux/splunkforwarder-${UF_VERSION}-${UF_HASH}.x86_64.rpm"
UF_TGZ_URL="https://download.splunk.com/products/universalforwarder/releases/${UF_VERSION}/linux/splunkforwarder-${UF_VERSION}-${UF_HASH}-linux-amd64.tgz"

# ---------- Helpers ----------
say()  { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

setup_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2>&1
    echo "=== UF install started: $(date) ==="
}

prompt_inputs() {
    read -rp "Enter indexer IP/hostname: " INDEXER
    [[ -n "$INDEXER" ]] || die "Indexer cannot be empty."

    read -rp "Enter Splunk admin username [admin]: " ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-admin}"

    while true; do
        read -rsp "Enter Splunk admin password (>=8 chars): " ADMIN_PASS; echo
        read -rsp "Confirm password: " ADMIN_PASS_CONFIRM; echo

        if [[ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]]; then
            warn "Passwords do not match. Try again."
            continue
        fi
        if [[ ${#ADMIN_PASS} -lt 8 ]]; then
            warn "Password must be at least 8 characters."
            continue
        fi
        unset ADMIN_PASS_CONFIRM
        break
    done
}

ensure_splunk_user() {
    if ! id "$SPLUNK_USER" >/dev/null 2>&1; then
        say "Creating $SPLUNK_USER system user (nologin)"
        useradd -r -m -d "/home/${SPLUNK_USER}" -s /sbin/nologin "$SPLUNK_USER" 2>/dev/null || \
        useradd -r -m -d "/home/${SPLUNK_USER}" -s /usr/sbin/nologin "$SPLUNK_USER" 2>/dev/null || \
        useradd -r -m -d "/home/${SPLUNK_USER}" "$SPLUNK_USER"
    fi

    getent group "$SPLUNK_GROUP" >/dev/null 2>&1 || groupadd "$SPLUNK_GROUP"
    usermod -aG "$SPLUNK_GROUP" "$SPLUNK_USER" 2>/dev/null || true

    # Grant read access to common log files via ACL (if available)
    if have setfacl; then
        for f in /var/log/messages /var/log/secure /var/log/syslog /var/log/auth.log /var/log/audit/audit.log; do
            [[ -f "$f" ]] && setfacl -m "u:${SPLUNK_USER}:r" "$f" 2>/dev/null || true
        done
        setfacl -m "u:${SPLUNK_USER}:rx" /var/log 2>/dev/null || true
    else
        warn "setfacl not found — install 'acl' if Splunk fails to read logs."
    fi
}

download_uf() {
    local url="$1" out="$2"
    say "Downloading $url"
    rm -f "$out"
    if have wget; then
        wget -q --show-progress -O "$out" "$url" && return 0
        warn "wget failed; trying curl"
    fi
    if have curl; then
        curl -fSL -o "$out" "$url" && return 0
    fi
    die "Download failed — install wget or curl and retry."
}

install_uf() {
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"

    if have dpkg; then
        local pkg="splunkforwarder-${UF_VERSION}-${UF_HASH}-linux-amd64.deb"
        download_uf "$UF_DEB_URL" "$pkg"
        say "Installing .deb"
        dpkg -i "$pkg" || { have apt-get && apt-get install -f -y && dpkg -i "$pkg"; } || die "dpkg install failed"
    elif have rpm; then
        local pkg="splunkforwarder-${UF_VERSION}-${UF_HASH}.x86_64.rpm"
        download_uf "$UF_RPM_URL" "$pkg"
        say "Installing .rpm"
        if have dnf; then
            dnf install -y "./$pkg"
        elif have yum; then
            yum install -y "./$pkg"
        else
            rpm -ivh "$pkg"
        fi
    else
        local pkg="splunkforwarder-${UF_VERSION}-${UF_HASH}-linux-amd64.tgz"
        download_uf "$UF_TGZ_URL" "$pkg"
        say "Extracting .tgz to /opt"
        tar -xzf "$pkg" -C /opt
    fi

    [[ -x "$UF_BIN" ]] || die "UF install failed — $UF_BIN not found."
}

write_config() {
    mkdir -p "$LOCAL_CONF"
    umask 077

    # user-seed.conf — Splunk consumes this on first start
    cat > "$LOCAL_CONF/user-seed.conf" <<EOF
[user_info]
USERNAME = ${ADMIN_USER}
PASSWORD = ${ADMIN_PASS}
EOF

    # server.conf
    cat > "$LOCAL_CONF/server.conf" <<EOF
[general]
serverName = $(hostname -s)-uf
EOF

    # outputs.conf
    cat > "$LOCAL_CONF/outputs.conf" <<EOF
[tcpout]
defaultGroup = primary

[tcpout:primary]
server = ${INDEXER}:9997
EOF

    # inputs.conf — only monitor files that actually exist
    cat > "$LOCAL_CONF/inputs.conf" <<EOF
[default]
index = main

EOF

    for f in /var/log/syslog /var/log/auth.log /var/log/messages /var/log/secure /var/log/audit/audit.log; do
        if [[ -f "$f" ]]; then
            cat >> "$LOCAL_CONF/inputs.conf" <<EOF
[monitor://${f}]
index = main

EOF
            say "Monitoring: $f"
        fi
    done

    chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME"
    chmod 600 "$LOCAL_CONF/user-seed.conf" "$LOCAL_CONF/server.conf" \
              "$LOCAL_CONF/outputs.conf"   "$LOCAL_CONF/inputs.conf"

    unset ADMIN_PASS  # clear from env

    say "Configs written to $LOCAL_CONF"
}

start_uf() {
    say "Starting UF (accepting license)"
    sudo -u "$SPLUNK_USER" "$UF_BIN" start --accept-license --answer-yes --no-prompt

    say "Enabling boot-start"
    if have systemctl; then
        "$UF_BIN" enable boot-start -systemd-managed 1 -user "$SPLUNK_USER" >/dev/null 2>&1 || \
        "$UF_BIN" enable boot-start -user "$SPLUNK_USER" >/dev/null 2>&1 || \
        warn "Could not enable boot-start automatically"
    else
        "$UF_BIN" enable boot-start -user "$SPLUNK_USER" >/dev/null 2>&1 || true
    fi
}

cleanup_user_seed() {
    if [[ -f "$SPLUNK_HOME/etc/passwd" ]] && grep -q "^${ADMIN_USER}:" "$SPLUNK_HOME/etc/passwd"; then
        rm -f "$LOCAL_CONF/user-seed.conf"
        say "Removed user-seed.conf (creds consumed by Splunk)"
    else
        warn "user-seed.conf still present — Splunk may not have processed it yet."
    fi
}

verify() {
    echo ""
    echo "=== Forward-server status ==="
    "$UF_BIN" list forward-server 2>/dev/null || true

    echo ""
    echo "=== Monitors ==="
    "$UF_BIN" list monitor 2>/dev/null | head -30 || true

    echo ""
    echo "DONE. Log: $LOG_FILE"
    echo "Search in Splunk: index=main host=$(hostname -s)"
}

# ---------- Main ----------
setup_logging
prompt_inputs
ensure_splunk_user
install_uf
write_config
start_uf
sleep 5
cleanup_user_seed
verify
