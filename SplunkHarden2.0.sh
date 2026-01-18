#!/usr/bin/env bash
# oracle9-splunk-ccdc-complete.sh
# Complete hardening + password management for Oracle Linux 9.2 Splunk server (CCDC)
# Designed for 2026 SEMO Invitational
#
# Default users per team pack: root, sysadmin (password: Changeme1!)
# Scored service: SSH (likely uses sysadmin)
#
# Usage: sudo bash oracle9-splunk-ccdc-complete.sh [--skip-passwords] [--restart-splunk]

set -euo pipefail
IFS=$'\n\t'

### -------------------- Configuration --------------------
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SPLUNK_USER="${SPLUNK_USER:-splunk}"
SPLUNK_GROUP="${SPLUNK_GROUP:-splunk}"

SPLUNK_WEB_PORT=8000
SPLUNK_MGMT_PORT=8089
SPLUNK_RECEIVE_PORT=9997

CCDC_DIR="/ccdc"
CCDC_ETC="${CCDC_DIR}/etc"
SCRIPT_DIR="${CCDC_DIR}/scripts"

SKIP_PASSWORDS="0"
RESTART_SPLUNK="0"

### -------------------- Parse Arguments --------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-passwords) SKIP_PASSWORDS="1"; shift ;;
    --restart-splunk) RESTART_SPLUNK="1"; shift ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

### -------------------- Helper Functions --------------------
say(){ echo -e "\e[32m[+]\e[0m $*"; }
warn(){ echo -e "\e[33m[-]\e[0m $*" >&2; }
err(){ echo -e "\e[31m[!]\e[0m $*" >&2; }
die(){ err "$*"; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "Must be run as root"
}

sendLog(){
  local LOGFILE="${CCDC_DIR}/logs/harden.log"
  mkdir -p "$(dirname "$LOGFILE")"
  echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" >> "$LOGFILE"
}

backup_file() {
  local src="$1"
  [[ -e "$src" ]] || return 0
  cp -a "$src" "${BACKUP_DIR}/$(basename "$src").${TS}" 2>/dev/null || true
}

pkg_install() {
  dnf -y install "$@" >/dev/null 2>&1 || warn "Failed to install: $*"
}

### -------------------- Splunk FS Guardrails --------------------
fix_splunk_fs() {
  [[ -d "$SPLUNK_HOME" ]] || return 0
  say "Ensuring Splunk filesystem ownership/permissions"

  # Ensure splunk-launch.conf pins the OS user
  local launch_conf="${SPLUNK_HOME}/etc/splunk-launch.conf"
  if [[ -f "$launch_conf" ]]; then
    if grep -q '^SPLUNK_OS_USER=' "$launch_conf"; then
      sed -i "s/^SPLUNK_OS_USER=.*/SPLUNK_OS_USER=${SPLUNK_USER}/" "$launch_conf"
    else
      echo "SPLUNK_OS_USER=${SPLUNK_USER}" >> "$launch_conf"
    fi
    chown "${SPLUNK_USER}:${SPLUNK_GROUP}" "$launch_conf"
    chmod 644 "$launch_conf"
  fi

  # Own the whole tree (prevents root-owned local.meta / users.ini / var issues)
  chown -R "${SPLUNK_USER}:${SPLUNK_GROUP}" "${SPLUNK_HOME}"

  # Runtime dirs must exist + be writable by splunk
  install -d -o "${SPLUNK_USER}" -g "${SPLUNK_GROUP}" -m 0700 \
    "${SPLUNK_HOME}/var" \
    "${SPLUNK_HOME}/var/log" \
    "${SPLUNK_HOME}/var/run" \
    "${SPLUNK_HOME}/var/run/splunk" \
    "${SPLUNK_HOME}/var/log/splunk" \
    "${SPLUNK_HOME}/var/log/introspection" \
    "${SPLUNK_HOME}/var/log/watchdog" 2>/dev/null || true

  # Users mapping must be accessible by splunk
  if [[ -d "${SPLUNK_HOME}/etc/users" ]]; then
    chown -R "${SPLUNK_USER}:${SPLUNK_GROUP}" "${SPLUNK_HOME}/etc/users"
    chmod 755 "${SPLUNK_HOME}/etc/users"
    [[ -f "${SPLUNK_HOME}/etc/users/users.ini" ]] && chmod 600 "${SPLUNK_HOME}/etc/users/users.ini"
  fi

  # Restore SELinux contexts if enforcing (best-effort)
  if have getenforce && [[ "$(getenforce)" == "Enforcing" ]] && have restorecon; then
    restorecon -Rv "${SPLUNK_HOME}" >/dev/null 2>&1 || true
  fi
}

splunk_unit_uses_splunk_user() {
  [[ -n "${SPLUNK_UNIT:-}" ]] || return 1
  systemctl cat "${SPLUNK_UNIT}.service" 2>/dev/null | grep -qE "^[[:space:]]*User[[:space:]]*=[[:space:]]*${SPLUNK_USER}[[:space:]]*$"
}

preflight_splunk() {
  [[ -d "$SPLUNK_HOME" ]] || return 0

  # If Splunk is running as root, fix before trying to restart.
  if pgrep -u root -f "${SPLUNK_HOME}/bin/splunkd" >/dev/null 2>&1; then
    warn "Splunk appears to be running as root; stopping it to prevent root-owned files"
    "${SPLUNK_HOME}/bin/splunk" stop >/dev/null 2>&1 || pkill -TERM -f "${SPLUNK_HOME}/bin/splunkd" || true
    sleep 2
    pkill -KILL -f "${SPLUNK_HOME}/bin/splunkd" 2>/dev/null || true
  fi

  # Repair filesystem state (root-owned local.meta/var/users.ini causes the exact crash you saw)
  fix_splunk_fs

  # Best-effort: remove stale pid so splunk restart doesn't choke
  rm -f "${SPLUNK_HOME}/var/run/splunk/splunkd.pid" 2>/dev/null || true
}

### -------------------- Initialization --------------------
require_root

TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="/root/ccdc_backups_${TS}"
mkdir -p "$BACKUP_DIR"
mkdir -p "$CCDC_DIR" "$CCDC_ETC" "$SCRIPT_DIR" "${CCDC_DIR}/logs"

say "=== Oracle 9.2 Splunk CCDC Hardening - SEMO 2026 ==="
say "Backup directory: $BACKUP_DIR"
sendLog "=== Hardening script started ==="

# Verify Splunk user exists
if ! id -u "$SPLUNK_USER" >/dev/null 2>&1; then
  warn "Splunk user '$SPLUNK_USER' does not exist; some Splunk operations may fail"
fi

# Detect Splunk systemd unit name
SPLUNK_UNIT=""
for u in splunk Splunkd splunkd; do
  if systemctl list-unit-files 2>/dev/null | grep -q "^${u}\.service"; then
    SPLUNK_UNIT="$u"
    say "Detected Splunk systemd unit: ${SPLUNK_UNIT}.service"
    break
  fi
done

# Backup critical files
for f in \
  /etc/selinux/config \
  /etc/ssh/sshd_config \
  /etc/security/limits.conf \
  /etc/sysctl.conf \
  /etc/audit/rules.d/ccdc.rules \
  /etc/passwd \
  /etc/shadow \
  /etc/group \
  /etc/sudoers \
  "${SPLUNK_HOME}/etc/system/local/server.conf" \
  "${SPLUNK_HOME}/etc/system/local/web.conf" \
  "${SPLUNK_HOME}/etc/system/local/inputs.conf"
do backup_file "$f"; done

### -------------------- Password Management --------------------
change_passwords() {
  if [[ "$SKIP_PASSWORDS" == "1" ]]; then
    say "Skipping password changes (--skip-passwords)"
    return 0
  fi

  say "=== Password Management ==="

  # Root password
  echo -e "\n\e[36m[*] Change root password\e[0m"
  while true; do
    echo -n "Change root password? (y/n): "
    read -r resp
    if [[ "$resp" =~ ^[Yy]$ ]]; then
      while true; do
        echo -n "Enter new root password: "
        stty -echo; read -r rootPass; stty echo; echo

        # Check for problematic characters
        if [[ "$rootPass" =~ [\\\"\`\$] ]]; then
          warn "Password contains shell metacharacters (\\, \", \`, \$). Choose a simpler password."
          continue
        fi

        echo -n "Confirm root password: "
        stty -echo; read -r confirmPass; stty echo; echo

        if [[ "$rootPass" == "$confirmPass" ]]; then
          echo "root:$rootPass" | chpasswd
          say "Root password changed"
          sendLog "Root password changed"
          break
        else
          warn "Passwords do not match. Try again."
        fi
      done
      break
    elif [[ "$resp" =~ ^[Nn]$ ]]; then
      warn "Skipping root password change"
      break
    fi
  done

  # Sysadmin password (CRITICAL - SSH scored service!)
  if id sysadmin >/dev/null 2>&1; then
    echo -e "\n\e[36m[*] Change sysadmin password (IMPORTANT: SSH is scored!)\e[0m"
    echo -e "\e[33mREMINDER: After changing, submit PCR: sysadmin,<newpassword>\e[0m"
    while true; do
      echo -n "Change sysadmin password? (y/n): "
      read -r resp
      if [[ "$resp" =~ ^[Yy]$ ]]; then
        while true; do
          echo -n "Enter new sysadmin password: "
          stty -echo; read -r sysPass; stty echo; echo

          # Check for problematic characters
          if [[ "$sysPass" =~ [\\\"\`\$] ]]; then
            warn "Password contains shell metacharacters (\\, \", \`, \$). Choose a simpler password."
            continue
          fi

          echo -n "Confirm sysadmin password: "
          stty -echo; read -r confirmPass; stty echo; echo

          if [[ "$sysPass" == "$confirmPass" ]]; then
            echo "sysadmin:$sysPass" | chpasswd
            say "Sysadmin password changed"
            sendLog "Sysadmin password changed"
            echo
            echo -e "\e[33m╔════════════════════════════════════════════════════════════╗\e[0m"
            echo -e "\e[33m║ SUBMIT PCR NOW: sysadmin,${sysPass}                        ║\e[0m"
            echo -e "\e[33m╚════════════════════════════════════════════════════════════╝\e[0m"
            echo
            break
          else
            warn "Passwords do not match. Try again."
          fi
        done
        break
      elif [[ "$resp" =~ ^[Nn]$ ]]; then
        warn "Skipping sysadmin password change"
        break
      fi
    done
  fi

  # Optional: Create additional admin user
  echo -e "\n\e[36m[*] Create additional admin user (optional)\e[0m"
  echo -n "Create additional admin user? (y/n): "
  read -r resp
  if [[ "$resp" =~ ^[Yy]$ ]]; then
    echo -n "Enter username: "
    read -r adminUser

    if id "$adminUser" >/dev/null 2>&1; then
      warn "User $adminUser already exists, skipping creation"
    else
      useradd "$adminUser"
      while true; do
        echo -n "Enter password for $adminUser: "
        stty -echo; read -r adminPass; stty echo; echo

        if [[ "$adminPass" =~ [\\\"\`\$] ]]; then
          warn "Password contains shell metacharacters (\\, \", \`, \$). Choose a simpler password."
          continue
        fi

        echo -n "Confirm $adminUser password: "
        stty -echo; read -r confirmPass; stty echo; echo

        if [[ "$adminPass" == "$confirmPass" ]]; then
          echo "$adminUser:$adminPass" | chpasswd
          usermod -aG wheel "$adminUser"
          say "$adminUser user created with sudo access"
          sendLog "$adminUser user created"
          break
        else
          warn "Passwords do not match. Try again."
        fi
      done
    fi
  fi

  # Splunk Web UI admin password
  if [[ -x "${SPLUNK_HOME}/bin/splunk" ]]; then
    echo -e "\n\e[36m[*] Change Splunk Web UI admin password\e[0m"
    echo -n "Change Splunk admin password? (y/n): "
    read -r resp
    if [[ "$resp" =~ ^[Yy]$ ]]; then
      echo -n "Enter current Splunk admin password: "
      stty -echo; read -r oldPass; stty echo; echo

      while true; do
        echo -n "Enter new Splunk admin password: "
        stty -echo; read -r newPass; stty echo; echo

        if [[ "$newPass" =~ [\\\"\`\$] ]]; then
          warn "Password contains shell metacharacters (\\, \", \`, \$). Choose a simpler password."
          continue
        fi

        echo -n "Confirm new Splunk admin password: "
        stty -echo; read -r confirmPass; stty echo; echo

        if [[ "$newPass" == "$confirmPass" ]]; then
          if su -s /bin/bash -c "${SPLUNK_HOME}/bin/splunk edit user admin -password \"${newPass}\" -auth \"admin:${oldPass}\"" "$SPLUNK_USER" 2>/dev/null; then
            say "Splunk admin password changed"
            sendLog "Splunk admin password changed"
          else
            warn "Failed to change Splunk admin password (check current password)"
          fi
          break
        else
          warn "Passwords do not match. Try again."
        fi
      done
    fi
  fi
}

### -------------------- Package Installation --------------------
install_packages() {
  say "Installing required packages"
  pkg_install epel-release
  pkg_install firewalld audit aide policycoreutils-python-utils setools-console \
    git net-tools rkhunter iptables iptables-services rsyslog

  # Enable rsyslog for proper logging
  systemctl enable --now rsyslog >/dev/null 2>&1 || true
  sendLog "Packages installed"
}

### -------------------- SELinux --------------------
configure_selinux() {
  say "Configuring SELinux to enforcing"
  if [[ -f /etc/selinux/config ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
  fi

  if have setenforce; then
    if setenforce 1 2>/dev/null; then
      say "SELinux set to enforcing"
    else
      warn "SELinux enforce failed - may need reboot or is already enforcing"
    fi
  fi

  echo
  warn "If Splunk fails to bind ports after this:"
  warn "  ausearch -m avc -ts recent | audit2why"
  warn "  semanage port -a -t http_port_t -p tcp 8000"
  warn "  Or temporarily: setenforce 0"
  echo

  sendLog "SELinux configured to enforcing"
}

### -------------------- SSH Hardening --------------------
harden_ssh() {
  say "Hardening SSH (keeping enabled for scoring)"

  local sshd_config="/etc/ssh/sshd_config"

  # Check if already hardened (idempotent)
  if grep -q "CCDC SSH Hardening" "$sshd_config"; then
    say "SSH already hardened, skipping"
    return 0
  fi

  # Ask about AllowUsers restriction
  echo
  echo -e "\e[36m[*] SSH Access Restriction\e[0m"
  echo "WARNING: Restricting SSH users can break scoring if scoreboard uses different account."
  echo "Team pack shows sysadmin as the likely scored user."
  echo
  echo -n "Restrict SSH to specific users? (y/n, default n): "
  read -r restrict_resp

  # Apply hardening settings
  cat >> "$sshd_config" <<'EOF'

# CCDC SSH Hardening
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
Protocol 2
LogLevel VERBOSE
UsePAM yes
EOF

  # Only add AllowUsers if explicitly requested
  if [[ "$restrict_resp" =~ ^[Yy]$ ]]; then
    local allow_users=()
    id -u sysadmin >/dev/null 2>&1 && allow_users+=("sysadmin")

    # Ask about additional users
    echo -n "Allow additional users? Enter usernames separated by spaces (or press Enter to skip): "
    read -r extra_users
    if [[ -n "$extra_users" ]]; then
      for u in $extra_users; do
        if id -u "$u" >/dev/null 2>&1; then
          allow_users+=("$u")
        else
          warn "User $u does not exist, not adding to AllowUsers"
        fi
      done
    fi

    if (( ${#allow_users[@]} > 0 )); then
      echo "AllowUsers ${allow_users[*]}" >> "$sshd_config"
      say "SSH restricted to users: ${allow_users[*]}"
    fi
  else
    # Use AllowGroups wheel instead (safer for scoring)
    echo "AllowGroups wheel" >> "$sshd_config"
    # Ensure sysadmin is in wheel
    usermod -aG wheel sysadmin 2>/dev/null || true
    say "SSH access via 'wheel' group (sysadmin added to wheel)"
  fi

  # Validate config before restarting
  if ! sshd -t; then
    err "sshd_config validation failed! Not restarting SSH"
    sendLog "ERROR: sshd_config invalid"
    return 1
  fi

  # Restart SSH
  systemctl restart sshd
  say "SSH hardened and restarted"
  sendLog "SSH hardened"
}

### -------------------- Firewall Configuration --------------------
configure_firewall() {
  say "Configuring firewalld (DROP-by-default; allow ssh/8000/9997 only)"
  systemctl enable --now firewalld >/dev/null 2>&1 || true

  firewall-cmd --permanent --new-zone=ccdc >/dev/null 2>&1 || true
  firewall-cmd --permanent --zone=ccdc --set-target=DROP >/dev/null 2>&1 || true

  firewall-cmd --permanent --zone=ccdc --add-service=ssh >/dev/null 2>&1 || true
  firewall-cmd --permanent --zone=ccdc --add-port="${SPLUNK_WEB_PORT}/tcp" >/dev/null 2>&1 || true
  firewall-cmd --permanent --zone=ccdc --add-port="${SPLUNK_RECEIVE_PORT}/tcp" >/dev/null 2>&1 || true

  firewall-cmd --permanent --zone=ccdc --add-rich-rule='rule family="ipv4" port port="8089" protocol="tcp" drop' >/dev/null 2>&1 || true

  mapfile -t IFACES < <(firewall-cmd --get-active-zones 2>/dev/null | awk '
    /^[[:alnum:]_-]+$/ {z=$1}
    $1=="interfaces:" {for (i=2;i<=NF;i++) print $i}
  ')

  if [[ ${#IFACES[@]} -eq 0 ]]; then
    IFACE="$(ip route show default 2>/dev/null | awk "{print \$5; exit}")"
    [[ -n "$IFACE" ]] && IFACES=("$IFACE")
  fi

  for i in "${IFACES[@]}"; do
    firewall-cmd --permanent --zone=ccdc --add-interface="$i" >/dev/null 2>&1 || true
  done

  firewall-cmd --reload >/dev/null 2>&1 || true

  say "Firewall configured (zone: ccdc; interfaces: ${IFACES[*]:-(none detected)})"
  firewall-cmd --zone=ccdc --list-all || true
  sendLog "Firewall configured (DROP default; allow 22/8000/9997)"
}

### -------------------- Splunk Configuration --------------------
configure_splunk() {
  if [[ ! -d "$SPLUNK_HOME" ]]; then
    warn "SPLUNK_HOME not found at $SPLUNK_HOME, skipping Splunk config"
    return 0
  fi

  say "Configuring Splunk"

  mkdir -p "${SPLUNK_HOME}/etc/system/local"

  cat > "${SPLUNK_HOME}/etc/system/local/server.conf" <<EOF
[sslConfig]
enableSplunkdSSL = true
sslVersions = tls1.2
cipherSuite = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
allowSslCompression = false

[general]
mgmtHostPort = 127.0.0.1:8089
EOF

  cat > "${SPLUNK_HOME}/etc/system/local/web.conf" <<EOF
[settings]
enableSplunkWebSSL = true
httpport = ${SPLUNK_WEB_PORT}
enableSearchJobXslt = false
EOF

  cat > "${SPLUNK_HOME}/etc/system/local/inputs.conf" <<EOF
[splunktcp://${SPLUNK_RECEIVE_PORT}]
disabled = 0
EOF

  cat > "${SPLUNK_HOME}/etc/system/local/distsearch.conf" <<EOF
[distributedSearch]
disabled = true
EOF

  # Ownership on local configs
  chown -R "${SPLUNK_USER}:${SPLUNK_GROUP}" "${SPLUNK_HOME}/etc/system/local"

  # Less brittle perms than 700-recursive (prevents accidental access breakage)
  chmod -R u=rwX,go=rX "${SPLUNK_HOME}/etc/system/local"
  chmod 600 "${SPLUNK_HOME}/etc/system/local/"*.conf 2>/dev/null || true

  # Validate configs (non-fatal)
  if [[ -x "${SPLUNK_HOME}/bin/splunk" ]]; then
    say "Validating Splunk configs..."
    su -s /bin/bash -c "${SPLUNK_HOME}/bin/splunk btool server list --debug" "$SPLUNK_USER" >/dev/null 2>&1 || warn "server.conf validation warnings"
    su -s /bin/bash -c "${SPLUNK_HOME}/bin/splunk btool web list --debug" "$SPLUNK_USER" >/dev/null 2>&1 || warn "web.conf validation warnings"
    su -s /bin/bash -c "${SPLUNK_HOME}/bin/splunk btool inputs list --debug" "$SPLUNK_USER" >/dev/null 2>&1 || warn "inputs.conf validation warnings"
  fi

  say "Splunk configured"
  sendLog "Splunk base configuration complete"
}

### -------------------- Splunk Ulimits --------------------
set_splunk_limits() {
  say "Setting Splunk ulimits"
  mkdir -p /etc/security/limits.d
  cat > /etc/security/limits.d/splunk.conf <<EOF
${SPLUNK_USER} soft nofile 64000
${SPLUNK_USER} hard nofile 64000
${SPLUNK_USER} soft nproc  16000
${SPLUNK_USER} hard nproc  16000
EOF
  sendLog "Splunk ulimits configured"
}

### -------------------- Audit Rules --------------------
configure_auditd() {
  say "Configuring auditd rules"

  mkdir -p /etc/audit/rules.d
  cat > /etc/audit/rules.d/ccdc.rules <<EOF
# Identity & auth
-w /etc/passwd -p wa -k user_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd_changes

# Splunk configs
-w ${SPLUNK_HOME}/etc/system/local/ -p wa -k splunk_config_changes
-w ${SPLUNK_HOME}/etc/apps/ -p wa -k splunk_app_changes

# Command logging
-a exit,always -F arch=b64 -S execve -k command_log
-w /usr/bin/sudo -p x -k sudo_log
-w /bin/su -p x -k su_log
EOF

  systemctl enable --now auditd >/dev/null 2>&1 || true
  augenrules --load >/dev/null 2>&1 || true

  sendLog "Auditd configured"
}

### -------------------- AIDE Setup --------------------
setup_aide() {
  say "Setting up AIDE (this may take a while)"

  if [[ ! -f /var/lib/aide/aide.db.gz ]]; then
    aide --init >/dev/null 2>&1 || warn "AIDE init failed"
    [[ -f /var/lib/aide/aide.db.new.gz ]] && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
  fi

  install -d -m 0750 /var/log/aide

  cat > /usr/local/bin/check_integrity <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ts="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="/var/log/aide"
mkdir -p "$LOG_DIR"

OUT="${LOG_DIR}/aide_check_${ts}.log"
SUMMARY="${LOG_DIR}/aide_summary_${ts}.txt"

set +e
aide --check | tee "$OUT"
rc=$?
set -e

grep -E '^(Added files:|Removed files:|Changed files:)' "$OUT" > "$SUMMARY" || true

if [[ $rc -ne 0 ]]; then
  logger -p authpriv.alert -t AIDE "INTEGRITY ALERT: differences detected; see $OUT and $SUMMARY"
else
  logger -p authpriv.info -t AIDE "Integrity OK (no differences)."
fi
exit $rc
EOF
  chmod +x /usr/local/bin/check_integrity

  cat > /etc/cron.d/aide-check <<'EOF'
*/15 * * * * root /usr/local/bin/check_integrity
EOF
  chmod 0644 /etc/cron.d/aide-check

  sendLog "AIDE configured"
}

### -------------------- Sysctl Hardening --------------------
harden_sysctl() {
  say "Applying sysctl hardening"

  cat > /etc/sysctl.d/99-ccdc.conf <<'EOF'
# CCDC sysctl hardening
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 3
kernel.sysrq = 0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.core.bpf_jit_harden = 2
fs.protected_fifos = 2
fs.protected_regular = 2
dev.tty.ldisc_autoload = 0
EOF

  sysctl --system >/dev/null 2>&1 || true
  sendLog "Sysctl hardened"
}

### -------------------- Disable Core Dumps --------------------
disable_core_dumps() {
  say "Disabling core dumps"
  if ! grep -qE '^\*\s+hard\s+core\s+0' /etc/security/limits.conf 2>/dev/null; then
    echo "* hard core 0" >> /etc/security/limits.conf
  fi
  sendLog "Core dumps disabled"
}

### -------------------- User Account Lockdown --------------------
lockdown_users() {
  say "Locking down unused user accounts (UID >= 1000 only)"

  NOLOGIN="${SCRIPT_DIR}/nologin.sh"
  cat <<'EOF' > "$NOLOGIN"
#!/bin/bash
echo "This account is unavailable."
EOF
  chmod 755 "$NOLOGIN"

  while IFS=: read -r username _ uid _ _ _ shell; do
    if [[ "$username" =~ ^(root|sysadmin|splunk)$ ]]; then
      continue
    fi

    if groups "$username" 2>/dev/null | grep -q '\bwheel\b'; then
      continue
    fi

    if [[ "$uid" -ge 1000 ]]; then
      if [[ "$shell" == "/sbin/nologin" ]] || [[ "$shell" == "$NOLOGIN" ]]; then
        continue
      fi

      usermod -s "$NOLOGIN" "$username" 2>/dev/null || true
      passwd -l "$username" 2>/dev/null || true
      sendLog "Locked user: $username"
    fi
  done < /etc/passwd
}

### -------------------- Secure Root --------------------
secure_root() {
  say "Securing root account"

  if [[ -f /etc/securetty ]]; then
    if ! grep -q "^tty1$" /etc/securetty; then
      echo "tty1" >> /etc/securetty
    fi
  fi

  chmod 700 /root
  sendLog "Root account secured"
}

### -------------------- Set UMASK --------------------
set_umask() {
  say "Setting secure UMASK"
  if ! grep -q "^umask 077" /etc/bashrc 2>/dev/null; then
    echo "umask 077" >> /etc/bashrc
  fi
  umask 077
  sendLog "UMASK set to 077"
}

### -------------------- Cron/AT Security --------------------
cronjail() {
  say "Copying existing cron/at jobs to jail for review"

  mkdir -p "$CCDC_ETC/cron.jail"

  for item in /etc/crontab; do
    if [[ -f "$item" ]] && [[ -s "$item" ]]; then
      cp "$item" "$CCDC_ETC/cron.jail/" 2>/dev/null || true
    fi
  done

  for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly /var/spool/cron /var/spool/at; do
    if [[ -d "$dir" ]] && [[ "$(ls -A "$dir" 2>/dev/null)" ]]; then
      mkdir -p "$CCDC_ETC/cron.jail/$(basename "$dir")"
      cp -r "$dir"/* "$CCDC_ETC/cron.jail/$(basename "$dir")/" 2>/dev/null || true
    fi
  done

  sendLog "Cron/at jobs copied to jail"
}

secure_cron_at() {
  say "Securing cron and at"

  systemctl enable --now crond >/dev/null 2>&1 || true

  touch /etc/cron.allow
  chmod 600 /etc/cron.allow

  echo "root" > /etc/cron.allow
  id -u sysadmin >/dev/null 2>&1 && echo "sysadmin" >> /etc/cron.allow
  : > /etc/cron.deny

  touch /etc/at.allow
  chmod 600 /etc/at.allow

  echo "root" > /etc/at.allow
  id -u sysadmin >/dev/null 2>&1 && echo "sysadmin" >> /etc/at.allow
  : > /etc/at.deny

  sendLog "Cron/AT secured"
}

### -------------------- Malicious Bash Detection --------------------
check_malicious_bash() {
  say "Checking for malicious bash configurations"

  for FILE in /etc/bashrc /etc/profile /etc/profile.d/* /root/.bashrc /root/.bash_profile \
              /home/*/.bashrc /home/*/.bash_profile /etc/bash.bashrc /root/.bash_login \
              /home/*/.bash_login /root/.profile /home/*/.profile /etc/environment; do

    if [[ ! -f "$FILE" ]]; then continue; fi

    if grep -qE "^[^#]*(trap|PROMPT_COMMAND|watch)" "$FILE"; then
      TRAP_CONTENT=$(grep "^[^#]*trap" "$FILE" 2>/dev/null || true)
      PROMPT_CONTENT=$(grep "^[^#]*PROMPT_COMMAND" "$FILE" 2>/dev/null || true)
      WATCH_CONTENT=$(grep "^[^#]*watch" "$FILE" 2>/dev/null || true)

      [[ -n "$TRAP_CONTENT" ]] && echo "$TRAP_CONTENT - Found in $FILE on $(date)" >> "${CCDC_DIR}/logs/malicious_bash.txt"
      [[ -n "$PROMPT_CONTENT" ]] && echo "$PROMPT_CONTENT - Found in $FILE on $(date)" >> "${CCDC_DIR}/logs/malicious_bash.txt"
      [[ -n "$WATCH_CONTENT" ]] && echo "$WATCH_CONTENT - Found in $FILE on $(date)" >> "${CCDC_DIR}/logs/malicious_bash.txt"

      sed -i '/^[^#]*trap/d' "$FILE"
      sed -i '/^[^#]*watch/d' "$FILE"

      sendLog "Malicious bash config removed from $FILE"
    fi
  done

  export PROMPT_COMMAND=''
  unset PROMPT_COMMAND
}

### -------------------- System Monitoring Service --------------------
setup_monitoring() {
  say "Installing CCDC monitoring service"

  cat > /usr/local/bin/ccdc_monitor.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
LOG_DIR="/var/log/ccdc_monitoring"
mkdir -p "\${LOG_DIR}"

ALLOWED_PORTS=("tcp:22" "tcp:8000" "tcp:9997")
SPLUNK_UNIT="${SPLUNK_UNIT:-splunk}"

while true; do
  TS="\$(date +%Y%m%d_%H%M%S)"
  SNAP="\${LOG_DIR}/status_\${TS}.log"

  {
    echo "=== System Status \${TS} ==="
    echo "== Splunk service =="
    if systemctl is-active --quiet "\${SPLUNK_UNIT}"; then
      systemctl --no-pager status "\${SPLUNK_UNIT}" || true
    else
      echo "SPLUNK NOT ACTIVE"
    fi
    echo
    echo "== Listening sockets =="
    ss -tulpen
    echo
    echo "== Recent messages =="
    if [[ -f /var/log/messages ]]; then
      tail -n 100 /var/log/messages
    else
      journalctl -n 100 --no-pager
    fi
  } > "\$SNAP"

  if ! systemctl is-active --quiet "\${SPLUNK_UNIT}"; then
    logger -p daemon.crit -t CCDC "SPLUNK DOWN: service not active"
  fi

  if ss -ltnp | awk '\$4 ~ /:8089\$/ {print \$4}' | grep -q -v '^127\.0\.0\.1:'; then
    logger -p authpriv.alert -t CCDC "SECURITY: splunkd (8089) listening on non-loopback!"
  fi

  ALLOW_RE="\$(printf '%s\n' "\${ALLOWED_PORTS[@]}" | sed 's#^#^#;s#:#.*:#;s#\$#\$#' | paste -sd'|' -)"
  BAD_LISTEN="\$(ss -ltnpH | awk '{print "tcp:"\$4}' | grep -Ev '127\.0\.0\.1:' | grep -Ev "\${ALLOW_RE:-^\$}" || true)"

  if [[ -n "\${BAD_LISTEN}" ]]; then
    logger -p authpriv.warning -t CCDC "UNEXPECTED LISTENERS: \${BAD_LISTEN}"
  fi

  LAST_AIDE="\$(ls -1t /var/log/aide/aide_summary_*.txt 2>/dev/null | head -1 || true)"
  if [[ -n "\$LAST_AIDE" ]] && grep -qE '^(Added files:|Removed files:|Changed files:)\s+[1-9]' "\$LAST_AIDE" 2>/dev/null; then
    logger -p authpriv.alert -t CCDC "AIDE: Integrity differences detected. See \$LAST_AIDE"
  fi

  sleep 300
done
EOF
  chmod +x /usr/local/bin/ccdc_monitor.sh

  cat > /etc/systemd/system/ccdc-monitor.service <<'EOF'
[Unit]
Description=CCDC Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ccdc_monitor.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now ccdc-monitor >/dev/null 2>&1 || true
  sendLog "CCDC monitoring service installed"
}

### -------------------- Disable Uncommon Protocols --------------------
disable_protocols() {
  say "Disabling uncommon network protocols"

  for proto in dccp sctp rds tipc; do
    echo "install $proto /bin/false" > "/etc/modprobe.d/${proto}.conf"
  done

  sendLog "Uncommon protocols disabled"
}

### -------------------- Secure System Permissions --------------------
secure_permissions() {
  say "Securing system file permissions"

  chown root:root /etc/group
  chmod 644 /etc/group
  chown root:root /etc/sudoers
  chmod 440 /etc/sudoers
  chown root:root /etc/passwd
  chmod 644 /etc/passwd

  if getent group shadow >/dev/null; then
    chown root:shadow /etc/shadow
  else
    chown root:root /etc/shadow
  fi
  chmod 640 /etc/shadow

  if [[ -f /boot/grub2/grub.cfg ]]; then
    chmod 600 /boot/grub2/grub.cfg
  fi

  sendLog "System permissions secured"
}

### -------------------- Disable/Remove Unnecessary Services --------------------
cleanup_services() {
  say "Disabling unnecessary services"

  local services=(
    "rpcbind" "rpcgssd" "rpcsvcgssd" "rpcidmapd"
    "nfs" "netfs" "cups" "avahi-daemon" "bluetooth"
    "postfix" "sendmail"
  )

  for svc in "${services[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
  done

  sendLog "Unnecessary services disabled"
}

### -------------------- Final Backup --------------------
final_backup() {
  say "Creating final backup"

  local backup_file="/ccdc/backups/final_backup_${TS}.tgz"
  mkdir -p /ccdc/backups

  tar -czf "$backup_file" \
    /opt/splunk/etc \
    /etc/ssh \
    /etc/security \
    /etc/audit \
    /etc/sysctl.d \
    /etc/sudoers \
    /etc/passwd \
    /etc/shadow \
    /etc/group \
    2>/dev/null || warn "Backup had some errors (non-fatal)"

  say "Final backup saved to $backup_file"
  sendLog "Final backup created"
}

### -------------------- Restart Splunk --------------------
restart_splunk() {
  if [[ "$RESTART_SPLUNK" != "1" ]]; then
    return 0
  fi

  if [[ ! -x "${SPLUNK_HOME}/bin/splunk" ]]; then
    warn "Splunk binary not found, skipping restart"
    return 0
  fi

  say "Restarting Splunk to apply changes"

  # Preflight: stop root-run splunk, fix perms, clear stale pid
  preflight_splunk

  # Prefer systemd only if unit is explicitly configured to run as SPLUNK_USER
  if [[ -n "$SPLUNK_UNIT" ]] && splunk_unit_uses_splunk_user; then
    systemctl restart "$SPLUNK_UNIT" || warn "Failed to restart Splunk via systemd"
  else
    warn "Restarting via su to ensure Splunk runs as ${SPLUNK_USER}"
    su -s /bin/bash -c "${SPLUNK_HOME}/bin/splunk restart" "$SPLUNK_USER" || warn "Failed to restart Splunk"
  fi

  sendLog "Splunk restarted"
}

### -------------------- Main Execution --------------------
main() {
  say "Starting hardening at $(date)"

  change_passwords

  install_packages
  configure_selinux
  harden_ssh
  configure_firewall

  configure_splunk
  fix_splunk_fs
  set_splunk_limits

  configure_auditd
  harden_sysctl
  disable_core_dumps
  disable_protocols

  lockdown_users
  secure_root
  set_umask

  cronjail
  secure_cron_at

  check_malicious_bash

  say "Initializing AIDE in background..."
  setup_aide &
  aide_pid=$!

  setup_monitoring

  secure_permissions
  cleanup_services

  if kill -0 $aide_pid 2>/dev/null; then
    say "Waiting for AIDE initialization to complete..."
    wait $aide_pid 2>/dev/null || true
  fi

  final_backup
  fix_splunk_fs
  restart_splunk

  say "=== Hardening Complete ==="
  sendLog "=== Hardening script completed successfully ==="

  echo
  echo -e "\e[32m╔════════════════════════════════════════════════════════════╗\e[0m"
  echo -e "\e[32m║           Hardening Complete - Important Info             ║\e[0m"
  echo -e "\e[32m╚════════════════════════════════════════════════════════════╝\e[0m"
  echo
  echo "Backups saved to: $BACKUP_DIR"
  echo "Logs saved to: ${CCDC_DIR}/logs/harden.log"
  echo
  echo "Verification commands:"
  echo "  ss -ltnp | egrep ':${SPLUNK_WEB_PORT}|:${SPLUNK_MGMT_PORT}|:${SPLUNK_RECEIVE_PORT}|:22'"
  echo "  firewall-cmd --list-all"
  echo "  getenforce"
  if [[ -n "$SPLUNK_UNIT" ]]; then
    echo "  systemctl status ${SPLUNK_UNIT} ccdc-monitor sshd --no-pager"
  fi
  echo
  echo "Review these:"
  echo "  1. Cronjail contents: ls -la ${CCDC_ETC}/cron.jail/"
  echo "  2. Malicious bash log: cat ${CCDC_DIR}/logs/malicious_bash.txt"
  echo "  3. Monitoring logs: tail -f /var/log/ccdc_monitoring/status_*.log"
  echo "  4. AIDE logs: tail -f /var/log/aide/aide_check_*.log"
  echo
  echo "Access Splunk Web UI: https://<your-ip>:8000"
  echo "Test SSH access with sysadmin credentials"
  echo
  if [[ "$RESTART_SPLUNK" != "1" ]]; then
    warn "Splunk NOT restarted. Run this to apply receiver/mgmt changes:"
    if [[ -n "$SPLUNK_UNIT" ]]; then
      warn "  systemctl restart ${SPLUNK_UNIT}"
    else
      warn "  su - splunk -c '/opt/splunk/bin/splunk restart'"
    fi
  fi
  echo
  echo -e "\e[33m╔════════════════════════════════════════════════════════════╗\e[0m"
  echo -e "\e[33m║  REMINDER: Submit PCRs if you changed any passwords!      ║\e[0m"
  echo -e "\e[33m║  Format: username,newpassword                             ║\e[0m"
  echo -e "\e[33m║  Scoreboard: https://score.semocdc.org                    ║\e[0m"
  echo -e "\e[33m╚════════════════════════════════════════════════════════════╝\e[0m"
  echo
}

main
exit 0
