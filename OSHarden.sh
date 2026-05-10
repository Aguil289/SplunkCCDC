#!/usr/bin/env bash
# oracle9-os-harden.sh
# OS hardening for Oracle Linux 9.2 
# Run THIS first, then run the Splunk hardening script
#
# This script adds:
#   - SELinux config, Sysctl hardening, Auditd rules
#   - User lockdown, Malicious bash detection, Protocol disabling
#   - AIDE setup, Core dump disable, System permissions
#
# Usage: sudo bash oracle9-os-harden.sh

set -euo pipefail
IFS=$'\n\t'

### -------------------- Configuration --------------------
CCDC_DIR="/ccdc"
CCDC_ETC="${CCDC_DIR}/etc"
SCRIPT_DIR="${CCDC_DIR}/scripts"

### -------------------- Helper Functions --------------------
say()  { echo -e "\e[32m[+]\e[0m $*"; }
warn() { echo -e "\e[33m[-]\e[0m $*" >&2; }
err()  { echo -e "\e[31m[!]\e[0m $*" >&2; }
die()  { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "Must be run as root"
}

sendLog() {
  local LOGFILE="${CCDC_DIR}/logs/os-harden.log"
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

### -------------------- Initialization --------------------
require_root

TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="/root/ccdc_backups_${TS}"
mkdir -p "$BACKUP_DIR"
mkdir -p "$CCDC_DIR" "$CCDC_ETC" "$SCRIPT_DIR" "${CCDC_DIR}/logs"

say "=== Oracle Linux 9.2 OS Hardening ==="
say "=== (Run BEFORE Splunk script) ==="
say "Backup directory: $BACKUP_DIR"
sendLog "=== OS Hardening script started ==="

# Backup critical files
for f in /etc/selinux/config /etc/security/limits.conf /etc/sysctl.conf \
         /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
  backup_file "$f"
done

### -------------------- Install Additional Packages --------------------
install_packages() {
  say "Installing additional security packages"
  pkg_install audit aide policycoreutils-python-utils setools-console rsyslog

  systemctl enable --now rsyslog >/dev/null 2>&1 || true
  sendLog "Security packages installed"
}

### -------------------- SELinux --------------------
configure_selinux() {
  say "Configuring SELinux (permissive for competition stability)"

  if [[ -f /etc/selinux/config ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
  fi

  have setenforce && setenforce 0 2>/dev/null || true

  sendLog "SELinux set to permissive"
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
kernel.yama.ptrace_scope = 2
kernel.sysrq = 0

# Network hardening
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

# IPv6 disable
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Additional
net.core.bpf_jit_harden = 2
fs.protected_fifos = 2
fs.protected_regular = 2
EOF

  sysctl --system >/dev/null 2>&1 || true
  sendLog "Sysctl hardened"
}

### -------------------- Auditd --------------------
configure_auditd() {
  say "Configuring auditd"

  mkdir -p /etc/audit/rules.d
  cat > /etc/audit/rules.d/ccdc.rules <<'EOF'
-D
-b 8192
-f 1

# Identity monitoring
-w /etc/passwd -p wa -k user_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Cron monitoring
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.d/ -p wa -k cron_changes
-w /var/spool/cron/ -p wa -k cron_changes

# Command execution
-a exit,always -F arch=b64 -S execve -k cmd_exec
-w /usr/bin/sudo -p x -k sudo_exec
-w /bin/su -p x -k su_exec

# Kernel modules
-w /sbin/insmod -p x -k kernel_mod
-w /sbin/rmmod -p x -k kernel_mod
-w /sbin/modprobe -p x -k kernel_mod

# Splunk config monitoring
-w /opt/splunk/etc/ -p wa -k splunk_config
EOF

  systemctl enable --now auditd >/dev/null 2>&1 || true
  augenrules --load >/dev/null 2>&1 || true

  sendLog "Auditd configured"
}

### -------------------- Disable Core Dumps --------------------
disable_core_dumps() {
  say "Disabling core dumps"

  grep -qE '^\*\s+hard\s+core\s+0' /etc/security/limits.conf 2>/dev/null || \
    echo "* hard core 0" >> /etc/security/limits.conf

  sendLog "Core dumps disabled"
}

### -------------------- Disable Uncommon Protocols --------------------
disable_protocols() {
  say "Disabling uncommon network protocols"

  for proto in dccp sctp rds tipc; do
    echo "install $proto /bin/false" > "/etc/modprobe.d/${proto}.conf"
  done

  sendLog "Protocols disabled"
}


### -------------------- Secure Root --------------------
secure_root() {
  say "Securing root account"

  echo "tty1" > /etc/securetty
  chmod 600 /etc/securetty
  chmod 700 /root

  sendLog "Root secured"
}

### -------------------- UMASK --------------------
set_umask() {
  say "Setting UMASK 077"

  for f in /etc/bashrc /etc/profile; do
    [[ -f "$f" ]] && ! grep -q "^umask 077" "$f" && echo "umask 077" >> "$f"
  done

  sendLog "UMASK set"
}

### -------------------- Backup Cron Jobs (for review) --------------------
backup_cron_jobs() {
  say "Backing up cron jobs for review"

  mkdir -p "$CCDC_ETC/cron.jail"

  [[ -f /etc/crontab ]] && cp /etc/crontab "$CCDC_ETC/cron.jail/" 2>/dev/null || true

  for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron; do
    if [[ -d "$dir" ]] && [[ "$(ls -A "$dir" 2>/dev/null)" ]]; then
      mkdir -p "$CCDC_ETC/cron.jail/$(basename "$dir")"
      cp -r "$dir"/* "$CCDC_ETC/cron.jail/$(basename "$dir")/" 2>/dev/null || true
    fi
  done

  say "Cron backed up to: $CCDC_ETC/cron.jail/"
  sendLog "Cron jobs backed up"
}

### -------------------- Malicious Bash Detection --------------------
check_malicious_bash() {
  say "Checking for malicious bash configurations"

  local malicious_log="${CCDC_DIR}/logs/malicious_bash.txt"
  local found=0

  for FILE in /etc/bashrc /etc/profile /etc/profile.d/* /root/.bashrc /root/.bash_profile \
              /home/*/.bashrc /home/*/.bash_profile /root/.profile /home/*/.profile; do
    [[ -f "$FILE" ]] || continue

    if grep -qE "^[^#]*(trap|PROMPT_COMMAND|curl\s|wget\s|nc\s|/dev/tcp|/dev/udp|bash\s+-i)" "$FILE" 2>/dev/null; then
      found=1
      echo "=== $FILE ===" >> "$malicious_log"
      grep -nE "^[^#]*(trap|PROMPT_COMMAND|curl\s|wget\s|nc\s|/dev/tcp|/dev/udp|bash\s+-i)" "$FILE" \
        >> "$malicious_log" 2>/dev/null || true

      # 🚨 GUARD: NEVER auto-edit system-wide shell init files
      case "$FILE" in
        /etc/bashrc|/etc/profile|/etc/profile.d/*)
          warn "Suspicious patterns detected in system file $FILE — logged ONLY, not modified"
          sendLog "Detected suspicious bash content in system file $FILE (not auto-cleaned)"
          continue
          ;;
      esac

      sed -i '/^[^#]*trap/d; /^[^#]*PROMPT_COMMAND/d' "$FILE"
      warn "Cleaned: $FILE"
      sendLog "Cleaned malicious bash: $FILE"
    fi
  done

  export PROMPT_COMMAND=''
  unset PROMPT_COMMAND

  [[ $found -eq 1 ]] && warn "Review: $malicious_log" || say "No malicious bash found"
}


### -------------------- Secure Permissions --------------------
secure_permissions() {
  say "Securing system permissions"

  chown root:root /etc/passwd /etc/group /etc/sudoers
  chmod 644 /etc/passwd /etc/group
  chmod 440 /etc/sudoers

  if getent group shadow >/dev/null; then
    chown root:shadow /etc/shadow
  else
    chown root:root /etc/shadow
  fi
  chmod 640 /etc/shadow

  [[ -f /boot/grub2/grub.cfg ]] && chmod 600 /boot/grub2/grub.cfg

  sendLog "Permissions secured"
}

### -------------------- Disable Services --------------------
cleanup_services() {
  say "Disabling unnecessary services"
  systemctl stop cockpit.socket cockpit 2>/dev/null || true
  systemctl disable cockpit.socket cockpit 2>/dev/null || true
  dnf remove -y cockpit cockpit-ws cockpit-bridge cockpit-system 2>/dev/null || true

  for svc in rpcbind nfs nfs-server cups avahi-daemon bluetooth postfix sendmail; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
  done

  sendLog "Services disabled"
}

### -------------------- AIDE Setup --------------------
setup_aide() {
  say "Setting up AIDE (background)"

  if [[ ! -f /var/lib/aide/aide.db.gz ]]; then
    aide --init >/dev/null 2>&1 &
    say "AIDE initializing in background (takes a while)"
  fi

  mkdir -p /var/log/aide
  cat > /usr/local/bin/aide-check <<'EOF'
#!/bin/bash
LOG="/var/log/aide/check_$(date +%Y%m%d_%H%M%S).log"
aide --check > "$LOG" 2>&1
[[ $? -ne 0 ]] && logger -p authpriv.alert -t AIDE "Changes detected - $LOG"
EOF
  chmod +x /usr/local/bin/aide-check

  sendLog "AIDE configured"
}

### -------------------- Quick Status Script --------------------
setup_status_script() {
  say "Installing ccdc-status command"

  cat > /usr/local/bin/ccdc-status <<'EOF'
#!/bin/bash
echo "=== Listening Ports ==="
ss -tlnp
echo
echo "=== Failed Logins ==="
grep -i "failed" /var/log/secure 2>/dev/null | tail -5 || journalctl -u systemd-logind | grep -i fail | tail -5
echo
echo "=== Recent Audit ==="
ausearch -m USER_AUTH,ADD_USER,DEL_USER -ts recent 2>/dev/null | tail -10
echo
echo "=== Splunk ==="
systemctl status splunk --no-pager 2>/dev/null || /opt/splunk/bin/splunk status 2>/dev/null || echo "Unknown"
EOF
  chmod +x /usr/local/bin/ccdc-status

  sendLog "Status script installed"
}

### -------------------- Main --------------------
main() {
  say "Starting at $(date)"

  install_packages
  configure_selinux
  harden_sysctl
  configure_auditd
  disable_core_dumps
  disable_protocols
  secure_root
  set_umask
  backup_cron_jobs
  check_malicious_bash
  secure_permissions
  cleanup_services
  setup_aide
  setup_status_script

  say "=== OS Hardening Complete ==="
  sendLog "=== Completed ==="

  echo
  echo -e "\e[32m════════════════════════════════════════════════════════════\e[0m"
  echo -e "\e[32m  OS Hardening Complete - Now run Splunk script   \e[0m"
  echo -e "\e[32m════════════════════════════════════════════════════════════\e[0m"
  echo
  echo "Backups: $BACKUP_DIR"
  echo "Cron backup: $CCDC_ETC/cron.jail/"
  echo "Logs: ${CCDC_DIR}/logs/"
  echo
  echo "Quick status: ccdc-status"
  echo
}

main
exit 0
