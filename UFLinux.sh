#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Trap errors for better debugging
trap 'echo "[ERROR] Failed at line $LINENO. Check $LOG for details."; exit 1' ERR

# Re-run as root if needed
if [[ "${EUID}" -ne 0 ]]; then
  exec sudo -E "$0" "$@"
fi

###################### SETUP ######################
SPLUNK_HOME="/opt/splunkforwarder"
SPLUNK_USER="splunkfwd"
SPLUNK_GROUP="splunkfwd"
LOCAL_CONF="$SPLUNK_HOME/etc/system/local"
UF_BIN="$SPLUNK_HOME/bin/splunk"
LOG="/var/log/ccdc-splunk-install.log"
SUCCESSFUL_MONITORS=()

# GitHub repository for pre-staged packages (set this to your team's repo)
# Example: GITHUB_REPO="https://github.com/Aguil289/SplunkCCDC"
GITHUB_REPO="${GITHUB_REPO:-}"

# Fast deploy mode (skip prompts, use defaults)
FAST_DEPLOY=false
INDEXER_IP=""

###################### LOGGING & UTILITIES ######################
setup_logging() {
  mkdir -p "$(dirname "$LOG")"
  exec 1> >(tee -a "$LOG")
  exec 2>&1
  echo "=== Splunk Installation Started: $(date) ==="
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[ERROR] Missing dependency: $1"; return 1; }
}

have_cmd() { 
  command -v "$1" >/dev/null 2>&1
}

install_dependencies() {
  echo "[INFO] Installing dependencies..."
  
  # Only install what we absolutely need: wget, curl, acl
  if have_cmd apt-get; then
    apt-get update -qq 2>&1 | grep -v "Reading" || true
    apt-get install -qq -y wget curl acl 2>&1 | grep -v "already" || true
  elif have_cmd dnf; then
    dnf install -qq -y wget curl acl
  elif have_cmd yum; then
    yum install -qq -y wget curl acl
  fi
  
  # Verify critical tools
  need_cmd wget || return 1
  need_cmd curl || return 1
  need_cmd setfacl || return 1
  
  echo "[OK] Dependencies installed"
}

download_file() {
  local url=$1
  local output=$2
  
  echo "[DOWNLOAD] Fetching from $url..."
  
  # If GitHub repo is set, try that first (faster, whitelisted by web proxy)
  if [[ -n "$GITHUB_REPO" ]]; then
    local filename=$(basename "$url")
    local github_url="${GITHUB_REPO}/splunk/${filename}"
    echo "[INFO] Trying GitHub repository first: $github_url"
    
    if wget -q --show-progress -O "$output" "$github_url" 2>&1; then
      echo "[OK] Downloaded from GitHub repository"
      return 0
    else
      echo "[WARN] GitHub download failed, falling back to Splunk servers..."
    fi
  fi
  
  # Fail fast - no interactive prompts
  if wget -q --show-progress -O "$output" "$url" 2>&1; then
    return 0
  else
    echo "[WARN] wget failed, trying curl..."
    if curl -fSL -o "$output" "$url" 2>&1; then
      return 0
    else
      echo "[ERROR] Download failed for $url"
      echo "[ERROR] Cannot proceed without package. Exiting."
      exit 1
    fi
  fi
}

###################### USER & PERMISSIONS ######################
ensure_splunk_user() {
  if ! id "$SPLUNK_USER" >/dev/null 2>&1; then
    echo "[INFO] Creating $SPLUNK_USER user (no login shell)"
    # Safe defaults: no login shell, real home not inside SPLUNK_HOME
    useradd -r -m -d "/home/${SPLUNK_USER}" -s /sbin/nologin "$SPLUNK_USER" 2>/dev/null || \
    useradd -r -m -d "/home/${SPLUNK_USER}" -s /usr/sbin/nologin "$SPLUNK_USER" 2>/dev/null || \
    useradd -r -m -d "/home/${SPLUNK_USER}" "$SPLUNK_USER"
  fi
  
  # Ensure group exists and user is a member
  if ! getent group "$SPLUNK_GROUP" >/dev/null 2>&1; then
    groupadd "$SPLUNK_GROUP" 2>/dev/null || true
  fi
  usermod -aG "$SPLUNK_GROUP" "$SPLUNK_USER" 2>/dev/null || true
  
  # Only target specific directories we'll actually monitor
  echo "[INFO] Setting ACL permissions for $SPLUNK_USER on specific log directories"
  
  # Base /var/log access (read + execute to traverse)
  setfacl -m u:$SPLUNK_USER:rx /var/log 2>/dev/null || true
  
  # Common log directories (only if they exist)
  for dir in /var/log/audit /var/log/nginx /var/log/httpd /var/log/apache2 \
             /var/log/mysql /var/log/mariadb /var/log/apt; do
    if [[ -d "$dir" ]]; then
      setfacl -Rm u:$SPLUNK_USER:rx "$dir" 2>/dev/null || true
      setfacl -dm u:$SPLUNK_USER:rx "$dir" 2>/dev/null || true
    fi
  done
  
  echo "[OK] ACL permissions set"
}

###################### CREDENTIAL MANAGEMENT ######################
prompt_creds() {
  # Fast deploy mode: use defaults
  if [[ "$FAST_DEPLOY" == true ]]; then
    ADMIN_USER="admin"
    ADMIN_PASS="ChangeMeCCDC2026!"
    echo "[FAST] Using default credentials (admin/ChangeMeCCDC2026!)"
    return 0
  fi
  
  read -rp "Enter Splunk admin username [admin]: " ADMIN_USER
  ADMIN_USER=${ADMIN_USER:-admin}

  while true; do
    read -rsp "Enter password for $ADMIN_USER (>=10 chars): " ADMIN_PASS; echo
    read -rsp "Confirm password: " ADMIN_PASS_CONFIRM; echo

    [[ "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ]] || { echo "Passwords do not match."; continue; }
    [[ ${#ADMIN_PASS} -ge 10 ]] || { echo "Password too short."; continue; }
    break
  done
}

write_user_seed() {
  mkdir -p "$LOCAL_CONF"
  umask 077
  cat > "$LOCAL_CONF/user-seed.conf" <<EOF
[user_info]
USERNAME = ${ADMIN_USER}
PASSWORD = ${ADMIN_PASS}
EOF

  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$LOCAL_CONF" 2>/dev/null || true
  chmod 600 "$LOCAL_CONF/user-seed.conf"

  # Reduce accidental exposure in environment
  unset ADMIN_PASS ADMIN_PASS_CONFIRM
}

cleanup_user_seed() {
  cleanup_user_seed() {
  if [[ -f "$SPLUNK_HOME/etc/passwd" ]] && grep -q "^${ADMIN_USER}:" "$SPLUNK_HOME/etc/passwd"; then
    rm -f "$LOCAL_CONF/user-seed.conf"
  fi
}


###################### INSTALLATION ######################
ensure_uf_installed() {
  [[ -x "$UF_BIN" ]] || { echo "[ERROR] Splunk UF not found at $SPLUNK_HOME. Install first."; return 1; }
}

install_uf_deb() {
  need_cmd dpkg || return 1

  local pkg="splunkforwarder-10.2.0-d749cb17ea65-linux-amd64.deb"
  echo "[INFO] Downloading UF (.deb)..."
  download_file "https://download.splunk.com/products/universalforwarder/releases/10.2.0/linux/${pkg}" "$pkg"
  echo "[INFO] Installing UF (.deb)..."
  dpkg -i "$pkg"
}

install_uf_rpm() {
  local pkgmgr=""
  if have_cmd dnf; then pkgmgr="dnf"
  elif have_cmd yum; then pkgmgr="yum"
  else echo "[ERROR] Neither dnf nor yum found."; return 1
  fi

  local pkg="splunkforwarder-10.2.0-d749cb17ea65.x86_64.rpm"
  echo "[INFO] Downloading UF (.rpm)..."
  download_file "https://download.splunk.com/products/universalforwarder/releases/10.2.0/linux/${pkg}" "$pkg"
  echo "[INFO] Installing UF (.rpm) with $pkgmgr..."
  "$pkgmgr" install -y "$pkg"
}

install_uf_tgz() {
  need_cmd tar || return 1

  local pkg="splunkforwarder-10.2.0-d749cb17ea65-linux-amd64.tgz"
  echo "[INFO] Downloading UF (.tgz)..."
  download_file "https://download.splunk.com/products/universalforwarder/releases/10.2.0/linux/${pkg}" "$pkg"
  echo "[INFO] Extracting UF to /opt..."
  tar -xzf "$pkg" -C /opt
}

fix_ownership() {
  # Ensure Splunk tree is owned by splunkfwd after install
  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME" 2>/dev/null || true
  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$LOCAL_CONF" 2>/dev/null || true
}

start_uf_first_time() {
  ensure_uf_installed
  echo "[INFO] Starting Splunk UF (accept license)..."
  sudo -u "$SPLUNK_USER" "$UF_BIN" start --accept-license --answer-yes --no-prompt
  cleanup_user_seed
}

restart_uf() {
  ensure_uf_installed
  
  # Warn about service interruption during active scoring
  if [[ "$FAST_DEPLOY" != true ]]; then
    echo ""
    echo "[WARN] ============================================"
    echo "[WARN] Restarting Splunk will briefly interrupt"
    echo "[WARN] log collection (~30 seconds)"
    echo "[WARN] ============================================"
    echo ""
    read -rp "Continue with restart? (y/N): " restart_choice
    [[ "$restart_choice" =~ ^[Yy]$ ]] || { echo "[INFO] Restart cancelled"; return 1; }
  fi
  
  echo "[INFO] Restarting Splunk UF..."
  sudo -u "$SPLUNK_USER" "$UF_BIN" restart --no-prompt 2>/dev/null || "$UF_BIN" restart --no-prompt
}

enable_boot_start() {
  ensure_uf_installed
  echo "[INFO] Enabling boot-start..."
  if have_cmd systemctl; then
    "$UF_BIN" enable boot-start -systemd-managed 1 -user "$SPLUNK_USER" >/dev/null 2>&1 || \
    "$UF_BIN" enable boot-start -user "$SPLUNK_USER"
  else
    "$UF_BIN" enable boot-start -user "$SPLUNK_USER"
  fi
}

###################### CONFIGURATION ######################
configure_forwarding() {
  ensure_uf_installed
  mkdir -p "$LOCAL_CONF"
  umask 077
  cat > "$LOCAL_CONF/server.conf" <<EOF
[general]
serverName = $(hostname -s)-splunkfwd
EOF
chown "$SPLUNK_USER:$SPLUNK_USER" "$LOCAL_CONF/server.conf" || true
chmod 600 "$LOCAL_CONF/server.conf"


  # Fast deploy mode: use provided indexer IP
  if [[ "$FAST_DEPLOY" == true ]]; then
    INDEXER="$INDEXER_IP"
    echo "[FAST] Using indexer: $INDEXER"
  else
    read -rp "Enter Indexer IP/hostname: " INDEXER
    [[ -n "$INDEXER" ]] || { echo "[ERROR] Indexer cannot be empty."; return 1; }

    # Test connectivity before configuring
    echo "[INFO] Testing connectivity to indexer..."
    if have_cmd nc; then
      if ! nc -zv "$INDEXER" 9997 2>&1 | grep -q "succeeded\|Connected"; then
        echo "[WARN] Cannot connect to $INDEXER:9997. Proceeding anyway..."
        read -rp "Continue? (y/N): " continue_choice
        [[ "$continue_choice" =~ ^[Yy]$ ]] || return 1
      else
        echo "[OK] Connectivity verified"
      fi
    elif have_cmd timeout; then
      if ! timeout 2 bash -c "cat < /dev/null > /dev/tcp/$INDEXER/9997" 2>/dev/null; then
        echo "[WARN] Cannot connect to $INDEXER:9997. Proceeding anyway..."
        read -rp "Continue? (y/N): " continue_choice
        [[ "$continue_choice" =~ ^[Yy]$ ]] || return 1
      else
        echo "[OK] Connectivity verified"
      fi
    else
      echo "[WARN] Cannot test connectivity (nc/timeout not found). Proceeding..."
    fi
  fi


cat > "$LOCAL_CONF/outputs.conf" <<EOF
[tcpout]
defaultGroup = primary

[tcpout:primary]
server = ${INDEXER}:9997
EOF


  chown "$SPLUNK_USER:$SPLUNK_USER" "$LOCAL_CONF/outputs.conf" 2>/dev/null || true
  chmod 600 "$LOCAL_CONF/outputs.conf"
  echo "[OK] Wrote: $LOCAL_CONF/outputs.conf"
}

###################### LOG MONITORING ######################
add_log_monitors() {
  ensure_uf_installed

  local preset
  # Fast deploy mode: always use option 3 (auto-detect all → main)
  if [[ "$FAST_DEPLOY" == true ]]; then
    preset=3
    echo "[FAST] Using auto-detect mode (all logs → main index)"
  else
    echo "Choose log preset:"
    echo "1) Minimal (auth + syslog/messages + secure) → main index"
    echo "2) Standard (minimal + audit) → main index"
    echo "3) Auto-detect all logs → uses main index (RECOMMENDED for CCDC)"
    read -rp "Select [1-3]: " preset
  fi

  mkdir -p "$LOCAL_CONF"
  umask 077

  # Helper to add monitors only for files that exist
  add_to_inputs() {
    local path="$1"
    local index="$2"
    if [[ -f "$path" ]]; then
      echo "[FOUND] $path → index=$index"
      cat >> "$LOCAL_CONF/inputs.conf" <<EOF
[monitor://${path}]
index = ${index}

EOF
      SUCCESSFUL_MONITORS+=("$path")
      fi
  }

  # Start fresh
  : > "$LOCAL_CONF/inputs.conf"

  case "$preset" in
    1)
      # Minimal: system logs only → main index (always exists)
      add_to_inputs "/var/log/syslog" "main"
      add_to_inputs "/var/log/auth.log" "main"
      add_to_inputs "/var/log/messages" "main"
      add_to_inputs "/var/log/secure" "main"
      ;;
    2)
      # Standard: add audit → main index
      add_to_inputs "/var/log/syslog" "main"
      add_to_inputs "/var/log/auth.log" "main"
      add_to_inputs "/var/log/messages" "main"
      add_to_inputs "/var/log/secure" "main"
      add_to_inputs "/var/log/audit/audit.log" "main"
      ;;
    3)
      # Auto-detect: everything → main index (safest for CCDC)
      echo "[INFO] Auto-detecting log sources (all → main index)..."
      
      # System logs
      add_to_inputs "/var/log/syslog" "main"
      add_to_inputs "/var/log/auth.log" "main"
      add_to_inputs "/var/log/messages" "main"
      add_to_inputs "/var/log/secure" "main"
      add_to_inputs "/var/log/audit/audit.log" "main"
      
      # Web servers
      add_to_inputs "/var/log/apache2/access.log" "main"
      add_to_inputs "/var/log/apache2/error.log" "main"
      add_to_inputs "/var/log/httpd/access_log" "main"
      add_to_inputs "/var/log/httpd/error_log" "main"
      add_to_inputs "/var/log/nginx/access.log" "main"
      add_to_inputs "/var/log/nginx/error.log" "main"
      
      # Databases
      add_to_inputs "/var/log/mysql/error.log" "main"
      add_to_inputs "/var/log/mysql/mysql.log" "main"
      add_to_inputs "/var/log/mariadb/mariadb.log" "main"
      
      # Package managers
      add_to_inputs "/var/log/dpkg.log" "main"
      add_to_inputs "/var/log/apt/history.log" "main"
      add_to_inputs "/var/log/dnf.rpm.log" "main"
      add_to_inputs "/var/log/yum.log" "main"
      
      # Firewall - only files, not directories
      add_to_inputs "/var/log/ufw.log" "main"
      # Note: firewalld typically logs to journald or /var/log/messages
      # which we already monitor above
      ;;
    *)
      echo "[ERROR] Invalid preset."
      return 1
      ;;
  esac

  if [[ ! -s "$LOCAL_CONF/inputs.conf" ]]; then
    echo "[WARN] No matching log files found to monitor on this host."
    echo "Check /var/log paths and re-run."
    return 1
  fi

  chown "$SPLUNK_USER:$SPLUNK_USER" "$LOCAL_CONF/inputs.conf" 2>/dev/null || true
  chmod 600 "$LOCAL_CONF/inputs.conf"
  echo "[OK] Wrote: $LOCAL_CONF/inputs.conf"
}

###################### AUDITD ######################
install_auditd() {
  echo "[INFO] Installing auditd for enhanced logging..."
  
  if have_cmd apt-get; then
    apt-get install -qq -y auditd
  elif have_cmd dnf; then
    dnf install -qq -y audit
  elif have_cmd yum; then
    yum install -qq -y audit
  fi
  
  if ! have_cmd auditctl; then
    echo "[WARN] auditd installation failed"
    return 1
  fi
  
  # Enable service
  if have_cmd systemctl; then
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
  fi
  
  # Add basic CCDC rules
  local rule_file="/etc/audit/rules.d/ccdc.rules"
  cat > "$rule_file" <<'EOF'
# Monitor authentication
-w /etc/passwd -p wa -k CCDC_passwd_changes
-w /etc/shadow -p wa -k CCDC_shadow_changes
-w /etc/sudoers -p wa -k CCDC_sudoers_changes
-w /etc/sudoers.d/ -p wa -k CCDC_sudoers_changes

# Monitor SSH
-w /etc/ssh/sshd_config -p wa -k CCDC_sshd_config
-w /root/.ssh/ -p wa -k CCDC_root_ssh

# Monitor cron
-w /etc/crontab -p wa -k CCDC_cron_changes
-w /etc/cron.d/ -p wa -k CCDC_cron_changes

# Monitor shells and scripts
-w /bin/bash -p x -k CCDC_shell_exec
-w /bin/sh -p x -k CCDC_shell_exec
EOF
  
  # Add user home directory rules (be aware this can bloat on shared systems)
  for dir in /home/*; do
    if [[ -d "$dir/.ssh" ]]; then
      echo "-w ${dir}/.ssh/ -p wa -k CCDC_user_ssh" >> "$rule_file"
    fi
    if [[ -f "$dir/.bashrc" ]]; then
      echo "-w ${dir}/.bashrc -p wa -k CCDC_bashrc_changes" >> "$rule_file"
    fi
  done
  
  # Load rules - augenrules not available on all distros
  if have_cmd augenrules; then
    augenrules --load 2>/dev/null || auditctl -R "$rule_file" 2>/dev/null || true
  else
    auditctl -R "$rule_file" 2>/dev/null || true
  fi
  
  echo "[OK] auditd configured with CCDC rules"
  
  # Ensure splunkfwd can read audit logs
  if [[ -d /var/log/audit ]]; then
    setfacl -Rm u:$SPLUNK_USER:rx /var/log/audit/ 2>/dev/null || true
    setfacl -dm u:$SPLUNK_USER:rx /var/log/audit/ 2>/dev/null || true
  fi
}

###################### STATUS & VERIFICATION ######################
verify_forwarding() {
  ensure_uf_installed
  echo ""
  echo "=== Forward-server status ==="
  "$UF_BIN" list forward-server 2>/dev/null || true
  echo ""
  echo "=== Monitors configured ==="
  "$UF_BIN" list monitor 2>/dev/null || true
}

print_summary() {
  echo ""
  echo "================================"
  echo "    INSTALLATION COMPLETE"
  echo "================================"
  echo ""
  echo "Installation log: $LOG"
  echo ""
  if [[ ${#SUCCESSFUL_MONITORS[@]} -gt 0 ]]; then
    echo "Successfully monitored logs:"
    for log in "${SUCCESSFUL_MONITORS[@]}"; do
      echo "  ✓ $log"
    done
    echo ""
  fi
  echo "Next steps:"
  echo "  1. Verify connectivity to indexer"
  echo "  2. Check for data in Splunk web interface"
  echo "  3. Search: index=main OR index=* to verify data flow"
  echo ""
}

###################### WORKFLOW FUNCTIONS ######################
install_flow() {
  echo "=============================="
  echo " Splunk UF Install"
  echo "=============================="
  echo "1) .deb (Debian/Ubuntu/Devuan)"
  echo "2) .rpm (RHEL/Fedora/Oracle)"
  echo "3) .tgz (generic)"
  echo "4) Back"
  read -rp "Select an option [1-4]: " installchoice

  ensure_splunk_user
  prompt_creds

  case "$installchoice" in
    1) install_uf_deb ;;
    2) install_uf_rpm ;;
    3) install_uf_tgz ;;
    4) return 0 ;;
    *) echo "[ERROR] Invalid option."; return 1 ;;
  esac

  write_user_seed
  fix_ownership
  start_uf_first_time
  enable_boot_start
  verify_forwarding
}

configure_flow() {
  configure_forwarding
  restart_uf
  enable_boot_start
  verify_forwarding
}

monitors_flow() {
  add_log_monitors
  restart_uf
  verify_forwarding
}

auditd_flow() {
  install_auditd
  if [[ -f "/var/log/audit/audit.log" ]]; then
    echo "[INFO] Adding auditd monitor to Splunk inputs.conf..."
    mkdir -p "$LOCAL_CONF"
    if ! grep -q "/var/log/audit/audit.log" "$LOCAL_CONF/inputs.conf" 2>/dev/null; then
      cat >> "$LOCAL_CONF/inputs.conf" <<'EOF'

[monitor:///var/log/audit/audit.log]
index = main
EOF
      chown "$SPLUNK_USER:$SPLUNK_USER" "$LOCAL_CONF/inputs.conf" 2>/dev/null || true
      echo "[OK] Added audit.log monitor"
      SUCCESSFUL_MONITORS+=("/var/log/audit/audit.log")
      restart_uf
    else
      echo "[INFO] audit.log already monitored"
    fi
  fi
}

###################### MAIN MENU ######################
# Initialize logging first
setup_logging

# Parse command line arguments for fast deploy mode
while [[ $# -gt 0 ]]; do
  case $1 in
    --fast-deploy)
      FAST_DEPLOY=true
      INDEXER_IP="$2"
      shift 2
      ;;
    --github-repo)
      GITHUB_REPO="$2"
      shift 2
      ;;
    --help)
      echo "Splunk Universal Forwarder Installer for CCDC"
      echo ""
      echo "Usage:"
      echo "  $0                                    # Interactive mode"
      echo "  $0 --fast-deploy <indexer_ip>        # Fast competition mode"
      echo "  $0 --github-repo <repo_url>          # Use GitHub repo for packages"
      echo ""
      echo "Fast Deploy Mode:"
      echo "  Skips all prompts and uses defaults:"
      echo "  - Auto-detects package type"
      echo "  - Uses admin/ChangeMeCCDC2026! credentials"
      echo "  - Configures auto-detect monitors (option 3)"
      echo "  - All logs sent to 'main' index"
      echo "  - Installs auditd automatically"
      echo ""
      echo "GitHub Repository:"
      echo "  Pre-stage Splunk packages in your team GitHub repo"
      echo "  Example: --github-repo https://raw.githubusercontent.com/team/ccdc/main"
      echo "  Script will look for: \$REPO/splunk/splunkforwarder-*.{deb,rpm,tgz}"
      echo ""
      echo "Examples:"
      echo "  $0 --fast-deploy 10.0.1.100"
      echo "  $0 --fast-deploy 10.0.1.100 --github-repo https://raw.githubusercontent.com/team/ccdc/main"
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Fast deploy mode - full automation
if [[ "$FAST_DEPLOY" == true ]]; then
  if [[ -z "$INDEXER_IP" ]]; then
    echo "[ERROR] Fast deploy requires indexer IP: $0 --fast-deploy <indexer_ip>"
    exit 1
  fi
  
  echo "========================================"
  echo " FAST DEPLOY MODE - Competition Ready"
  echo "========================================"
  echo "Indexer: $INDEXER_IP"
  if [[ -n "$GITHUB_REPO" ]]; then
    echo "GitHub: $GITHUB_REPO"
  fi
  echo "This will:"
  echo "  1. Install dependencies"
  echo "  2. Install Splunk UF (auto-detect package)"
  echo "  3. Configure forwarding to $INDEXER_IP"
  echo "  4. Auto-detect and monitor all logs"
  echo "  5. Install and configure auditd"
  echo ""
  sleep 2
  
  # Run full installation pipeline
  install_dependencies
  ensure_splunk_user
  
  # Auto-detect package type
  if have_cmd dpkg; then
    echo "[FAST] Detected Debian-based system"
    install_uf_deb
  elif have_cmd rpm; then
    echo "[FAST] Detected RPM-based system"
    install_uf_rpm
  else
    echo "[FAST] Using generic .tgz package"
    install_uf_tgz
  fi
  
  prompt_creds  # Uses defaults in fast mode
  write_user_seed
  fix_ownership
  start_uf_first_time
  configure_forwarding  # Uses INDEXER_IP in fast mode
  add_log_monitors  # Uses option 3 in fast mode
  enable_boot_start
  
  # Install auditd
  install_auditd
  if [[ -f "/var/log/audit/audit.log" ]]; then
    if ! grep -q "/var/log/audit/audit.log" "$LOCAL_CONF/inputs.conf" 2>/dev/null; then
      cat >> "$LOCAL_CONF/inputs.conf" <<'EOF'

[monitor:///var/log/audit/audit.log]
index = main
EOF
      chown "$SPLUNK_USER:$SPLUNK_USER" "$LOCAL_CONF/inputs.conf" 2>/dev/null || true
      SUCCESSFUL_MONITORS+=("/var/log/audit/audit.log")
    fi
  fi
  
  # Final restart
  FAST_DEPLOY=false  # Allow restart warning
  restart_uf
  
  # Show summary
  verify_forwarding
  print_summary
  
  echo ""
  echo "=== FAST DEPLOY COMPLETE ==="
  echo "Time to complete: ~2-3 minutes"
  echo "Repeat on remaining servers with:"
  echo "  $0 --fast-deploy $INDEXER_IP"
  exit 0
fi

# Interactive menu
while true; do
  echo ""
  echo "=============================="
  echo " Splunk Forwarder Installer"
  echo "=============================="
  echo "1) Install Splunk UF"
  echo "2) Configure forwarding"
  echo "3) Add log monitors"
  echo "4) Install auditd (recommended)"
  echo "5) Verify status"
  echo "6) Exit"
  echo
  read -rp "Select an option [1-6]: " choice

  case "$choice" in
    1) 
      install_dependencies
      install_flow 
      ;;
    2) configure_flow ;;
    3) monitors_flow ;;
    4) auditd_flow ;;
    5) 
      verify_forwarding
      print_summary
      ;;
    6) 
      echo "[INFO] Exiting."
      print_summary
      break 
      ;;
    *) echo "[ERROR] Invalid option." ;;
  esac
done
