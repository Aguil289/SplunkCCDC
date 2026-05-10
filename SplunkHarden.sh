#!/bin/bash
# SplunkHarden
# Hardening script for Splunk on Oracle Linux 9.2
#

set -u

# --- HELPER FUNCTIONS ---
prompt_password() {
    local user_label=$1
    local var_name=$2
    while true; do
        echo -n "Enter new password for $user_label: "
        stty -echo
        read pass1
        stty echo
        echo
        echo -n "Confirm new password for $user_label: "
        stty -echo
        read pass2
        stty echo
        echo
        
        if [ "$pass1" == "$pass2" ] && [ -n "$pass1" ]; then
            eval "$var_name='$pass1'"
            break
        else
            echo "Passwords do not match or are empty. Please try again."
        fi
    done
}

# --- PRE-CHECKS ---
if [ "$(id -u)" != "0" ]; then
   echo "ERROR: Must be run as root."
   exit 1
fi

# --- CONFIGURATION VARIABLES ---
SPLUNK_VERSION="10.2.2"
SPLUNK_BUILD="80b90d638de6"
SPLUNK_HOME="/opt/splunk"
SPLUNK_PKG="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}.x86_64.rpm"
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/${SPLUNK_PKG}"
SPLUNK_USERNAME="admin"
SPLUNK_USER="splunk"
SPLUNK_GROUP="splunk"

BACKUP_DIR="/etc/BacService"
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/splunkHarden.log"

# Create directories
mkdir -p $LOG_DIR
mkdir -p $BACKUP_DIR

# Redirect output to log
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==================================================="
echo "         Starting Splunk Hardening (v2)            "
echo "==================================================="

# --- PASSWORD PROMPTS ---
echo "--- CREDENTIAL SETUP ---"
echo "Changing System Passwords..."

prompt_password "Root" ROOT_PASS
prompt_password "Bbob (backup admin)" BBOB_PASS
prompt_password "Splunk Admin (web UI)" SPLUNK_PASSWORD

# Change root password
echo "root:$ROOT_PASS" | chpasswd
echo "[+] Changed root password"

# FIX: Check if sysadmin exists before prompting
if id "sysadmin" &>/dev/null; then
    prompt_password "sysadmin" SYSADMIN_PASS
    echo "sysadmin:$SYSADMIN_PASS" | chpasswd
    echo "[+] Changed sysadmin password"
else
    echo "[!] sysadmin user does not exist, skipping"
fi

# Create Backup User 'bbob'
if ! id "bbob" &>/dev/null; then
    echo "Creating backup user bbob..."
    useradd bbob
    usermod -aG wheel bbob
fi
echo "bbob:$BBOB_PASS" | chpasswd
echo "[+] Configured bbob with sudo access"

echo "------------------------"

# --- ENSURE SPLUNK USER EXISTS ---
if ! id "$SPLUNK_USER" &>/dev/null; then
    echo "Creating splunk user..."
    useradd -r -m -d /opt/splunk -s /sbin/nologin "$SPLUNK_USER"
fi

echo "Nuking and then reinstalling Splunk..."

# --- BACKUP EXISTING SPLUNK ---
if [ -d "$SPLUNK_HOME" ]; then
    # FIX: Backup licenses - glob OUTSIDE quotes
    echo "Backing up licenses..."
    mkdir -p "$BACKUP_DIR/licenses"
    if [ -d "$SPLUNK_HOME/etc/licenses" ]; then
        # Check if directory has files
        if ls $SPLUNK_HOME/etc/licenses/* &>/dev/null; then
            cp -R $SPLUNK_HOME/etc/licenses/* "$BACKUP_DIR/licenses/" 2>/dev/null || true
            echo "[+] Licenses backed up"
        else
            echo "[!] No license files found"
        fi
    fi

    # Backup base Splunk installation
    echo "Backing up base Splunk installation..."
    mkdir -p "$BACKUP_DIR/splunkORIGINAL"
    cp -R "$SPLUNK_HOME" "$BACKUP_DIR/splunkORIGINAL/" 2>/dev/null || true
    
    # Stop Splunk
    echo "Stopping Splunk..."
    $SPLUNK_HOME/bin/splunk stop 2>/dev/null || true
    pkill -f splunkd 2>/dev/null || true
    sleep 2
    
    # Remove old installation
    rm -rf "$SPLUNK_HOME"
    dnf remove -y splunk 2>/dev/null || true
fi

# --- DOWNLOAD & INSTALL ---
if [ ! -f "$SPLUNK_PKG" ]; then
    echo "Downloading Splunk $SPLUNK_VERSION..."
    wget -q -O "$SPLUNK_PKG" "$SPLUNK_URL"
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to download Splunk"
        exit 1
    fi
fi

echo "Installing Splunk..."
dnf install -y "$SPLUNK_PKG"

# --- SET OWNERSHIP BEFORE FIRST START ---
echo "Setting Splunk ownership..."
chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "$SPLUNK_HOME"

# --- CREATE CONFIG FILES BEFORE FIRST START ---
echo "Creating Splunk configuration..."
mkdir -p $SPLUNK_HOME/etc/system/local

# Create user-seed.conf (admin credentials)
cat > $SPLUNK_HOME/etc/system/local/user-seed.conf <<EOF
[user_info]
USERNAME = $SPLUNK_USERNAME
PASSWORD = $SPLUNK_PASSWORD
EOF

# FIX: Create server.conf BEFORE starting (not sed after)
cat > $SPLUNK_HOME/etc/system/local/server.conf <<EOF
[sslConfig]
enableSplunkdSSL = true
sslVersions = tls1.2
allowSslCompression = false

[general]
serverName = $(hostname)

[httpServer]
mgmtHostPort = 127.0.0.1:8089
EOF

# Create inputs.conf
cat > $SPLUNK_HOME/etc/system/local/inputs.conf <<EOF
[default]
host = $(hostname)

[tcp://514]
sourcetype = syslog
index = main
disabled = 0
EOF

# Set ownership on all config files
chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} $SPLUNK_HOME/etc/system/local
chmod 600 $SPLUNK_HOME/etc/system/local/*.conf

# --- RESTORE LICENSES ---
if [ -d "$BACKUP_DIR/licenses" ]; then
    if ls $BACKUP_DIR/licenses/* &>/dev/null; then
        echo "Restoring licenses..."
        mkdir -p $SPLUNK_HOME/etc/licenses
        cp -r $BACKUP_DIR/licenses/* $SPLUNK_HOME/etc/licenses/ 2>/dev/null || true
        chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} $SPLUNK_HOME/etc/licenses
        echo "[+] Licenses restored"
    fi
fi

# --- FIRST START AS SPLUNK USER ---
echo "Initializing Splunk (as $SPLUNK_USER user)..."

# FIX: Clear LD_LIBRARY_PATH to avoid OpenSSL conflict with systemctl
export LD_LIBRARY_PATH=""

# Start Splunk as the splunk user
su -s /bin/bash $SPLUNK_USER -c "$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt"

if [ $? -ne 0 ]; then
    echo "ERROR: Splunk failed to start"
    exit 1
fi

echo "Waiting for Splunk to initialize..."
sleep 10

# --- ENABLE BOOT START ---
echo "Enabling Splunk boot-start..."
$SPLUNK_HOME/bin/splunk enable boot-start -user $SPLUNK_USER

# --- ENABLE 9997 LISTENER ---
echo "Enabling 9997 listener..."
su -s /bin/bash $SPLUNK_USER -c "$SPLUNK_HOME/bin/splunk enable listen 9997 -auth '$SPLUNK_USERNAME:$SPLUNK_PASSWORD'" || {
    echo "[!] Could not enable 9997 listener automatically"
    echo "[!] Enable manually: splunk enable listen 9997 -auth admin:<password>"
}

# --- OS HARDENING ---
echo ""
echo "==================================================="
echo "              OS Hardening                         "
echo "==================================================="

echo "Setting Legal Banners..."
cat > /etc/issue <<EOF
UNAUTHORIZED ACCESS PROHIBITED. VIOLATORS WILL BE PROSECUTED.
EOF
cp /etc/issue /etc/motd

echo "Clearing Cron jobs..."
echo "" > /etc/crontab
rm -f /var/spool/cron/* 2>/dev/null || true

echo "Removing SSH Server..."
systemctl stop sshd 2>/dev/null || true
systemctl disable sshd 2>/dev/null || true
dnf remove -y openssh-server 2>/dev/null || true

echo "Restricting user creation tools..."
chmod 700 /usr/sbin/useradd 2>/dev/null || true
chmod 700 /usr/sbin/groupadd 2>/dev/null || true

echo "Locking down Cron and AT permissions..."
echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny

echo "root" > /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

# --- FIREWALL ---
echo ""
echo "==================================================="
echo "              Firewall Configuration               "
echo "==================================================="

dnf install -y iptables-services 2>/dev/null || true
systemctl stop firewalld 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true


# --- CLEANUP ---
rm -f "$SPLUNK_PKG" 2>/dev/null || true

# --- VERIFICATION ---
echo ""
echo "==================================================="
echo "              Verification                         "
echo "==================================================="

echo "Splunk Status:"
su -s /bin/bash $SPLUNK_USER -c "$SPLUNK_HOME/bin/splunk status" || echo "[!] Check Splunk manually"

echo ""
echo "Listening Ports:"
ss -tlnp | grep -E "8000|8089|9997|514" || echo "[!] Check ports manually"

echo ""
echo "==================================================="
echo "         Splunk Hardening Complete                 "
echo "==================================================="
echo ""
echo "Splunk Web UI: http://$(hostname -I | awk '{print $1}'):8000"
echo "Login: $SPLUNK_USERNAME / <your password>"
echo ""
echo "Splunk running as: $SPLUNK_USER"
echo "Logs saved to: $LOG_FILE"
echo ""
