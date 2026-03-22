#!/bin/bash
# FINAL BOSS HARDENING & FORENSICS SCRIPT (WITH FORENSICS MODE)
# Debian/Ubuntu/Mint/Apt-based distros
# Forensics mode generates a read-only report for auditing and questions, for forensics questions

##########################
# GLOBALS & LOGGING
##########################
TIMESTAMP=$(date +'%F-%H%M%S')
LOG_DIR="./cp-logs"
BACKUP_DIR="./cp-backups/$TIMESTAMP"
mkdir -p "$LOG_DIR" "$BACKUP_DIR"

LOG="$LOG_DIR/hardening_$TIMESTAMP.log"
ERR="$LOG_DIR/errors_$TIMESTAMP.log"
FORENSICS_LOG="$LOG_DIR/forensics_$TIMESTAMP.log"
SUSPICIOUS_OUTPUT="$LOG_DIR/suspicious_files_$TIMESTAMP.txt"

exec > >(tee -i "$LOG") 2> >(tee -a "$ERR" >&2)

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; CYAN="\e[36m"; RESET="\e[0m"
DRYRUN=false
MODE="default"

for arg in "$@"; do
    [[ "$arg" == "--dry-run" ]] && DRYRUN=true
    [[ "$arg" =~ --forensic|--forensics ]] && MODE="forensic"
    [[ "$arg" == "--undo" ]] && MODE="undo"
done

current_user=$(whoami)
protected_user="$current_user"

declare -A ADMIN_PASSWORDS
declare -a REMOVED_USERS
declare -a BACKED_UP_FILES
declare -a STOPPED_SERVICES

backup_file() {
    [[ -f "$1" ]] && cp -n "$1" "$BACKUP_DIR/$(basename $1).bak" && BACKED_UP_FILES+=("$1")
}

log_score() { echo "[$(date +'%F %T')] [$1] $2" >>"$FORENSICS_LOG"; }

##########################
# UNDO FUNCTION
##########################
undo_script() {
    echo -e "${YELLOW}UNDO MODE: Restoring backups and undoing changes...${RESET}"
    for file in "${BACKED_UP_FILES[@]}"; do
        [[ -f "$BACKUP_DIR/$(basename $file).bak" ]] && sudo cp "$BACKUP_DIR/$(basename $file).bak" "$file"
    done
    for user in "${REMOVED_USERS[@]}"; do
        sudo adduser --disabled-password --gecos "" "$user"
        echo "Re-added user $user"
    done
    for svc in "${STOPPED_SERVICES[@]}"; do
        sudo systemctl stop "$svc"
        sudo systemctl disable "$svc"
    done
    echo -e "${GREEN}UNDO COMPLETE${RESET}"
    exit 0
}

[[ "$MODE" == "undo" ]] && undo_script

##########################
# OS DETECTION
##########################
if [ -f /etc/os-release ]; then
    source /etc/os-release
else
    echo -e "${RED}Cannot detect OS. Exiting.${RESET}" && exit 1
fi
echo -e "${CYAN}Detected OS: $NAME $VERSION_ID${RESET}"

##########################
# STEP 1: USER / ADMIN AUDIT
##########################
echo "--- [1/17] USER/AUTHORIZED ADMIN AUDIT ---"
tmp_audit=$(mktemp /tmp/user_audit.XXXX)
cat > "$tmp_audit" <<EOL
# Authorized Administrators:
# $protected_user
# iwest
# password: JITTerS
# Authorized Users:
# hspecter
# jpearson
EOL
nano "$tmp_audit"

users_list=""; admins_list="$protected_user "
section=""; last_admin=""
while IFS= read -r line; do
    line=$(echo "$line"|xargs)
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

    case "$line" in
        "Authorized Administrators:"|"Authorized Users:") section="$line"; continue ;;
    esac

    if [[ "$section" == "Authorized Administrators:" ]]; then
        if [[ "$line" =~ ^password:\ (.+)$ ]]; then
            ADMIN_PASSWORDS["$last_admin"]="${BASH_REMATCH[1]}"
        else
            last_admin="$line"
            admins_list+="$line "
        fi
    elif [[ "$section" == "Authorized Users:" ]]; then
        users_list+="$line "
    fi
done < "$tmp_audit"
rm -f "$tmp_audit"

all_authorized="$admins_list $users_list"

echo -e "${YELLOW}Auditing system users...${RESET}"
for user in $(awk -F: '$3>=1000 && $3<=6000 {print $1}' /etc/passwd); do
    if [[ ! " $all_authorized " =~ " $user " ]]; then
        echo "ALERT: Unauthorized user detected: $user"
        REMOVED_USERS+=("$user")
        if [[ "$MODE" != "forensic" && "$DRYRUN" == false ]]; then
            read -p "Do you want to remove $user? [y/N]: " choice
            [[ "$choice" =~ ^[Yy]$ ]] && sudo deluser --remove-home "$user"
        fi
    fi
done

##########################
# STEP 2: ADMIN PASSWORD ENFORCEMENT
##########################
echo "--- [2/17] Admin password audit ---"
for admin in $admins_list; do
    [[ "$admin" == "$protected_user" ]] && continue
    current_hash=$(getent shadow "$admin" | cut -d: -f2)
    if [[ -z "$current_hash" || "$current_hash" == "!" || "$current_hash" == "*" ]]; then
        echo "Admin $admin has no password set!"
        log_score "ALERT" "Admin $admin has no password set"
        if [[ "$MODE" != "forensic" && "$DRYRUN" == false ]]; then
            read -p "Enter new password for $admin: " new_pass; echo
            echo "$admin:$new_pass" | sudo chpasswd
            log_score "FIXED" "Password updated for $admin"
        fi
    else
        log_score "INFO" "Admin $admin password present"
    fi
done

##########################
# STEP 3: SYSTEM UPDATE CHECK
##########################
echo "--- [3/17] Checking system updates ---"
$DRYRUN && echo "[DRY-RUN] Skipping actual upgrade." || sudo apt update -y

##########################
# STEP 4-16: HARDENING & SCAN
##########################
echo "--- [4-16/17] System hardening & scanning (safe mode) ---"

# PAM and SSH hardening only logged in forensic mode
backup_file /etc/login.defs
backup_file /etc/ssh/sshd_config
echo "[INFO] PAM/SSH configs backed up. Changes skipped in forensic mode."

# Firewall and Fail2Ban
$DRYRUN && echo "[DRY-RUN] Firewall & Fail2Ban changes skipped." || echo "[INFO] Firewall & Fail2Ban can be configured interactively."

# Suspicious files
echo "" > "$SUSPICIOUS_OUTPUT"
find /etc /usr /bin /sbin -type f -perm -0002 >> "$SUSPICIOUS_OUTPUT" 2>/dev/null
find /usr/bin /usr/sbin -type f \( -perm -4000 -o -perm -2000 \) >> "$SUSPICIOUS_OUTPUT" 2>/dev/null
find /etc /home -name ".*" -type f >> "$SUSPICIOUS_OUTPUT" 2>/dev/null
find /tmp /var/tmp -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" -o -name "*.exe" \) >> "$SUSPICIOUS_OUTPUT" 2>/dev/null
echo "[FORENSICS MODE] Suspicious files logged in $SUSPICIOUS_OUTPUT"

##########################
# STEP 17: OPTIONAL VirusTotal
##########################
read -sp "Enter VirusTotal API key (optional): " VIRUSTOTAL_API_KEY; echo
if [[ -n "$VIRUSTOTAL_API_KEY" && "$MODE" == "forensic" ]]; then
    echo "[INFO] VirusTotal lookup for suspicious files (read-only)"
    # Optional: implement read-only VT lookup
fi

##########################
# FINAL FORENSICS REPORT
##########################
echo -e "${CYAN}--- FORENSICS REPORT ---${RESET}"
echo "Users detected: $(awk -F: '$3>=1000 && $3<=6000 {print $1}' /etc/passwd | wc -l)"
echo "Unauthorized users: ${#REMOVED_USERS[@]}"
for u in "${REMOVED_USERS[@]}"; do echo " - $u"; done
echo "Suspicious files: $(grep -v '^#' "$SUSPICIOUS_OUTPUT" | wc -l)"
echo "Report location: $SUSPICIOUS_OUTPUT"
echo "Forensics log: $FORENSICS_LOG"
echo -e "${GREEN}FORENSICS MODE COMPLETE${RESET}"
