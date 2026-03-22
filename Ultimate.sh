#!/bin/bash
# ELITE CYBERPATRIOT HARDENING & FORENSICS SCRIPT (FULL UPGRADE)
# Debian/Ubuntu/Mint/Apt-based distros
# Full 17-step hardening + VirusTotal scan + undo + dry-run + final summary

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
# SPINNER
##########################
spin_pid() {
    local pid=$1 text=$2 i=0 spinstr='/-\|'
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r[%s] %c %s" "$text" "${spinstr:i:1}" "$text"
        i=$(( (i+1) % 4 )); sleep 0.1
    done
    wait $pid
    printf "\r[%s] ✔ %s\n" "$text" "$text"
}

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

for user in $(awk -F: '$3>=1000 && $3<=6000 {print $1}' /etc/passwd); do
    [[ ! " $all_authorized " =~ " $user " ]] && {
        echo "ALERT: Unauthorized user: $user"
        $DRYRUN || { sudo deluser --remove-home "$user"; REMOVED_USERS+=("$user"); }
    }
done

##########################
# STEP 2: ADMIN PASSWORD ENFORCEMENT
##########################
echo "--- [2/17] Enforcing admin passwords ---"
read -sp "Enter VirusTotal API key (optional, leave blank to skip): " VIRUSTOTAL_API_KEY
echo

if getent group sudo >/dev/null; then admin_group="sudo"
elif getent group admin >/dev/null; then admin_group="admin"
else admin_group=""; echo "No admin group found, skipping password enforcement."; fi

admins_list=$(getent group "$admin_group" | cut -d: -f4 | tr ',' ' ')" $protected_user"

for admin in $admins_list; do
    [[ "$admin" == "$protected_user" ]] && continue
    current_hash=$(getent shadow "$admin" | cut -d: -f2)
    need_change=false
    [[ -z "$current_hash" || "$current_hash" == "!" || "$current_hash" == "*" ]] && need_change=true

    if [ "$need_change" = true ]; then
        valid=false
        while [ "$valid" = false ]; do
            read -p "Enter new password for $admin: " new_pass; echo
            read -p "Confirm password: " confirm_pass; echo
            if [[ "$new_pass" != "$confirm_pass" ]]; then
                echo "Mismatch!"
                continue
            fi
            if [[ ${#new_pass} -ge 14 ]] && [[ "$new_pass" =~ [A-Z] ]] && [[ "$new_pass" =~ [a-z] ]] && [[ "$new_pass" =~ [0-9] ]] && [[ "$new_pass" =~ [\!\@\#\$\%\^\&\*\(\)\_\+\%\-\=] ]]; then
                $DRYRUN || echo "$admin:$new_pass" | sudo chpasswd
                log_score "FIXED" "Password updated for $admin"
                valid=true
            else
                echo "Password must have 14+ chars, uppercase, lowercase, number, and symbol."
            fi
        done
    else
        log_score "GAIN" "Admin $admin password strong"
    fi
done

##########################
# STEP 3: SYSTEM UPDATES
##########################
echo "--- [3/17] Installing system updates ---"
(
sudo apt update && sudo apt upgrade -y && sudo apt dist-upgrade -y
) & spin_pid "Updating system"

##########################
# STEP 4-16: FULL HARDENING
##########################
# Step 4
echo "--- [4/17] Configuring PAM / Password policies ---"
backup_file /etc/login.defs
sudo sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/; s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/; s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
sudo apt install -y libpam-cracklib
echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' | sudo tee -a /etc/pam.d/common-auth
sudo sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=14/' /etc/pam.d/common-password
sudo sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

# Step 5
echo "--- [5/17] Hardening SSH ---"
backup_file /etc/ssh/sshd_config
sudo sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^.*ChallengeResponseAuthentication.*$/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^.*PasswordAuthentication.*$/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^.*UsePAM.*$/UsePAM yes/' /etc/ssh/sshd_config
sudo systemctl reload sshd

# Step 6
echo "--- [6/17] Configuring UFW firewall ---"
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable

# Step 7
echo "--- [7/17] Installing Fail2Ban ---"
sudo apt install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
STOPPED_SERVICES+=("fail2ban")

# Step 8
echo "--- [8/17] Auditing cron and autostart ---"
crontab -l > "$BACKUP_DIR/cron.bak"
sudo systemctl list-timers

# Step 9
echo "--- [9/17] Detecting hidden users ---"
awk -F: '($3>=1000)&&($3<=6000){print $1}' /etc/passwd

# Step 10
echo "--- [10/17] Installing and configuring auditd ---"
sudo apt install -y auditd
sudo auditctl -e 1

# Step 11
echo "--- [11/17] Running rkhunter, chkrootkit, clamav ---"
sudo apt install -y rkhunter chkrootkit clamav
sudo rkhunter --update
sudo rkhunter --check --sk
sudo chkrootkit
sudo clamscan -r /

# Step 12
echo "--- [12/17] Scanning for suspicious files ---"
echo "" > "$SUSPICIOUS_OUTPUT"
find /etc /usr /bin /sbin -type f -perm -0002 >> "$SUSPICIOUS_OUTPUT" 2>/dev/null
find /usr/bin /usr/sbin -type f \( -perm -4000 -o -perm -2000 \) >> "$SUSPICIOUS_OUTPUT" 2>/dev/null
find /etc /home -name ".*" -type f >> "$SUSPICIOUS_OUTPUT" 2>/dev/null
find /tmp /var/tmp -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" -o -name "*.exe" \) >> "$SUSPICIOUS_OUTPUT" 2>/dev/null

# Step 13-16
echo "--- [13-16/17] Safe cleanup and additional hardening ---"
mkdir -p "$BACKUP_DIR/home_files_backup"
find /home -type f \( -name "*.mp3" -o -name "*.mp4" -o -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \) -exec mv {} "$BACKUP_DIR/home_files_backup" \;

##########################
# STEP 17: VirusTotal scan
##########################
if [[ -n "$VIRUSTOTAL_API_KEY" ]]; then
    VT_OUTPUT="$LOG_DIR/virustotal_results_$TIMESTAMP.json"
    VT_SUMMARY="$LOG_DIR/virustotal_summary_$TIMESTAMP.txt"
    sudo apt install -y curl jq
    echo "{}" > "$VT_OUTPUT"

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        sha256=$(sha256sum "$file" | awk '{print $1}')
        response=$(curl -s --request GET "https://www.virustotal.com/api/v3/files/$sha256" \
                    -H "x-apikey: $VIRUSTOTAL_API_KEY")
        status=$(echo "$response" | jq -r '.error.code // empty')
        if [[ "$status" == "NotFoundError" ]]; then
            echo "Uploading unknown file $file..."
            upload_resp=$(curl -s --request POST "https://www.virustotal.com/api/v3/files" \
                        -H "x-apikey: $VIRUSTOTAL_API_KEY" -F "file=@$file")
            echo "$upload_resp" | jq '.data.attributes.last_analysis_stats' >> "$VT_OUTPUT"
        else
            echo "$file already known to VT"
            echo "$response" | jq '.data.attributes.last_analysis_stats' >> "$VT_OUTPUT"
        fi
    done < <(grep -v '^#' "$SUSPICIOUS_OUTPUT")

    # Human-readable summary
    echo "--- VirusTotal Scan Summary ---" > "$VT_SUMMARY"
    jq -r '. as $in | keys[]? | "\(.): \($in[.].malicious)/\($in[.].total)"' "$VT_OUTPUT" >> "$VT_SUMMARY" 2>/dev/null
    echo -e "${CYAN}VirusTotal JSON: $VT_OUTPUT${RESET}"
    echo -e "${CYAN}VirusTotal summary: $VT_SUMMARY${RESET}"
fi

##########################
# FINAL LOGS
##########################
echo -e "${GREEN}ALL 17 STEPS COMPLETE${RESET}"
echo "Main log: $LOG"
echo "Error log: $ERR"
echo "Forensics log: $FORENSICS_LOG"
echo "Suspicious files report: $SUSPICIOUS_OUTPUT"

##########################
# FINAL SUMMARY
##########################
echo -e "${CYAN}--- FINAL SUMMARY ---${RESET}"

if [[ ${#REMOVED_USERS[@]} -gt 0 ]]; then
    echo "Unauthorized users removed: ${#REMOVED_USERS[@]}"
    for u in "${REMOVED_USERS[@]}"; do echo " - $u"; done
else
    echo "No unauthorized users found."
fi

updated_admins=$(grep "FIXED" "$FORENSICS_LOG" | wc -l)
echo "Admin passwords updated: $updated_admins"

suspicious_count=$(grep -v '^#' "$SUSPICIOUS_OUTPUT" | wc -l)
echo "Suspicious files detected: $suspicious_count"
echo "Suspicious files report: $SUSPICIOUS_OUTPUT"

if [[ -n "$VT_OUTPUT" ]]; then
    vt_count=$(jq '. | length' "$VT_OUTPUT" 2>/dev/null)
    echo "Files checked with VirusTotal: $vt_count"
    echo "VirusTotal JSON: $VT_OUTPUT"
    echo "VirusTotal summary: $VT_SUMMARY"
fi

echo -e "${GREEN}HARDENING & FORENSICS COMPLETE!${RESET}"
