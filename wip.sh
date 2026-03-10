#!/bin/bash

# --- LOGGING ---
LOGFILE="./hardening_$(date +%F_%T).log"
ERROR_LOG="./errors_$(date +%F_%T).log"
exec > >(tee -i "$LOGFILE")
exec 2> >(tee -a "$ERROR_LOG" >&2)

# --- TERMINAL WIDTH ---
cols=$(tput cols)

# --- SPINNER FUNCTION ---
spin() {
    local pid=$1
    local step=$2
    local text=$3
    local spinstr='|/-\'
    local delay=0.1
    local i=0

    while kill -0 "$pid" 2>/dev/null; do
        printf "\r[%s] %s %s" "$step" "${spinstr:i:1}" "$text"
        i=$(( (i+1) %4 ))
        sleep $delay
    done
    printf "\r[%s] ✔ %s\n" "$step" "$text"
}

# --- CURRENT USER ---
current_user=$(whoami)
protected_user="$current_user"

# --- [0/15] WARNING ---
echo -e "\e[1;31mFINISH FORENSICS QUESTIONS BEFORE RUNNING THIS. ONLY RUN THIS SCRIPT IF THEY ARE DONE OR YOU GIVE UP.\e[0m"
read -p "If you acknowledge, press Enter..."

# --- [1/15] USER AUDIT WITH NANO INPUT ---
echo "--- [1/15] USER AUDIT WITH NANO INPUT ---"
tmp_audit_file=$(mktemp /tmp/user_audit.XXXX)

cat > "$tmp_audit_file" <<EOL
# Paste user audit here:
# Format example:
# Authorized Administrators:
# LABEX  # current user automatically protected
#     password: (blank/none)
# iwest
#     password: JITTerS
# Authorized Users:
# hspecter
# jpearson
# jquelling
# rzane
# lsnart
EOL

# Open nano normally
nano "$tmp_audit_file"

declare -A admin_passwords
users_list=""
admins_list="$protected_user "  # protect current user automatically
section=""
last_admin=""

while IFS= read -r line; do
    line=$(echo "$line" | xargs)
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

    case "$line" in
        "Authorized Administrators:"|"Authorized Users:") section="$line"; continue ;; 
    esac

    if [[ "$section" == "Authorized Administrators:" ]]; then
        if [[ "$line" =~ ^password:\ (.+)$ ]]; then
            admin_passwords["$last_admin"]="${BASH_REMATCH[1]}"
        else
            last_admin="$line"
            admins_list+="$line "
        fi
    elif [[ "$section" == "Authorized Users:" ]]; then
        users_list+="$line "
    fi
done < "$tmp_audit_file"

rm -f "$tmp_audit_file"
all_authorized="$users_list $admins_list"

echo "Admins found: $admins_list"
echo "Standard users found: $users_list"

# --- [1a/15] USER AUDIT: Remove unauthorized users ---
echo "--- [1a/15] USER AUDIT ---"
for user in $(awk -F: '$3 >= 1000 && $3 <= 6000 {print $1}' /etc/passwd); do
    # skip protected user automatically
    if [ "$user" = "$protected_user" ]; then
        echo "INFO: Skipping $user (protected admin)"
        continue
    fi
    if [[ ! " $all_authorized " =~ " $user " ]]; then
        echo "ALERT: Unauthorized user found: $user (not removed automatically)"
    else
        echo "Verified: $user is authorized."
    fi
done

# --- [1b/15] ADMIN PASSWORD UPDATE ---
echo "--- [1b/15] ADMIN PASSWORD UPDATES ---"
for admin in $admins_list; do
    if [ "$admin" == "$protected_user" ]; then
        echo "Skipping password update for current user: $admin"
        continue
    fi
    current_pass="${admin_passwords[$admin]}"
    need_change=false
    if [[ -z "$current_pass" || "$current_pass" == "(blank/none)" ]]; then
        need_change=true
    else
        if [[ ${#current_pass} -lt 8 ]] || ! [[ "$current_pass" =~ [A-Z] ]] || ! [[ "$current_pass" =~ [0-9] ]] || ! echo "$current_pass" | grep -q '[!@#$%^&*()_+%-]'; then
            need_change=true
        fi
    fi
    if [ "$need_change" = true ]; then
        echo "Password reset required for admin: $admin"
        valid=false
        while [ "$valid" == false ]; do
            read -p "Enter new password for $admin: " new_pass
            echo ""
            has_upper=false; has_number=false; has_symbol=false
            [[ "$new_pass" =~ [A-Z] ]] && has_upper=true
            [[ "$new_pass" =~ [0-9] ]] && has_number=true
            if echo "$new_pass" | grep -q '[!@#$%^&*()_+%-]'; then has_symbol=true; fi
            if [[ ${#new_pass} -ge 8 ]] && $has_upper && $has_number && $has_symbol; then
                read -p "Confirm and apply? (y/n): " confirm
                if [[ "$confirm" == "y" ]]; then
                    (echo "$admin:$new_pass" | sudo chpasswd >>"$LOGFILE" 2>>"$ERROR_LOG") & spin $! "1b/15" "Updating password for $admin"
                    echo "Password updated for $admin."
                    valid=true
                fi
            else
                echo "ERROR: Password must have 8+ chars, 1 uppercase, 1 number, 1 symbol." | tee -a "$ERROR_LOG"
            fi
        done
    else
        echo "Password for admin $admin meets complexity requirements. No change needed."
    fi
done

# --- [1c/15] ADMIN PRIVILEGE AUDIT ---
echo "--- [1c/15] ADMIN PRIVILEGE AUDIT (UNIVERSAL) ---"
if getent group sudo >/dev/null; then admin_group="sudo"
elif getent group admin >/dev/null; then admin_group="admin"
else admin_group=""; echo "CRITICAL: No sudo/admin group found. Skipping privilege audit."; fi

if [ -n "$admin_group" ]; then
    echo "Detected admin group: $admin_group"
    for user in $(awk -F: '$3 >= 1000 && $3 <= 6000 {print $1}' /etc/passwd); do
        if [[ ! " $all_authorized " =~ " $user " ]]; then continue; fi
        is_admin=false
        if id -nG "$user" | grep -qw "$admin_group"; then is_admin=true; fi
        if [ "$user" = "$protected_user" ]; then
            echo "INFO: Skipping $user (script runner) to prevent lockout."
            continue
        fi
        if [[ " $admins_list " =~ " $user " ]] && [ "$is_admin" = false ]; then
            echo "Fixing: $user should be admin. Adding to $admin_group..."
            (sudo usermod -aG "$admin_group" "$user" >>"$LOGFILE" 2>>"$ERROR_LOG") & spin $! "1c/15" "Promoting $user to admin"
        elif [[ ! " $admins_list " =~ " $user " ]] && [ "$is_admin" = true ]; then
            current_admin_count=$(getent group "$admin_group" | cut -d: -f4 | tr ',' '\n' | grep -c .)
            if [ "$current_admin_count" -le 1 ]; then
                echo "WARNING: Cannot remove $user — would leave system without admin."
                continue
            fi
            echo "Fixing: $user should NOT be admin. Removing from $admin_group..."
            (sudo deluser "$user" "$admin_group" >>"$LOGFILE" 2>>"$ERROR_LOG") & spin $! "1c/15" "Demoting $user from admin"
        fi
    done
fi

# --- BACKUP CRITICAL FILES ---
backup_dir="./backup_$(date +%F_%T)"
mkdir -p "$backup_dir"
sudo cp /etc/pam.d/* /etc/login.defs /etc/security/pwquality.conf /etc/ssh/sshd_config "$backup_dir/" >>"$LOGFILE" 2>>"$ERROR_LOG"
echo "--- Backup of critical files saved in $backup_dir ---"

# --- [2/15] SYSTEM UPDATES ---
echo "--- [2/15] SYSTEM UPDATES ---"
{ sudo apt-get update -y >>"$LOGFILE" 2>>"$ERROR_LOG"; } & spin $! "2/15" "Updating package lists"
{ sudo apt-get upgrade -y >>"$LOGFILE" 2>>"$ERROR_LOG"; } & spin $! "2/15" "Upgrading packages"
{ sudo apt-get install -y unattended-upgrades clamav ufw auditd fail2ban libpam-pwquality locate >>"$LOGFILE" 2>>"$ERROR_LOG"; } & spin $! "2/15" "Installing security packages"
sudo DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -plow unattended-upgrades >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "2/15" "Configuring unattended upgrades"

# --- [3/15] DISABLE GUEST LOGIN ---
echo "--- [3/15] DISABLE GUEST LOGIN ---"
sudo mkdir -p /etc/lightdm/lightdm.conf.d >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "3/15" "Creating config directory"
echo -e "[Seat:*]\nallow-guest=false" | sudo tee /etc/lightdm/lightdm.conf.d/50-no-guest.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "3/15" "Disabling guest login"

# --- [4/15] PASSWORD COMPLEXITY ---
echo "--- [4/15] PASSWORD COMPLEXITY ---"
sudo sed -i 's/^# minlen =.*/minlen = 8/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "4/15" "Setting minlen=8"
sudo sed -i 's/^# ucredit =.*/ucredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "4/15" "Setting ucredit=-1"
sudo sed -i 's/^# lcredit =.*/lcredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "4/15" "Setting lcredit=-1"
sudo sed -i 's/^# dcredit =.*/dcredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "4/15" "Setting dcredit=-1"
sudo sed -i 's/^# ocredit =.*/ocredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "4/15" "Setting ocredit=-1"

# --- [5/15] PASSWORD HISTORY ---
echo "--- [5/15] PASSWORD HISTORY ---"
sudo sed -i '/pam_unix.so/ s/$/ remember=5/' /etc/pam.d/common-password >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "5/15" "Enabling password history"

# --- [6/15] ACCOUNT AGING ---
echo "--- [6/15] ACCOUNT AGING ---"
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "6/15" "Setting max days"
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "6/15" "Setting min days"
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE    7/' /etc/login.defs >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "6/15" "Setting warn age"

# --- [7/15] ACCOUNT LOCKOUT ---
echo "--- [7/15] ACCOUNT LOCKOUT ---"
sudo sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800' /etc/pam.d/common-auth >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "7/15" "Setting faillock preauth"
sudo sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800' /etc/pam.d/common-auth >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "7/15" "Setting faillock authfail"
echo "account required pam_faillock.so" | sudo tee -a /etc/pam.d/common-account >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "7/15" "Setting faillock account"

# --- [8/15] SSH HARDENING ---
echo "--- [8/15] SSH HARDENING ---"
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "8/15" "Disabling root SSH login"
sudo sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "8/15" "Changing SSH port"
sudo systemctl restart sshd >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "8/15" "Restarting SSH"

# --- [9/15] FIREWALL ---
echo "--- [9/15] FIREWALL ---"
sudo ufw default deny incoming >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "9/15" "Setting default deny incoming"
sudo ufw default allow outgoing >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "9/15" "Allowing outgoing"
sudo ufw allow 2222/tcp >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "9/15" "Allowing SSH port 2222"
sudo ufw --force enable >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "9/15" "Enabling UFW"

# --- [10/15] REMOVE PROHIBITED TOOLS (with readme prompt) ---
echo "--- [10/15] REMOVE PROHIBITED TOOLS ---"
read -p "Check the README before purging tools. Press Enter to continue..."
hacker_tools=("ophcrack" "john" "nmap" "zenmap" "netcat")
tmp_tools_file=$(mktemp /tmp/hacker_tools.XXXX)
echo "# Uncomment any tools that the README says you need to keep" > "$tmp_tools_file"
for tool in "${hacker_tools[@]}"; do
    echo "#$tool" >> "$tmp_tools_file"
done
nano "$tmp_tools_file"
tools_to_remove=()
while IFS= read -r line; do
    line=$(echo "$line" | xargs)
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue
    tools_to_remove+=("$line")
done < "$tmp_tools_file"
rm -f "$tmp_tools_file"

if [ ${#tools_to_remove[@]} -gt 0 ]; then
    echo "Purging hacker tools: ${tools_to_remove[*]}"
    sudo apt-get purge -y "${tools_to_remove[@]}" >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "10/15" "Purging hacker tools"
fi
sudo updatedb >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "10/15" "Updating file database"

# --- [11/15] FINAL HARDENING ---
echo "--- [11/15] FINAL HARDENING ---"
sudo chmod 640 /etc/shadow >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/15" "Setting /etc/shadow permissions"
sudo chmod 644 /etc/passwd >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/15" "Setting /etc/passwd permissions"
sudo systemctl enable auditd >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/15" "Enabling auditd"
sudo systemctl start auditd >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/15" "Starting auditd"
sudo systemctl enable fail2ban >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/15" "Enabling fail2ban"
sudo systemctl start fail2ban >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/15" "Starting fail2ban"

echo "--- HARDENING COMPLETE ---"
# --- [12/15] HIDDEN USER DETECTION ---
echo "--- [12/15] HIDDEN USER DETECTION ---"
awk -F: -v protected="$protected_user" '($3 < 1000 && $1 != "root" && $1 != protected) {print "Suspicious user: " $1 " UID:" $3}' /etc/passwd >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "12/15" "Scanning for hidden users"

# --- [13/15] CRON & SCHEDULED JOB BACKDOOR SCAN ---
echo "--- [13/15] CRON BACKDOOR SCAN ---"
cron_dirs=("/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly" "/var/spool/cron/crontabs")
for dir in "${cron_dirs[@]}"; do
    if [ -d "$dir" ]; then
        find "$dir" -type f ! -user root >>"$LOGFILE" 2>>"$ERROR_LOG" &
        spin $! "13/15" "Checking $dir for non-root jobs"
    fi
done

# --- [14/15] PERSISTENCE / AUTOSTART SCAN ---
echo "--- [14/15] PERSISTENCE / AUTOSTART SCAN ---"
autostart_dirs=("/etc/init.d" "/etc/systemd/system" "/etc/rc.local" "/etc/rc*.d")
for dir in "${autostart_dirs[@]}"; do
    if [ -d "$dir" ]; then
        find "$dir" -type f ! -user root >>"$LOGFILE" 2>>"$ERROR_LOG" &
        spin $! "14/15" "Checking $dir for suspicious autostart files"
    fi
done

# --- [15/15] REVERSE SHELL / OPEN PORT SCAN ---
echo "--- [15/15] REVERSE SHELL / OPEN PORT SCAN ---"
sudo netstat -tulnp 2>/dev/null | awk -v protected="$protected_user" '
    NR>2 {split($7, a, "/"); pid=a[1]; name=a[2]; if(name != "" && name != "sshd" && name != "systemd") print "Suspicious service: " name " PID:" pid " Listening on: "$4}' >>"$LOGFILE" 2>>"$ERROR_LOG" &
spin $! "15/15" "Scanning for suspicious listening services"

echo "--- ELITE HARDENING COMPLETE ---"
