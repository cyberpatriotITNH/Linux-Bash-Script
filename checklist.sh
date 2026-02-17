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

# --- [0/11] WARNING ---
echo -e "\e[1;31mFINISH FORENSICS QUESTIONS BEFORE RUNNING THIS. ONLY RUN THIS SCRIPT IF THEY ARE DONE OR YOU GIVE UP.\e[0m"
read -p "If you acknowledge, press Enter..."

# --- [1/11] USER AUDIT WITH NANO INPUT ---
echo "--- [1/11] USER AUDIT WITH NANO INPUT ---"
tmp_audit_file=$(mktemp /tmp/user_audit.XXXX)
echo "# Paste user audit here:" > "$tmp_audit_file"
echo "# Format example:" >> "$tmp_audit_file"
echo "# Authorized Administrators:" >> "$tmp_audit_file"
echo "# ballen (you)" >> "$tmp_audit_file"
echo "#     password: (blank/none)" >> "$tmp_audit_file"
echo "# iwest" >> "$tmp_audit_file"
echo "#     password: JITTerS" >> "$tmp_audit_file"
echo "# Authorized Users:" >> "$tmp_audit_file"
echo "# cramonn" >> "$tmp_audit_file"
echo "# hrathaway" >> "$tmp_audit_file"
nano "$tmp_audit_file"

declare -A admin_passwords
users_list=""
admins_list="$current_user "  # Protect current user automatically
section=""
last_admin=""

while IFS= read -r line; do
    line=$(echo "$line" | xargs)   # trim whitespace
    [[ -z "$line" ]] && continue    # skip empty
    [[ "$line" =~ ^# ]] && continue # skip comments

    case "$line" in
        "Authorized Administrators:"|"Authorized Users:")
            section="$line"
            continue
            ;;
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

# --- [1a/11] USER AUDIT: Remove unauthorized users ---
echo "--- [1a/11] USER AUDIT ---"
while true; do
    for user in $(awk -F: '$3 >= 1000 && $3 <= 6000 {print $1}' /etc/passwd); do
        if [[ ! " $all_authorized " =~ " $user " ]]; then
            echo "ALERT: Unauthorized user found: $user"
            read -p "Delete user $user? (y/n/cancel): " choice
            if [[ "$choice" == "y" ]]; then
                if [ "$user" = "$protected_user" ]; then
                    echo "WARNING: Cannot delete current user $user to prevent lockout."
                    continue
                fi
                (sudo deluser --remove-home "$user" >>"$LOGFILE" 2>>"$ERROR_LOG") & spin $! "1a/11" "Removing user $user"
                echo "User $user removed."
            elif [[ "$choice" == "cancel" ]]; then
                echo "Audit cancelled."
                exit 1
            fi
        else
            echo "Verified: $user is authorized."
        fi
    done
    read -p "Press Enter to continue, or type 'redo' to restart user audit: " redo
    [[ "$redo" != "redo" ]] && break
done

# --- [1b/11] ADMIN PASSWORD UPDATE WITH COMPLEXITY CHECK ---
echo "--- [1b/11] ADMIN PASSWORD UPDATES ---"

for admin in $admins_list; do
    # Skip password update for current user
    if [ "$admin" == "$protected_user" ]; then
        echo "Skipping password update for current user: $admin"
        continue
    fi

    current_pass="${admin_passwords[$admin]}"
    need_change=false

    # Check if password is blank or weak
    if [[ -z "$current_pass" || "$current_pass" == "(blank/none)" ]]; then
        need_change=true
    else
        # Complexity checks: length 8+, uppercase, number, symbol
        if [[ ${#current_pass} -lt 8 ]]; then
            need_change=true
        elif ! [[ "$current_pass" =~ [A-Z] ]]; then
            need_change=true
        elif ! [[ "$current_pass" =~ [0-9] ]]; then
            need_change=true
        elif ! echo "$current_pass" | grep -q '[!@#$%^&*()_+%-]'; then
            need_change=true
        fi
    fi

    if [ "$need_change" = true ]; then
        echo "Password reset required for admin: $admin"
        valid=false
        while [ "$valid" == false ]; do
            read -p "Enter new password for $admin: " new_pass
            echo ""
            # --- Complexity check ---
            has_upper=false; has_number=false; has_symbol=false
            [[ "$new_pass" =~ [A-Z] ]] && has_upper=true
            [[ "$new_pass" =~ [0-9] ]] && has_number=true
            if echo "$new_pass" | grep -q '[!@#$%^&*()_+%-]'; then has_symbol=true; fi

            if [[ ${#new_pass} -ge 8 ]] && $has_upper && $has_number && $has_symbol; then
                read -p "Confirm and apply? (y/n): " confirm
                if [[ "$confirm" == "y" ]]; then
                    (echo "$admin:$new_pass" | sudo chpasswd >>"$LOGFILE" 2>>"$ERROR_LOG") & spin $! "1b/11" "Updating password for $admin"
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

# --- [1c/11] UNIVERSAL ADMIN PRIVILEGE AUDIT WITH SPINNER AND GUARDRAILS ---
echo "--- [1c/11] ADMIN PRIVILEGE AUDIT (UNIVERSAL) ---"

if getent group sudo >/dev/null; then
    admin_group="sudo"
elif getent group admin >/dev/null; then
    admin_group="admin"
else
    echo "CRITICAL: No sudo/admin group found. Skipping privilege audit."
    admin_group=""
fi

if [ -n "$admin_group" ]; then
    echo "Detected admin group: $admin_group"

    for user in $(awk -F: '$3 >= 1000 && $3 <= 6000 {print $1}' /etc/passwd); do

        # Skip completely unauthorized users
        if [[ ! " $all_authorized " =~ " $user " ]]; then
            continue
        fi

        # Check current admin status
        if id -nG "$user" | grep -qw "$admin_group"; then
            is_admin=true
        else
            is_admin=false
        fi

        # Protect script runner from demotion/removal
        if [ "$user" = "$protected_user" ]; then
            echo "INFO: Skipping $user (script runner) to prevent lockout."
            continue
        fi

        # CASE 1: Should be admin but isn't
        if [[ " $admins_list " =~ " $user " ]] && [ "$is_admin" = false ]; then
            echo "Fixing: $user should be admin. Adding to $admin_group..."
            (sudo usermod -aG "$admin_group" "$user" >>"$LOGFILE" 2>>"$ERROR_LOG") & spin $! "1c/11" "Promoting $user to admin"
            echo "$user promoted to admin."

        # CASE 2: Should NOT be admin but is
        elif [[ ! " $admins_list " =~ " $user " ]] && [ "$is_admin" = true ]; then
            current_admin_count=$(getent group "$admin_group" | cut -d: -f4 | tr ',' '\n' | grep -c .)
            if [ "$current_admin_count" -le 1 ]; then
                echo "WARNING: Cannot remove $user — would leave system without admin."
                continue
            fi
            echo "Fixing: $user should NOT be admin. Removing from $admin_group..."
            (sudo deluser "$user" "$admin_group" >>"$LOGFILE" 2>>"$ERROR_LOG") & spin $! "1c/11" "Demoting $user from admin"
            echo "$user demoted to standard user."
        fi
    done
fi

# --- BACKUP CRITICAL FILES ---
backup_dir="./backup_$(date +%F_%T)"
mkdir -p "$backup_dir"
sudo cp /etc/pam.d/common-auth /etc/pam.d/common-account /etc/login.defs /etc/security/pwquality.conf /etc/ssh/sshd_config "$backup_dir/" >>"$LOGFILE" 2>>"$ERROR_LOG"
echo "--- Backup of critical files saved in $backup_dir ---"

# --- [2/11] SYSTEM UPDATES ---
echo "--- [2/11] SYSTEM UPDATES ---"
{
    sudo apt-get update -y >>"$LOGFILE" 2>>"$ERROR_LOG"
} & spin $! "2/11" "Updating package lists"

{
    sudo apt-get upgrade -y >>"$LOGFILE" 2>>"$ERROR_LOG"
} & spin $! "2/11" "Upgrading packages"

{
    sudo apt-get install -y unattended-upgrades clamav ufw auditd fail2ban libpam-pwquality locate >>"$LOGFILE" 2>>"$ERROR_LOG"
} & spin $! "2/11" "Installing security packages"

sudo DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -plow unattended-upgrades >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "2/11" "Configuring unattended upgrades"

# --- [3/11] DISABLE GUEST LOGIN ---
echo "--- [3/11] DISABLE GUEST LOGIN ---"
sudo mkdir -p /etc/lightdm/lightdm.conf.d >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "3/11" "Creating config directory"
echo -e "[Seat:*]\nallow-guest=false" | sudo tee /etc/lightdm/lightdm.conf.d/50-no-guest.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "3/11" "Disabling guest login"

# --- [4/11] PASSWORD COMPLEXITY ---
echo "--- [4/11] PASSWORD COMPLEXITY ---"
sudo sed -i 's/^# minlen =.*/minlen = 8/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "4/11" "Setting minlen=8"
sudo sed -i 's/^# ucredit =.*/ucredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "4/11" "Setting ucredit=-1"
sudo sed -i 's/^# lcredit =.*/lcredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "4/11" "Setting lcredit=-1"
sudo sed -i 's/^# dcredit =.*/dcredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "4/11" "Setting dcredit=-1"
sudo sed -i 's/^# ocredit =.*/ocredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "4/11" "Setting ocredit=-1"

# --- [5/11] PASSWORD HISTORY ---
echo "--- [5/11] PASSWORD HISTORY ---"
sudo sed -i '/pam_unix.so/ s/$/ remember=5/' /etc/pam.d/common-password >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "5/11" "Enabling password history"

# --- [6/11] ACCOUNT AGING ---
echo "--- [6/11] ACCOUNT AGING ---"
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "6/11" "Setting max days"
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "6/11" "Setting min days"
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE    7/' /etc/login.defs >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "6/11" "Setting warn age"

# --- [7/11] ACCOUNT LOCKOUT ---
echo "--- [7/11] ACCOUNT LOCKOUT ---"
sudo sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800' /etc/pam.d/common-auth >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "7/11" "Setting faillock preauth"
sudo sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800' /etc/pam.d/common-auth >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "7/11" "Setting faillock authfail"
echo "account required pam_faillock.so" | sudo tee -a /etc/pam.d/common-account >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "7/11" "Setting faillock account"

# --- [8/11] SSH HARDENING ---
echo "--- [8/11] SSH HARDENING ---"
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "8/11" "Disabling root SSH login"
sudo sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "8/11" "Changing SSH port"
sudo systemctl restart sshd >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "8/11" "Restarting SSH"

# --- [9/11] FIREWALL ---
echo "--- [9/11] FIREWALL ---"
sudo ufw default deny incoming >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "9/11" "Setting default deny incoming"
sudo ufw default allow outgoing >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "9/11" "Allowing outgoing"
sudo ufw allow 2222/tcp >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "9/11" "Allowing SSH port 2222"
sudo ufw --force enable >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "9/11" "Enabling UFW"

# --- [10/11] REMOVE PROHIBITED TOOLS ---
echo "--- [10/11] REMOVE PROHIBITED TOOLS ---"
sudo apt-get purge -y ophcrack john nmap zenmap netcat >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "10/11" "Removing prohibited tools"
sudo updatedb >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "10/11" "Updating file database"
echo "Prohibited tools removed. Media files located:"
locate --existing '*.mp3' '*.mp4' '*.avi' '*.mov' '*.jpg' '*.png' >>"$LOGFILE"

# --- [11/11] FINAL HARDENING ---
echo "--- [11/11] FINAL HARDENING ---"
sudo chmod 640 /etc/shadow >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/11" "Setting /etc/shadow permissions"
sudo chmod 644 /etc/passwd >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/11" "Setting /etc/passwd permissions"
sudo systemctl enable auditd >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/11" "Enabling auditd"
sudo systemctl start auditd >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/11" "Starting auditd"
sudo systemctl enable fail2ban >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/11" "Enabling fail2ban"
sudo systemctl start fail2ban >>"$LOGFILE" 2>>"$ERROR_LOG" & spin $! "11/11" "Starting fail2ban"

echo "--- HARDENING COMPLETE
