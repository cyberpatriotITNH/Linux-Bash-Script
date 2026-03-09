#!/bin/bash

# --- LOGGING ---
LOGFILE="./hardening_$(date +%F_%T).log"
ERROR_LOG="./errors_$(date +%F_%T).log"
exec > >(tee -i "$LOGFILE")
exec 2> >(tee -a "$ERROR_LOG" >&2)

# --- CURRENT USER ---
current_user=$(whoami)
protected_user="$current_user"

# --- [0/11] WARNING ---
echo -e "\e[1;31mFINISH FORENSICS QUESTIONS BEFORE RUNNING THIS. ONLY RUN THIS SCRIPT IF THEY ARE DONE OR YOU GIVE UP.\e[0m"
read -p "If you acknowledge, press Enter..."

# --- [1/11] USER AUDIT WITH NANO INPUT ---
echo "--- [1/11] USER AUDIT WITH NANO INPUT ---"
tmp_audit_file=$(mktemp /tmp/user_audit.XXXX)
cat > "$tmp_audit_file" <<EOL
# Paste user audit here:
# Format example:
# Authorized Administrators:
# benjamin
#     password: W1llH4ck4B4con
# llitt
#     password: ugotlittup
# Authorized Users:
# hspecter
# jpearson
# jquelling
# rzane
# lsnart
EOL

# Open nano safely
nano "$tmp_audit_file" > /dev/tty

declare -A admin_passwords
users_list=""
admins_list="$current_user "
section=""
last_admin=""

while IFS= read -r line; do
    line=$(echo "$line" | xargs)
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

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

# --- [1a/11] REMOVE UNAUTHORIZED USERS ---
echo "--- [1a/11] USER AUDIT ---"
for user in $(awk -F: '$3 >= 1000 && $3 <= 6000 {print $1}' /etc/passwd); do
    if [[ ! " $all_authorized " =~ " $user " ]]; then
        echo "ALERT: Unauthorized user found: $user"
        read -p "Delete user $user? (y/n/cancel): " choice
        if [[ "$choice" == "y" ]]; then
            if [ "$user" = "$protected_user" ]; then
                echo "WARNING: Cannot delete current user $user to prevent lockout."
                continue
            fi
            sudo deluser --remove-home "$user" >>"$LOGFILE" 2>>"$ERROR_LOG"
            echo "User $user removed."
        elif [[ "$choice" == "cancel" ]]; then
            echo "Audit cancelled."
            exit 1
        fi
    else
        echo "Verified: $user is authorized."
    fi
done

# --- [1b/11] ADMIN PASSWORD UPDATE WITH COMPLEXITY CHECK ---
echo "--- [1b/11] ADMIN PASSWORD UPDATES ---"
for admin in $admins_list; do
    if [ "$admin" = "$protected_user" ]; then
        echo "Skipping password update for current user: $admin"
        continue
    fi

    current_pass="${admin_passwords[$admin]}"
    need_change=false

    if [[ -z "$current_pass" || "$current_pass" == "(blank/none)" ]]; then
        need_change=true
    elif [[ ${#current_pass} -lt 8 ]] || ! [[ "$current_pass" =~ [A-Z] ]] || ! [[ "$current_pass" =~ [0-9] ]] || ! echo "$current_pass" | grep -q '[!@#$%^&*()_+%-]'; then
        need_change=true
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
                    echo "$admin:$new_pass" | sudo chpasswd >>"$LOGFILE" 2>>"$ERROR_LOG"
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

# --- [1c/11] ADMIN PRIVILEGE AUDIT ---
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
        [[ ! " $all_authorized " =~ " $user " ]] && continue
        if id -nG "$user" | grep -qw "$admin_group"; then
            is_admin=true
        else
            is_admin=false
        fi

        [[ "$user" = "$protected_user" ]] && continue

        if [[ " $admins_list " =~ " $user " ]] && [ "$is_admin" = false ]; then
            echo "Promoting $user to admin..."
            sudo usermod -aG "$admin_group" "$user" >>"$LOGFILE" 2>>"$ERROR_LOG"
        elif [[ ! " $admins_list " =~ " $user " ]] && [ "$is_admin" = true ]; then
            current_admin_count=$(getent group "$admin_group" | cut -d: -f4 | tr ',' '\n' | grep -c .)
            [[ $current_admin_count -le 1 ]] && echo "Cannot remove $user — would leave system without admin." && continue
            echo "Demoting $user from admin..."
            sudo deluser "$user" "$admin_group" >>"$LOGFILE" 2>>"$ERROR_LOG"
        fi
    done
fi

# --- BACKUP CRITICAL FILES ---
backup_dir="./backup_$(date +%F_%T)"
mkdir -p "$backup_dir"
sudo cp /etc/pam.d/common-auth /etc/pam.d/common-account /etc/login.defs /etc/security/pwquality.conf /etc/ssh/sshd_config "$backup_dir/" >>"$LOGFILE" 2>>"$ERROR_LOG"

# --- [2/11] SYSTEM UPDATES ---
sudo apt-get update -y >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo apt-get upgrade -y >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo apt-get install -y unattended-upgrades clamav ufw auditd fail2ban libpam-pwquality locate >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -plow unattended-upgrades >>"$LOGFILE" 2>>"$ERROR_LOG"

# --- [3/11] DISABLE GUEST LOGIN ---
sudo mkdir -p /etc/lightdm/lightdm.conf.d >>"$LOGFILE" 2>>"$ERROR_LOG"
echo -e "[Seat:*]\nallow-guest=false" | sudo tee /etc/lightdm/lightdm.conf.d/50-no-guest.conf >>"$LOGFILE" 2>>"$ERROR_LOG"

# --- [4/11] PASSWORD COMPLEXITY ---
sudo sed -i 's/^# minlen =.*/minlen = 8/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo sed -i 's/^# ucredit =.*/ucredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo sed -i 's/^# lcredit =.*/lcredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo sed -i 's/^# dcredit =.*/dcredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo sed -i 's/^# ocredit =.*/ocredit = -1/' /etc/security/pwquality.conf >>"$LOGFILE" 2>>"$ERROR_LOG"

# --- [5/11] PASSWORD HISTORY ---
sudo sed -i '/pam_unix.so/ s/$/ remember=5/' /etc/pam.d/common-password >>"$LOGFILE" 2>>"$ERROR_LOG"

# --- [6/11] ACCOUNT AGING ---
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE    7/' /etc/login.defs >>"$LOGFILE" 2>>"$ERROR_LOG"

# --- [7/11] ACCOUNT LOCKOUT ---
sudo sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800' /etc/pam.d/common-auth >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800' /etc/pam.d/common-auth >>"$LOGFILE" 2>>"$ERROR_LOG"
echo "account required pam_faillock.so" | sudo tee -a /etc/pam.d/common-account >>"$LOGFILE" 2>>"$ERROR_LOG"

# --- [8/11] SSH HARDENING ---
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo systemctl restart sshd >>"$LOGFILE" 2>>"$ERROR_LOG"

# --- [9/11] FIREWALL ---
sudo ufw default deny incoming >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo ufw default allow outgoing >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo ufw allow 2222/tcp >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo ufw --force enable >>"$LOGFILE" 2>>"$ERROR_LOG"

# --- [10/11] REMOVE PROHIBITED TOOLS ---
sudo apt-get purge -y ophcrack john nmap zenmap netcat >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo updatedb >>"$LOGFILE" 2>>"$ERROR_LOG"
echo "Prohibited tools removed."

# --- [11/11] FINAL HARDENING ---
sudo chmod 640 /etc/shadow >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo chmod 644 /etc/passwd >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo systemctl enable auditd >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo systemctl start auditd >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo systemctl enable fail2ban >>"$LOGFILE" 2>>"$ERROR_LOG"
sudo systemctl start fail2ban >>"$LOGFILE" 2>>"$ERROR_LOG"

echo "--- HARDENING COMPLETE ---"
echo "See errors at $ERROR_LOG"
