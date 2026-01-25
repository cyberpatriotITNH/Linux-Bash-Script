#!/bin/bash

# --- [0/11] CRITICAL WARNING ---
echo -e "\e[1;31mFINISH FORENSICS QUESTIONS BEFORE RUNNING THIS. ONLY RUN THIS SCRIPT IF THEY ARE DONE OR YOU GIVE UP.\e[0m"
read -p "Press Enter to acknowledge and continue..."

# --- [1/11] INTERACTIVE USER AUDIT & ADMIN PASSWORDS ---
users_list=""
admins_list=""

echo "Enter AUTHORIZED NORMAL USERS (Type 'admins' when finished):"
while true; do
    read -p "> " entry
    if [[ "$entry" == "admins" ]]; then break; fi
    users_list+="$entry "
done

echo "Enter AUTHORIZED ADMINS (Type 'done' when finished):"
while true; do
    read -p "> " entry
    if [[ "$entry" == "done" ]]; then break; fi
    admins_list+="$entry "
done

all_authorized="$users_list $admins_list"

echo "--- STARTING USER AUDIT ---"
for user in $(awk -F: '$3 >= 1000 && $3 <= 6000 {print $1}' /etc/passwd); do
    if [[ ! $all_authorized =~ (^|[[:space:]])"$user"($|[[:space:]]) ]]; then
        echo "ALERT: Unauthorized user found: $user"
        read -p "Do you want to delete user $user? (y/n): " choice
        if [ "$choice" == "y" ]; then
            sudo deluser --remove-home "$user"
            echo "User $user has been removed."
        fi
    else
        echo "Verified: $user is authorized."
    fi
done

echo "--- ADMIN PASSWORD UPDATES ---"
for admin in $admins_list; do
    echo "Processing Admin: $admin"
    valid=false
    while [ "$valid" == false ]; do
        echo "Requirements: 8+ chars, 1 Capital, 1 Number, 1 Symbol."
        read -s -p "Enter new password for $admin: " new_pass
        echo ""
        
        if [[ ${#new_pass} -ge 8 && "$new_pass" == *[A-Z]* && "$new_pass" == *[0-9]* && "$new_pass" == *['!'@#\$%^\&*()_+]* ]]; then
            echo "is this correct: $new_pass"
            read -p "(y/n): " confirm
            if [ "$confirm" == "y" ]; then
                echo "$admin:$new_pass" | sudo chpasswd
                echo "Password successfully updated for $admin."
                valid=true
            fi
        else
            echo "ERROR: Password does not meet complexity requirements. Try again."
        fi
    done
done

echo "--- [2/11] Starting System Updates ---"
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y unattended-upgrades clamav ufw auditd fail2ban libpam-pwquality locate
sudo dpkg-reconfigure -plow unattended-upgrades
echo "Updates and core security packages installed."

echo "--- [3/11] Configuring User Settings & Guest Access ---"
sudo mkdir -p /etc/lightdm/lightdm.conf.d
echo -e "[Seat:*]\nallow-guest=false" | sudo tee /etc/lightdm/lightdm.conf.d/50-no-guest.conf
echo "Guest account disabled."

echo "--- [4/11] Setting Password Complexity (pwquality) ---"
sudo sed -i 's/^# minlen =.*/minlen = 8/' /etc/security/pwquality.conf
sudo sed -i 's/^# ucredit =.*/ucredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^# lcredit =.*/lcredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^# dcredit =.*/dcredit = -1/' /etc/security/pwquality.conf
sudo sed -i 's/^# ocredit =.*/ocredit = -1/' /etc/security/pwquality.conf
echo "Password complexity rules applied."

echo "--- [5/11] Setting Password History ---"
sudo sed -i '/pam_unix.so/ s/$/ remember=5/' /etc/pam.d/common-password
echo "System will now remember last 5 passwords."

echo "--- [6/11] Configuring Account Aging (login.defs) ---"
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE    7/' /etc/login.defs
echo "Password expiration set: Max 90 days."

echo "--- [7/11] Configuring Account Lockout (faillock) ---"
sudo sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800' /etc/pam.d/common-auth
sudo sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800' /etc/pam.d/common-auth
echo "account required pam_faillock.so" | sudo tee -a /etc/pam.d/common-account
echo "Lockout policy set: 5 attempts = 30 minute lockout."

echo "--- [8/11] Hardening SSH Configuration ---"
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart ssh
echo "SSH Root login disabled; Port changed to 2222."

echo "--- [9/11] Configuring Firewall (UFW) ---"
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp
echo "y" | sudo ufw enable
echo "Firewall active."

echo "--- [10/11] Cleaning Prohibited Tools and Media ---"
sudo apt-get purge -y ophcrack john nmap zenmap netcat
sudo updatedb
echo "Prohibited tools removed. Locating media files..."
locate *.mp3 *.mp4 *.avi *.mov *.jpg *.png

echo "--- [11/11] Final Hardening and Logs ---"
sudo chmod 640 /etc/shadow
sudo chmod 640 /etc/passwd
sudo systemctl enable auditd
sudo systemctl start auditd
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
echo "Permissions set. Auditd and Fail2Ban started."

echo "--- HARDENING COMPLETE ---"
