#!/bin/bash
# Elite CyberPatriot Hardening & Forensics Script [Unified Full 16-Step Version]
# Supports Debian/Ubuntu/Mint

##########################
# GLOBALS & COLORS
##########################
LOG_DIR="./cp-logs"
BACKUP_DIR="./cp-backups"
TIMESTAMP=$(date +'%F-%H%M%S')
REPORT_FILE="$LOG_DIR/cp-report-$TIMESTAMP.txt"
LOGFILE="$LOG_DIR/hardening_$TIMESTAMP.log"
ERROR_LOG="$LOG_DIR/errors_$TIMESTAMP.log"
SPINNER="/-\|"
mkdir -p "$LOG_DIR" "$BACKUP_DIR"

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
RESET="\e[0m"

##########################
# DRY-RUN MODE
##########################
DRYRUN=false
for arg in "$@"; do
    if [[ "$arg" == "--dry-run" ]]; then
        DRYRUN=true
        echo -e "${YELLOW}[DRY-RUN] Enabled: No destructive changes will be applied.${RESET}"
    fi
done

##########################
# SPINNER FUNCTION
##########################
spin() {
    local pid=$1
    local step=$2
    local text=$3
    local i=0
    local spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}[%s]${RESET} [%c] %s" "$step" "${spinstr:i:1}" "$text"
        i=$(( (i+1) %4 ))
        sleep 0.1
    done
    printf "\r${GREEN}[%s] ✔ %s${RESET}\n" "$step" "$text"
}

##########################
# UTILITY FUNCTIONS
##########################
backup_file() {
    local file="$1"
    local step="$2"
    [ -f "$file" ] && cp -n "$file" "$BACKUP_DIR/$(basename $file).cpbackup-${step}-${TIMESTAMP}"
}

log_and_echo() {
    echo -e "$1" | tee -a "$REPORT_FILE" "$LOGFILE"
}

stop_prompt() {
    read -p "$(echo -e ${YELLOW}Continue? (Y/N):${RESET}) " cont
    [[ ! "$cont" =~ ^[Yy]$ ]] && echo -e "${RED}Exiting.${RESET}" && exit
}

##########################
# ARGUMENT PARSING
##########################
MODE="default"
UNDO_STEP=""
for i in "$@"; do
    case "$i" in
        --forensic|--forensics) MODE="forensic" ;;
        --harden) MODE="harden" ;;
        --undo) MODE="undo"; UNDO_STEP="$2" ;;
    esac
done

if [ "$MODE" = "default" ]; then
    echo -e "${YELLOW}WARNING: This script will change system settings (passwords, SSH, firewall, etc.).${RESET}"
    read -p "Do you want to continue? (Y/N): " CONFIRM
    [[ ! "$CONFIRM" =~ ^[Yy]$ ]] && echo -e "${RED}Exiting.${RESET}" && exit 1
    MODE="harden"
fi

##########################
# OS DETECTION
##########################
if [ -f /etc/os-release ]; then
    source /etc/os-release
else
    echo -e "${RED}Cannot detect OS. Exiting.${RESET}" && exit 1
fi
log_and_echo "${BLUE}Detected OS: $NAME $VERSION_ID${RESET}"

##########################
# CURRENT USER
##########################
current_user=$(whoami)
protected_user="$current_user"

##########################
# STEP 1: USER/ADMIN AUDIT WITH NANO INPUT
##########################
if [ "$MODE" = "harden" ]; then
    echo -e "${MAGENTA}--- [1/16] USER/ADMIN AUDIT ---${RESET}"
    echo -e "${YELLOW}Opening temporary file for user audit. Please list authorized admins/users.${RESET}"

    tmp_audit_file=$(mktemp /tmp/user_audit.XXXX)
    cat > "$tmp_audit_file" <<EOL
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

    nano "$tmp_audit_file" > /dev/tty

    declare -A admin_passwords
    users_list=""
    admins_list="$protected_user "
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

    # Remove unauthorized users
    for user in $(awk -F: '$3 >= 1000 && $3 <= 6000 {print $1}' /etc/passwd); do
        if [[ ! " $all_authorized " =~ " $user " ]]; then
            echo "ALERT: Unauthorized user found: $user"
            if [ "$DRYRUN" = true ]; then
                echo "[DRY-RUN] Would remove user: $user"
                continue
            fi
            if [[ "$user" = "$protected_user" ]]; then
                echo "WARNING: Cannot delete current user $user to prevent lockout."
                continue
            fi
            read -p "Delete user $user? (y/n/cancel): " choice
            if [[ "$choice" == "y" ]]; then
                sudo deluser --remove-home "$user" >>"$LOGFILE" 2>>"$ERROR_LOG"
                echo "User $user removed."
            elif [[ "$choice" == "cancel" ]]; then
                echo "Audit cancelled."; exit 1
            fi
        else
            echo "Verified: $user is authorized."
        fi
    done

    # Admin password updates
    for admin in $admins_list; do
        [[ "$admin" = "$protected_user" ]] && continue
        current_pass="${admin_passwords[$admin]}"
        need_change=false

        if [[ -z "$current_pass" || "$current_pass" == "(blank/none)" ]]; then
            need_change=true
        elif [[ ${#current_pass} -lt 8 ]] || ! [[ "$current_pass" =~ [A-Z] ]] || ! [[ "$current_pass" =~ [0-9] ]] || ! echo "$current_pass" | grep -q '[!@#$%^&*()_+%-]'; then
            need_change=true
        fi

        if [ "$need_change" = true ]; then
            if [ "$DRYRUN" = true ]; then
                echo "[DRY-RUN] Would reset password for admin: $admin"
                continue
            fi
            echo "Password reset required for admin: $admin"
            valid=false
            while [ "$valid" = false ]; do
                read -p "Enter new password for $admin: " new_pass
                echo ""
                has_upper=false; has_number=false; has_symbol=false
                [[ "$new_pass" =~ [A-Z] ]] && has_upper=true
                [[ "$new_pass" =~ [0-9] ]] && has_number=true
                if echo "$new_pass" | grep -q '[!@#$%^&*()_+%-]'; then has_symbol=true; fi
                if [[ ${#new_pass} -ge 8 ]] && $has_upper && $has_number && $has_symbol; then
                    read -p "Confirm and apply? (y/n): " confirm
                    [[ "$confirm" == "y" ]] && echo "$admin:$new_pass" | sudo chpasswd >>"$LOGFILE" 2>>"$ERROR_LOG" && valid=true
                else
                    echo "ERROR: Password must have 8+ chars, 1 uppercase, 1 number, 1 symbol." | tee -a "$ERROR_LOG"
                fi
            done
        else
            echo "Password for $admin meets complexity requirements. No change needed."
        fi
    done

    # Admin privilege audit
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
            is_admin=false
            id -nG "$user" | grep -qw "$admin_group" && is_admin=true
            [[ "$user" = "$protected_user" ]] && continue

            if [[ " $admins_list " =~ " $user " ]] && [ "$is_admin" = false ]; then
                [ "$DRYRUN" = true ] && echo "[DRY-RUN] Would promote $user to admin" && continue
                sudo usermod -aG "$admin_group" "$user" >>"$LOGFILE" 2>>"$ERROR_LOG"
            elif [[ ! " $admins_list " =~ " $user " ]] && [ "$is_admin" = true ]; then
                current_admin_count=$(getent group "$admin_group" | cut -d: -f4 | tr ',' '\n' | grep -c .)
                [[ $current_admin_count -le 1 ]] && echo "Cannot remove $user — would leave system without admin." && continue
                [ "$DRYRUN" = true ] && echo "[DRY-RUN] Would demote $user from admin" && continue
                sudo deluser "$user" "$admin_group" >>"$LOGFILE" 2>>"$ERROR_LOG"
            fi
        done
    fi
fi
