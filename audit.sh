#!/usr/bin/env bash
#
# MIT License

# Copyright (c) 2024 Kyriacos Kyriacou (@kkyrio)

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# audit.sh
#
# Author: Kyri (https://x.com/kkyrio)
#
# This script performs security checks on an Ubuntu/Debian VPS, ensuring it follows
# good security practices. It checks for:
#   * Non-root user setup
#   * UFW firewall configuration
#   * SSH hardening
#   * Fail2ban configuration
#   * Access control and permissions
#   * Port security
#   * Automatic updates
#
# Local fork: runs entirely on the box with no remote reporting. All results
# print to the terminal only.
#
# Usage:
#   ./audit.sh
#
# Note: certain commands require sudo privileges.

set -u

VERSION="1.0.0"

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

check_os() {
    local os=""
    if [ -f /etc/lsb-release ]; then
        os="ubuntu"
    elif [ -f /etc/debian_version ]; then
        os="debian"
    fi

    if [ -z "$os" ]; then
        echo -e "${RED}This script only supports Ubuntu/Debian systems. Exiting.${NC}"
        echo "Please ensure you're running this script on a supported operating system."
        exit 1
    fi

    echo -e "${GREEN}Detected supported OS: ${os}${NC}\n"
}

check_dependencies() {
    echo -e "${CYAN}Checking required dependencies...${NC}"

    local required_commands=("systemctl" "dpkg" "stat")
    local missing_commands=()

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done

    if [ ${#missing_commands[@]} -ne 0 ]; then
        echo -e "${RED}The following required commands are missing:${NC}"
        for cmd in "${missing_commands[@]}"; do
            echo "  - $cmd"
        done
        echo
        echo -e "${YELLOW}Please install these commands before running this script.${NC}"
        exit 1
    fi

    echo -e "${GREEN}All required dependencies are installed${NC}\n"
    return 0
}

print_status() {
    local category="$1"
    local status="$2"
    local message="$3"
    local check="${4:-}"

    local indent=""
    local status_color=""

    if [ -n "$check" ]; then
        indent="  ├─ "
        category="$check"  # Use check as the category for checks
    fi

    case "$status" in
        "running")
            status_color="$CYAN"
            ;;
        "pass")
            status_color="$GREEN"
            ;;
        "fail")
            status_color="$RED"
            ;;
        "error")
            status_color="$RED"
            ;;
        "skip")
            status_color="$YELLOW"
            ;;
        *)
            status_color="$YELLOW"
            ;;
    esac

    echo -e "${indent}${status_color}[${status^^}]${NC} ${category}: ${message}"
}

send_status() {
    local category="$1"
    local status="$2"
    local message="$3"
    local check="${4:-}"

    print_status "$category" "$status" "$message" "$check"
}

get_sshd_port() {
    # Prefer the effective config (respects Include directives) so custom
    # ports are honored. Falls back to 22 if sshd isn't present.
    local port=""
    if command -v sshd >/dev/null 2>&1; then
        port=$(sudo sshd -T 2>/dev/null | awk '/^port[[:space:]]/ { print $2; exit }')
    fi
    [ -n "$port" ] && echo "$port" || echo "22"
}

check_ufw() {
    local category="ufw_security"
    local failed=false
    local ufw_active=false

    send_status "$category" "running" "Starting UFW security check"

    # Check if UFW is installed
    if ! command -v ufw >/dev/null 2>&1; then
        send_status "$category" "fail" "UFW is not installed" "installation"
        failed=true
    else
        send_status "$category" "pass" "UFW is installed" "installation"
    fi

    # Check if UFW is active
    if ! $failed; then
        if ! sudo ufw status | grep -qw "active"; then
            send_status "$category" "fail" "UFW is not active" "active_status"
            failed=true
        else
            send_status "$category" "pass" "UFW is active" "active_status"
            ufw_active=true
        fi
    else
        send_status "$category" "skip" "UFW not installed - skipping" "active_status"
    fi

    # Check default policies
    if $ufw_active; then
        local default_incoming
        if ! default_incoming=$(sudo ufw status verbose | grep "Default:" | grep "incoming" | awk '{print $2}'); then
            send_status "$category" "error" "Failed to retrieve UFW default policy" "default_policy"
            failed=true
        elif [ "$default_incoming" != "deny" ]; then
            send_status "$category" "fail" "Default incoming policy is not set to deny" "default_policy"
            failed=true
        else
            send_status "$category" "pass" "Default incoming policy is properly set to deny" "default_policy"
        fi
    else
        send_status "$category" "skip" "UFW not active - skipping" "default_policy"
    fi

    # Verify the SSH port is actually allowed. A deny-by-default "pass" that
    # doesn't also allow the port you connect on is a locked-out box.
    if $ufw_active; then
        local ssh_port
        ssh_port=$(get_sshd_port)
        local ufw_status
        ufw_status=$(sudo ufw status)
        if ! echo "$ufw_status" | awk -v p="$ssh_port" '($1 == p) || ($1 == (p "/tcp")) { if ($2 == "ALLOW") ok = 1 } END { exit !ok }'; then
            send_status "$category" "fail" "SSH port ${ssh_port} is not ALLOWed by UFW - you may be locked out" "ssh_port_allowed"
            failed=true
        else
            send_status "$category" "pass" "SSH port ${ssh_port} is ALLOWed by UFW" "ssh_port_allowed"
        fi
    else
        send_status "$category" "skip" "UFW not active - skipping" "ssh_port_allowed"
    fi

    # Final status
    if $failed; then
        send_status "$category" "fail" "Some UFW security checks failed"
        return 1
    else
        send_status "$category" "pass" "All UFW security checks passed"
        return 0
    fi
}

check_ssh_keys() {
    # Check key-based auth for every real login user (root + normal UIDs,
    # excluding nologin/false shells) rather than just the invoking user's
    # home directory. Also verifies the directory and key file aren't
    # group/other-writable, which sshd's StrictModes would reject.
    local found_user=false
    local broken=0
    local user home ssh_dir keys_file dir_mode file_mode

    while IFS=: read -r user home; do
        [ -z "$user" ] && continue
        found_user=true
        ssh_dir="$home/.ssh"
        keys_file=""
        if [ -f "$ssh_dir/authorized_keys" ]; then
            keys_file="$ssh_dir/authorized_keys"
        elif [ -f "$ssh_dir/authorized_keys2" ]; then
            keys_file="$ssh_dir/authorized_keys2"
        fi

        if [ -z "$keys_file" ]; then
            send_status "ssh_security" "fail" "No authorized_keys found for user '$user'" "key_auth_${user}"
            broken=1
            continue
        fi

        dir_mode=$(stat -c "%a" "$ssh_dir" 2>/dev/null)
        file_mode=$(stat -c "%a" "$keys_file" 2>/dev/null)

        if [ -z "$dir_mode" ] || [ -z "$file_mode" ]; then
            send_status "ssh_security" "fail" "Cannot read permissions for '$user'" "key_auth_${user}"
            broken=1
        elif (( (8#$file_mode & 8#022) != 0 )) || (( (8#$dir_mode & 8#022) != 0 )); then
            send_status "ssh_security" "fail" "Wrong permissions for '$user' (.ssh=$dir_mode, keys=$file_mode, group/other must not be writable)" "key_auth_${user}"
            broken=1
        else
            send_status "ssh_security" "pass" "Key auth set up for user '$user' ($file_mode)" "key_auth_${user}"
        fi
    done <<< "$(awk -F: '($3 == 0 || $3 >= 1000) && $7 !~ /(nologin|\/bin\/false)/ { print $1 ":" $6 }' /etc/passwd)"

    if ! $found_user; then
        send_status "ssh_security" "fail" "No login users found to verify key auth" "key_auth"
        broken=1
    elif [ $broken -eq 1 ]; then
        send_status "ssh_security" "fail" "Key auth is missing or misconfigured for some users" "key_auth"
    else
        send_status "ssh_security" "pass" "Key auth configured for all login users" "key_auth"
    fi

    if [ $broken -eq 1 ]; then
        return 1
    fi
    return 0
}

check_ssh() {
    local category="ssh_security"
    local final_status="pass"
    local ssh_enabled=false

    send_status "$category" "running" "Starting SSH security check"

    # Detect SSH under socket activation too (ssh.socket on modern
    # Ubuntu/Debian), so hardening checks aren't silently skipped on a host
    # that is actively listening.
    if systemctl is-active --quiet sshd 2>/dev/null \
        || systemctl is-active --quiet ssh.service 2>/dev/null \
        || systemctl is-active --quiet sshd.socket 2>/dev/null \
        || systemctl is-active --quiet ssh.socket 2>/dev/null; then
        send_status "$category" "pass" "SSH service is active" "service_status"
        ssh_enabled=true
    else
        # Nothing verified, so don't claim a pass.
        send_status "$category" "skip" "SSH service not found or running" "service_status"
        send_status "$category" "skip" "SSH not running - remaining checks skipped" "key_auth"
        send_status "$category" "skip" "SSH not running - remaining checks skipped" "config"
        send_status "$category" "skip" "SSH not running - remaining checks skipped" "port"
        send_status "$category" "skip" "SSH checks were skipped, not verified" "summary"
        return 0
    fi

    # Only continue if SSH is enabled
    if $ssh_enabled; then
        if ! command -v sshd >/dev/null 2>&1; then
            # e.g. dropbear - nothing sshd-specific to inspect
            send_status "$category" "skip" "sshd binary not found - config checks skipped" "config"
            return 0
        fi

        check_ssh_keys || final_status="fail"

        # Check SSH config settings
        local config_checks=(
            "PermitRootLogin no"
            "KbdInteractiveAuthentication no"
            "PasswordAuthentication no"
            "UsePAM no"
        )

        for check in "${config_checks[@]}"; do
            local key="${check% *}" # Get the key part (before the space)
            local expected="${check#* }" # Get the value part (after the space)
            local actual

            # Get actual value from sshd -T output
            actual=$(sudo sshd -T | grep -i "^${key}" | awk '{print $2}')

            if [ -z "$actual" ]; then
                send_status "$category" "fail" "${key} is not configured" "config_${key}"
                final_status="fail"
            elif [ "$actual" != "$expected" ]; then
                send_status "$category" "fail" "${key} is set to '$actual' (should be '$expected')" "config_${key}"
                final_status="fail"
            else
                send_status "$category" "pass" "${key} is correctly set to '$expected'" "config_${key}"
            fi
        done
    fi

    # Final status
    if [ "$final_status" = "fail" ]; then
        send_status "$category" "fail" "Some SSH security checks failed"
        return 1
    else
        send_status "$category" "pass" "All SSH security checks passed"
        return 0
    fi
}

check_non_root_user() {
    local category="non_root_user"
    local final_status="pass"
    local sudo_users
    local admin_users
    local privileged_users

    send_status "$category" "running" "Checking for properly configured non-root user"

    # Look for users with sudo privileges (in sudo or admin group)
    sudo_users=$(grep -Po '^sudo:.*:\K.*$' /etc/group | tr ',' '\n' | grep -v root)
    admin_users=$(grep -Po '^admin:.*:\K.*$' /etc/group | tr ',' '\n' | grep -v root)

    if [ -z "$sudo_users" ] && [ -z "$admin_users" ]; then
        send_status "$category" "fail" "No non-root users found with sudo privileges" "sudo_access"
        final_status="fail"
    else
        # Combine and deduplicate users
        privileged_users=$(echo -e "${sudo_users}\n${admin_users}" | sort -u | grep -v '^$')

        # Check if any of these users have a valid shell
        local valid_user_found=false
        local user_shell

        while IFS= read -r user; do
            user_shell=$(getent passwd "$user" | cut -d: -f7)
            if [[ "$user_shell" != "/usr/sbin/nologin" && "$user_shell" != "/bin/false" ]]; then
                valid_user_found=true
                send_status "$category" "pass" "Found valid non-root sudo user" "sudo_access"
                break
            fi
        done <<< "$privileged_users"

        if ! $valid_user_found; then
            send_status "$category" "fail" "No non-root sudo users found" "sudo_access"
            final_status="fail"
        fi
    fi

    # Final status
    if [ "$final_status" = "fail" ]; then
        send_status "$category" "fail" "Non-root sudo user check failed"
        return 1
    else
        send_status "$category" "pass" "Valid non-root sudo user exists"
        return 0
    fi
}

check_access_control() {
    local category="access_control"
    local failed=false

    send_status "$category" "running" "Starting access control checks"

    declare -A critical_files=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="600"
    )

    declare -A check_names=(
        ["/etc/passwd"]="passwd_file"
        ["/etc/shadow"]="shadow_file"
    )

    for file in "${!critical_files[@]}"; do
        if [ ! -e "$file" ]; then
            send_status "$category" "fail" "$file does not exist" "${check_names[$file]}"
            failed=true
            continue
        fi

        local actual_perms
        actual_perms=$(stat -c "%a" "$file")

        if [ "$actual_perms" != "${critical_files[$file]}" ]; then
            send_status "$category" "fail" "$file permissions are incorrectly set to $actual_perms (expected ${critical_files[$file]})" "${check_names[$file]}"
            failed=true
        else
            send_status "$category" "pass" "$file permissions are correctly set to ${critical_files[$file]}" "${check_names[$file]}"
        fi
    done

    # Final status
    if $failed; then
        send_status "$category" "fail" "Some access control checks failed"
        return 1
    else
        send_status "$category" "pass" "All access control checks passed"
        return 0
    fi
}

check_unattended_upgrades() {
   local category="unattended_upgrades"
   local final_status="pass"
   local auto_upgrades_file="/etc/apt/apt.conf.d/20auto-upgrades"
   local update_enabled
   local upgrade_enabled

   send_status "$category" "running" "Checking automatic upgrades configuration"

   # Check if package is installed
   if ! dpkg -l | grep -q "unattended-upgrades"; then
       send_status "$category" "fail" "unattended-upgrades package is not installed" "installation"
       final_status="fail"
       return 1
   fi
   send_status "$category" "pass" "unattended-upgrades package is installed" "installation"

   # Check if service is running
   if ! systemctl is-active --quiet unattended-upgrades.service; then
       send_status "$category" "fail" "unattended-upgrades service is not running" "service_status"
       final_status="fail"
   else
       send_status "$category" "pass" "unattended-upgrades service is running" "service_status"
   fi

   # Check if automatic updates are enabled in /etc/apt/apt.conf.d/20auto-upgrades
   if [ ! -f "$auto_upgrades_file" ]; then
       send_status "$category" "fail" "Auto-upgrades config file not found" "config_file"
       send_status "$category" "skip" "Auto-upgrades file not present - skipping" "auto_update"
       send_status "$category" "skip" "Auto-upgrades file not present - skipping" "auto_upgrade"
       final_status="fail"
   else
       send_status "$category" "pass" "Auto-upgrades configuration file exists" "config_file"

       update_enabled=$(grep "APT::Periodic::Update-Package-Lists" "$auto_upgrades_file" | grep -o '[0-9]\+' || echo "0")
       upgrade_enabled=$(grep "APT::Periodic::Unattended-Upgrade" "$auto_upgrades_file" | grep -o '[0-9]\+' || echo "0")

       if [ "$update_enabled" = "0" ]; then
           send_status "$category" "fail" "Automatic package list updates are disabled" "auto_update"
           final_status="fail"
       else
           send_status "$category" "pass" "Automatic updates are enabled" "auto_update"
       fi

       if [ "$upgrade_enabled" = "0" ]; then
           send_status "$category" "fail" "Automatic upgrades are disabled" "auto_upgrade"
           final_status="fail"
       else
           send_status "$category" "pass" "Automatic upgrades are enabled" "auto_upgrade"
       fi
   fi

   # Final status
   if [ "$final_status" = "fail" ]; then
       send_status "$category" "fail" "Some automatic upgrades check failed"
       return 1
   else
       send_status "$category" "pass" "All automatic upgrade checks passed"
       return 0
   fi
}

check_port_security() {
    local category="port_security"
    local description="Checking open ports"
    send_status "$category" "running" "$description"

    local cmd
    local column
    if command -v ss >/dev/null 2>&1; then
        cmd="ss -tuln"
        column=5
    elif command -v netstat >/dev/null 2>&1; then
        cmd="netstat -tuln"
        column=4
    else
        send_status "$category" "error" "Neither 'ss' nor 'netstat' command found"
        return 1
    fi

    # Get list of listening ports
    local ports
    ports=$($cmd | grep 'LISTEN' | awk "{print \$$column}" | awk -F: '{print $NF}' | sort -u)

    declare -A insecure_ports=(
        [21]="FTP - Unencrypted file transfer"
        [23]="Telnet - Unencrypted remote access"
        [25]="SMTP - Unencrypted email transfer"
        [69]="TFTP - Trivial FTP, unencrypted"
        [111]="RPC - Remote procedure call"
        [135]="RPC - Windows RPC"
        [445]="SMB - File sharing"
        [3389]="RDP - Remote Desktop"
    )
    local -a ordered_ports=(21 23 25 69 111 135 445 3389)

    local failed=0

    for port in "${ordered_ports[@]}"; do
        local subcategory="port_${port}"
        local port_description="Checking port ${port} (${insecure_ports[$port]})"

        if echo "$ports" | grep -q "^${port}$"; then
            failed=1
            send_status "$category" "fail" "Port ${port} (${insecure_ports[$port]}) is open" "$subcategory"
        else
            send_status "$category" "pass" "Port ${port} is not open" "$subcategory"
        fi
    done

    if [ $failed -eq 1 ]; then
        send_status "$category" "fail" "Some port security checks failed"
        return 1
    else
        send_status "$category" "pass" "All port security checks passed"
        return 0
    fi
}

check_fail2ban() {
    local category="fail2ban"
    local failed=false
    local installation_failed=false
    local config_file_missing=false
    local ssh_enabled
    local ssh_mode

    send_status "$category" "running" "Checking fail2ban installation and configuration"

    # Check if package is installed - all other checks depend on this
    if ! dpkg -l | grep -q "fail2ban"; then
        send_status "$category" "fail" "fail2ban package is not installed" "installation"
        installation_failed=true
        failed=true
    else
        send_status "$category" "pass" "fail2ban package is installed" "installation"
    fi

    if ! $installation_failed; then
        # Check if service is enabled
        if ! systemctl is-enabled --quiet fail2ban.service; then
            send_status "$category" "fail" "fail2ban service is not enabled" "service_enabled"
            failed=true
        else
            send_status "$category" "pass" "fail2ban service is enabled" "service_enabled"
        fi

        # Check if service is running
        if ! systemctl is-active --quiet fail2ban.service; then
            send_status "$category" "fail" "fail2ban service is not running" "service_active"
            failed=true
        else
            send_status "$category" "pass" "fail2ban service is running" "service_active"
        fi

        # Check if jail.local exists - jail config depends on this
        if [ ! -f "/etc/fail2ban/jail.local" ]; then
            send_status "$category" "fail" "jail.local configuration file not found" "config_file"
            config_file_missing=true
            failed=true
        else
            send_status "$category" "pass" "jail.local configuration file exists" "config_file"
        fi

        # Check SSH jail configuration only if jail.local exists
       if ! $config_file_missing; then
           # Check if SSH jail is enabled
           ssh_enabled=$(grep -A10 "^\[sshd\]" /etc/fail2ban/jail.local | grep -m 1 "enabled" | awk '{print $NF}' | tr -d '[:space:]')
           if [ "$ssh_enabled" != "true" ]; then
               send_status "$category" "fail" "SSH jail is not enabled" "ssh_jail_enabled"
               failed=true
           else
               send_status "$category" "pass" "SSH jail is enabled" "ssh_jail_enabled"
           fi

           # Check if mode is aggressive
           ssh_mode=$(grep -A10 "^\[sshd\]" /etc/fail2ban/jail.local | grep -m 1 "^mode[[:space:]]*=[[:space:]]*aggressive" >/dev/null && echo "aggressive" || echo "")
           if [ "$ssh_mode" != "aggressive" ]; then
               send_status "$category" "fail" "SSH jail is not in aggressive mode" "ssh_jail_mode"
               failed=true
           else
               send_status "$category" "pass" "SSH jail is in aggressive mode" "ssh_jail_mode"
           fi
       else
           send_status "$category" "skip" "jail.local file not present - skipping" "ssh_jail_enabled"
           send_status "$category" "skip" "jail.local file not present - skipping" "ssh_jail_mode"
       fi
    else
        # Skip all remaining checks if installation failed
        send_status "$category" "skip" "fail2ban not installed - skipping" "service_enabled"
        send_status "$category" "skip" "fail2ban not installed - skipping" "service_active"
        send_status "$category" "skip" "fail2ban not installed - skipping" "config_file"
        send_status "$category" "skip" "fail2ban not installed - skipping" "ssh_jail_enabled"
        send_status "$category" "skip" "fail2ban not installed - skipping" "ssh_jail_mode"
    fi

    # Final status
    if $failed; then
        send_status "$category" "fail" "Some fail2ban security checks failed"
        return 1
    else
        send_status "$category" "pass" "All fail2ban checks passed"
        return 0
    fi
}

main() {
    check_os
    check_dependencies

    local failed=0

    send_status "audit" "running" "Starting security audit v${VERSION}"

    check_non_root_user || failed=1
    check_ufw || failed=1
    check_ssh || failed=1
    check_fail2ban || failed=1
    check_access_control || failed=1
    check_port_security || failed=1
    check_unattended_upgrades || failed=1

    send_status "audit" "pass" "Security audit complete"

    if [ $failed -eq 1 ]; then
        echo -e "\n${RED}Audit completed with failures${NC}"
        exit 1
    else
        echo -e "\n${GREEN}All checks passed!${NC}"
        exit 0
    fi
}

main "$@"