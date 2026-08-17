# vps-audit

Scans your server to find common issues like weak SSH settings, missing firewalls, lack of updates, and more. Perfect for getting your VPS ready for production.

## Usage

1. Download the script

```bash
$ curl -O https://raw.githubusercontent.com/mattsafaii/vps-audit/main/audit.sh
```

2. Make it executable:

```bash
$ chmod +x audit.sh
```

3. Run the security audit:

```bash
$ sudo ./audit.sh
```

## Requirements

- Ubuntu/Debian-based distributions
- Root or sudo privileges

## Security checks

The script performs the following checks:

- Root
  - Check that a non-root sudo user exists
- Firewall (UFW)
  - Check that UFW is installed
  - Check that UFW is active
  - Check that incoming traffic is denied by default
  - Check that the SSH port is allowed (so a "pass" can't hide a firewall that blocks you out)
- SSH
  - Check that SSH is active (including socket-activated `ssh.socket`)
  - Check that key-based authentication is set up for every login user with non-writable permissions
  - Check that root login is disabled
  - Check that password and keyboard-interactive authentication are disabled
- Fail2Ban
  - Check that Fail2ban is installed
  - Check that Fail2ban is enabled and running
  - Check that the SSH jail is enabled
  - Check that the SSH jail is in aggressive mode
- Access control
  - Check that `/etc/passwd` is readable by everyone
  - Check that `/etc/shadow` is readable by root only
- System updates
  - Check that automatic package list updates are enabled
  - Check that automatic system upgrades are enabled
- Port security
  - Check that insecure ports are not open