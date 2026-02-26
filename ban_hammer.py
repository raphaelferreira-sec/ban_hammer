#!/usr/bin/env python3

# Script to monitor SSH logs for suspicious activities and block offending IPs

import subprocess
import re
import sys
import os
import logging
import ipaddress
import argparse
from collections import Counter
from logging.handlers import RotatingFileHandler

# ==================== CONFIGURATION ====================
''' Time period for journalctl --since
Use dash-prefix format: "-1d", "-2h", "-30m"
Or natural language:    "1 day ago", "2 hours ago"
Or named keywords:      "yesterday", "today" '''
JOURNALCTL_PERIOD = "-1d"

# SSH service name
SSH_SERVICE = "ssh"  # Could also be "sshd" on some systems

# Attempt threshold - block IP if attempts are >= this number
ATTEMPT_THRESHOLD = 1

# Logging configuration
LOG_FILE = "/var/log/ban_hammer.log"
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# Silent mode (set to True to suppress console output)
SILENT_MODE = False
# =======================================================

# Patterns to match — compiled once at module load for performance
_RAW_PATTERNS = [
    r"Connection closed by authenticating user.*?(\d+\.\d+\.\d+\.\d+)",
    r"invalid user.*?(\d+\.\d+\.\d+\.\d+)",
    r"Connection reset by.*?(\d+\.\d+\.\d+\.\d+)",
    r"Failed password.*?(\d+\.\d+\.\d+\.\d+)",
    r"Disconnected from authenticating user.*?(\d+\.\d+\.\d+\.\d+)",
]
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _RAW_PATTERNS]


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(silent: bool = False) -> logging.Logger:
    # Configure rotating file logger, with optional console handler.
    logger = logging.getLogger("ban_hammer")
    logger.setLevel(logging.DEBUG)

    # Clear existing handlers to avoid duplicates on reconfiguration
    if logger.handlers:
        logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_SIZE,
        backupCount=LOG_BACKUP_COUNT,
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if not silent:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger


logger = setup_logging(SILENT_MODE)


def log_message(level: str, message: str) -> None:
    # Dispatch a log message at the given level.
    getattr(logger, level, logger.info)(message)


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def run_command(command: list[str], silent: bool = False) -> tuple[bool, str]:
    """
    Execute a command (as a list — no shell=True) and return (success, stdout).

    Returns (False, "") on failure so callers can distinguish empty-output
    success from an actual error.
    """
    try:
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stderr and not silent:
            log_message("warning", f"Command stderr: {result.stderr.strip()}")
        return True, result.stdout.strip()
    except FileNotFoundError:
        log_message("error", f"Command not found: {command[0]}")
        return False, ""
    except subprocess.CalledProcessError as e:
        log_message("error", f"Command failed: {' '.join(command)}")
        log_message("error", f"Stderr: {e.stderr.strip()}")
        return False, ""


# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------

def is_valid_ip(ip: str) -> bool:
    # Return True only for well-formed IPv4/IPv6 addresses.
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def get_ssh_logs() -> str:
    # Fetch SSH log lines from journalctl.
    log_message("info", f"Fetching logs since: {JOURNALCTL_PERIOD}")
    ok, output = run_command(
        ["journalctl", "-u", SSH_SERVICE, "--since", JOURNALCTL_PERIOD],
        silent=True,
    )
    return output if ok else ""


def extract_ips(logs: str) -> list[str]:
    # Extract and validate IP addresses from log lines using pre-compiled patterns.
    if not logs:
        return []

    ips: list[str] = []
    for line in logs.splitlines():
        for pattern in COMPILED_PATTERNS:
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                if is_valid_ip(ip):
                    ips.append(ip)
                else:
                    log_message("warning", f"Skipping invalid IP extracted from log: {ip!r}")
                break  # Only one match per line needed

    log_message("info", f"Extracted {len(ips)} valid IP entries from logs")
    return ips


def count_attempts(ip_list: list[str]) -> tuple[Counter, list[str]]:
    # Count attempts per IP and return those meeting the threshold.
    ip_counter: Counter = Counter(ip_list)

    for ip, count in ip_counter.most_common():
        log_message("debug", f"IP {ip}: {count} attempt(s)")

    qualified_ips = [ip for ip, count in ip_counter.items() if count >= ATTEMPT_THRESHOLD]
    log_message("info", f"Found {len(qualified_ips)} IP(s) with >= {ATTEMPT_THRESHOLD} attempts")
    return ip_counter, qualified_ips


def get_current_iptables_rules() -> list[dict]:
    # Return a list of existing DROP rules with their source IPs and line numbers.
    ok, output = run_command(["iptables", "-L", "INPUT", "-v", "-n", "--line-numbers"], silent=True)
    if not ok or not output:
        return []

    drop_rules: list[dict] = []
    for line in output.splitlines():
        if "DROP" in line and "all" in line:
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                if not is_valid_ip(ip):
                    continue
                line_num_match = re.search(r"^(\d+)", line.strip())
                drop_rules.append({
                    "ip": ip,
                    "line": line_num_match.group(1) if line_num_match else None,
                    "full_line": line,
                })

    log_message("debug", f"Found {len(drop_rules)} existing DROP rule(s)")
    return drop_rules


def add_iptables_drop(ip: str) -> bool:
    # Insert a DROP rule for the given IP at position 1 of the INPUT chain.
    if not is_valid_ip(ip):
        log_message("error", f"Refusing to block invalid IP: {ip!r}")
        return False

    ok, _ = run_command(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], silent=True)
    if ok:
        log_message("info", f"DROP rule added for {ip}")
    else:
        log_message("error", f"Failed to add DROP rule for {ip}")
    return ok


def save_iptables() -> bool:
    # Persist iptables rules via netfilter-persistent.
    ok, _ = run_command(["netfilter-persistent", "save"], silent=True)
    if ok:
        log_message("info", "iptables rules saved successfully")
    else:
        log_message("error", "Failed to save iptables rules")
    return ok


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _pad(text: str, width: int) -> str:
    # Pad plain text (strip ANSI before measuring) to the given column width.
    plain = re.sub(r"\033\[[0-9;]*m", "", text)
    return text + " " * max(0, width - len(plain))


def display_table(
    ip_counter: Counter,
    blocked_set: set[str],
    new_ips: list[str],
    silent: bool = False,
) -> None:
    # Print a formatted, properly aligned summary table to stdout.
    if silent:
        return

    new_set = set(new_ips)
    sep = "=" * 80

    print("\n" + sep)
    print(f"SSH LOG ANALYSIS  |  Period: {JOURNALCTL_PERIOD}  |  Threshold: >= {ATTEMPT_THRESHOLD}")
    print(sep)

    if not ip_counter:
        print("No suspicious IPs found in the logs.")
        print(sep)
        return

    print(f"\n{'IP Address':<20} {'Attempts':<12} {'Status':<20} Action")
    print("-" * 80)

    for ip, count in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True):
        already = ip in blocked_set

        if ip in new_set:
            status      = "Not Blocked"
            status_col  = f"\033[93m{status}\033[0m"
            action_col  = f"\033[92mBLOCKED (>= {ATTEMPT_THRESHOLD})\033[0m"
        elif already:
            status      = "Already Blocked"
            status_col  = f"\033[91m{status}\033[0m"
            action_col  = "—"
        else:
            status      = "Not Blocked"
            status_col  = status
            action_col  = f"\033[90mBelow threshold (< {ATTEMPT_THRESHOLD})\033[0m"

        print(f"{ip:<20} {count:<12} {_pad(status_col, 20)} {action_col}")

    print(sep)
    print(f"Total unique IPs     : {len(ip_counter)}")
    print(f"Meeting threshold    : {sum(1 for c in ip_counter.values() if c >= ATTEMPT_THRESHOLD)}")
    print(f"Already blocked      : {len(blocked_set)}")
    print(f"New blocks this run  : {len(new_ips)}")
    print(sep)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if os.geteuid() != 0:
        log_message("error", "Script must be run as root (sudo)")
        sys.exit(1)

    log_message(
        "info",
        f"=== SSH Blocker started  threshold={ATTEMPT_THRESHOLD}  period='{JOURNALCTL_PERIOD}' ===",
    )

    # 1. Fetch logs
    if not SILENT_MODE:
        print("1. Fetching SSH logs...")
    logs = get_ssh_logs()
    if not logs:
        log_message("warning", "No logs returned from journalctl")
        if not SILENT_MODE:
            print("   No logs found or error accessing journalctl.")
        sys.exit(0)

    # 2. Extract IPs
    if not SILENT_MODE:
        print("2. Extracting IP addresses...")
    ips = extract_ips(logs)
    if not ips:
        log_message("info", "No patterns matched in logs")
        if not SILENT_MODE:
            print("   No matching patterns found in the logs.")
        sys.exit(0)

    # 3. Count & filter
    if not SILENT_MODE:
        print(f"3. Counting attempts (threshold >= {ATTEMPT_THRESHOLD})...")
    ip_counter, qualified_ips = count_attempts(ips)

    # 4. Current iptables state — use a set for O(1) lookup
    if not SILENT_MODE:
        print("4. Checking current iptables rules...")
    current_rules = get_current_iptables_rules()
    blocked_set: set[str] = {rule["ip"] for rule in current_rules}

    # 5. New IPs to block
    if not SILENT_MODE:
        print("5. Identifying new IPs to block...")
    new_ips_to_block = [ip for ip in qualified_ips if ip not in blocked_set]

    # 6. Display table
    display_table(ip_counter, blocked_set, new_ips_to_block, silent=SILENT_MODE)

    # 7. Apply new DROP rules
    if new_ips_to_block:
        if not SILENT_MODE:
            print("\n6. Adding new DROP rules...")
        added = sum(
            1
            for ip in new_ips_to_block
            if add_iptables_drop(ip)
        )
        log_message("info", f"Added {added}/{len(new_ips_to_block)} DROP rule(s)")

        # 8. Persist
        if added > 0:
            if not SILENT_MODE:
                print("7. Saving iptables rules...")
            if not save_iptables():
                log_message("error", "Rules were added but could not be persisted")
        else:
            log_message("warning", "No rules were actually inserted despite qualified IPs")
    else:
        log_message("info", "No new IPs to block")
        if not SILENT_MODE:
            print("\n6. No new IPs to block.")

    log_message(
    "info",
    f"=== SSH Blocker finished  total_attempts={len(ips)} ===",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH log analyser and IP blocker")
    parser.add_argument("--silent",    action="store_true", help="Suppress console output")
    parser.add_argument("--threshold", type=int,            help=f"Attempt threshold (default: {ATTEMPT_THRESHOLD})")
    parser.add_argument(
    "--period",
    type=str,
    help='journalctl --since value. E.g: "-1d", "-2h", "-30m", "yesterday"'
    )
    args = parser.parse_args()

    if args.silent:
        SILENT_MODE = True
        logger = setup_logging(silent=True)   # reconfigure without duplicate handlers

    if args.threshold is not None:
        ATTEMPT_THRESHOLD = args.threshold
        log_message("info", f"Threshold overridden to {ATTEMPT_THRESHOLD}")

    if args.period is not None:
        JOURNALCTL_PERIOD = args.period
        log_message("info", f"Period overridden to '{JOURNALCTL_PERIOD}'")

    main()