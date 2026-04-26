import re
from typing import Any

from phases.common import Tool


BASIC_TOOLS: list[Tool] = [
    Tool(
        id="sysinfo",
        label="System info",
        command_template="whoami && id && uname -a && hostname && ip addr",
        description="Collect current user, privileges, OS, and network info",
        timeout=15,
    ),
    Tool(
        id="sudo_check",
        label="sudo privileges",
        command_template="sudo -l",
        description="List commands the current user can run via sudo",
        timeout=10,
    ),
    Tool(
        id="suid_check",
        label="SUID binaries",
        command_template="find / -perm -4000 -type f 2>/dev/null",
        description="Find SUID binaries — common privilege escalation vectors",
        timeout=60,
    ),
    Tool(
        id="capabilities",
        label="Linux capabilities",
        command_template="getcap -r / 2>/dev/null",
        description="Find binaries with elevated capabilities — often exploitable for PE",
        timeout=30,
    ),
    Tool(
        id="cron_enum",
        label="Cron jobs",
        command_template=(
            "cat /etc/crontab 2>/dev/null; "
            "ls -la /etc/cron.* 2>/dev/null; "
            "cat /etc/cron.d/* 2>/dev/null; "
            "crontab -l 2>/dev/null; "
            "find /var/spool/cron -readable 2>/dev/null"
        ),
        description="Enumerate cron jobs — writable scripts run by cron are a PE path (HTB Bashed)",
        timeout=15,
    ),
    Tool(
        id="writable_check",
        label="Writable paths",
        command_template=(
            "find / -writable -not -path '*/proc/*' -not -path '*/sys/*' "
            "-not -path '*/dev/*' 2>/dev/null | grep -v snap | head -40"
        ),
        description="Find world-writable files and directories — PATH hijack, cron abuse",
        timeout=60,
    ),
    Tool(
        id="process_list",
        label="Process list",
        command_template="ps aux",
        description="List all running processes",
        timeout=10,
    ),
    Tool(
        id="network_info",
        label="Internal network",
        command_template="netstat -tulnp 2>/dev/null || ss -tulnp",
        description="Show open ports and internal services",
        timeout=10,
    ),
    Tool(
        id="nfs_check",
        label="NFS exports",
        command_template="showmount -e localhost 2>/dev/null; cat /etc/exports 2>/dev/null",
        description="Check NFS exports — no_root_squash misconfiguration enables root PE",
        timeout=15,
    ),
    Tool(
        id="env_check",
        label="Environment variables",
        command_template="env; cat /etc/environment 2>/dev/null; echo $PATH",
        description="Check env vars and PATH — LD_PRELOAD or PATH hijack may be possible",
        timeout=10,
    ),
    Tool(
        id="interesting_files",
        label="Interesting files",
        command_template=(
            "find / -name '*.bak' -o -name '*.backup' -o -name 'id_rsa' "
            "-o -name '.htpasswd' -o -name 'wp-config.php' -o -name '*.kdbx' "
            "2>/dev/null | grep -v proc | head -30"
        ),
        description="Search for backup files, SSH keys, password files — often contain credentials",
        timeout=60,
    ),
    Tool(
        id="cred_hunt",
        label="Credential hunt",
        command_template=(
            "cat /etc/passwd; "
            "cat ~/.bash_history 2>/dev/null; "
            "find / -name '*.conf' -readable 2>/dev/null | head -20"
        ),
        description="Search config files and shell history for credentials",
        timeout=30,
    ),
]

OPTIONAL_TOOLS: list[Tool] = [
    Tool(
        id="john",
        label="john (hash cracking)",
        command_template="john --wordlist={wordlist} {hashfile}",
        description="Crack password hashes with John the Ripper",
        optional=True,
        condition="hash_detected",
        requires_input=["wordlist", "hashfile"],
    ),
    Tool(
        id="hashcat",
        label="hashcat (hash cracking)",
        command_template="hashcat -m {mode} {hashfile} {wordlist}",
        description="GPU-accelerated hash cracking with hashcat",
        optional=True,
        condition="hash_detected",
        requires_input=["mode", "hashfile", "wordlist"],
    ),
    Tool(
        id="linpeas",
        label="linpeas.sh (auto PE enum)",
        command_template="bash {linpeas_path}",
        description="Automated Linux privilege escalation enumeration — upload manually first",
        optional=True,
        condition="linpeas_available",
        requires_input=["linpeas_path"],
    ),
    Tool(
        id="winpeas",
        label="winpeas.exe (auto PE enum)",
        command_template="{winpeas_path}",
        description="Automated Windows privilege escalation enumeration — upload manually first",
        optional=True,
        condition="winpeas_available",
        requires_input=["winpeas_path"],
    ),
]

# Ordered from most specific to most generic for correct first-match behaviour
HASH_PATTERNS: list[tuple[str, str, str]] = [
    (r"^\$6\$", "sha512crypt", "1800"),
    (r"^\$5\$", "sha256crypt", "7400"),
    (r"^\$1\$", "md5crypt", "500"),
    (r"^\$2[aby]\$", "bcrypt", "3200"),
    (r"^[a-f0-9]{32}$", "MD5", "0"),
    (r"^[a-f0-9]{40}$", "SHA1", "100"),
    (r"^[a-f0-9]{64}$", "SHA256", "1400"),
]


def detect_hash_type(hash_str: str) -> tuple[str, str] | None:
    """Return (hash_name, hashcat_mode) for a recognised hash, or None."""
    for pattern, name, mode in HASH_PATTERNS:
        if re.match(pattern, hash_str.strip(), re.IGNORECASE):
            return name, mode
    return None


def get_tools(result_store: dict[str, Any]) -> list[Tool]:
    """Return Phase 4 tools; optional tools are gated by runtime conditions."""
    tools = list(BASIC_TOOLS)
    phase4 = result_store.get("phase4", {})
    has_hashes = bool(phase4.get("hashes"))
    for tool in OPTIONAL_TOOLS:
        if tool.condition == "hash_detected" and has_hashes:
            tools.append(tool)
        elif tool.condition in ("linpeas_available", "winpeas_available"):
            tools.append(tool)
    return tools
