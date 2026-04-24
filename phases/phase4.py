import re
from typing import Any

from phases.common import Tool


BASIC_TOOLS: list[Tool] = [
    Tool(
        id="sysinfo",
        label="System info",
        command_template="whoami && id && uname -a && hostname && ip addr",
        description="Collect current user, privileges, OS, and network info",
    ),
    Tool(
        id="sudo_check",
        label="sudo privileges",
        command_template="sudo -l",
        description="List commands the current user can run via sudo",
    ),
    Tool(
        id="suid_check",
        label="SUID binaries",
        command_template="find / -perm -4000 -type f 2>/dev/null",
        description="Find SUID binaries — common privilege escalation vectors",
    ),
    Tool(
        id="process_list",
        label="Process list",
        command_template="ps aux",
        description="List all running processes",
    ),
    Tool(
        id="network_info",
        label="Internal network",
        command_template="netstat -tulnp 2>/dev/null || ss -tulnp",
        description="Show open ports and internal services",
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
    """Return Phase 4 tools; hash-cracking tools are added only when hashes exist."""
    tools = list(BASIC_TOOLS)
    if result_store.get("phase4", {}).get("hashes"):
        tools.extend(OPTIONAL_TOOLS)
    return tools
