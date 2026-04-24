from phases.common import Tool, build_command  # noqa: F401 — re-exported for callers


BASIC_TOOLS: list[Tool] = [
    Tool(
        id="whois",
        label="whois",
        command_template="whois {target}",
        description="Retrieve domain/IP registration information",
    ),
    Tool(
        id="nmap_fast",
        label="nmap (fast scan)",
        command_template="nmap -T4 -F {target}",
        description="Quick scan of the most common ports",
    ),
    Tool(
        id="nmap_svc",
        label="nmap (service/version)",
        command_template="nmap -sV -sC {target}",
        description="Detect service names and version strings per port",
    ),
    Tool(
        id="nmap_os",
        label="nmap (OS detection)",
        command_template="sudo nmap -O {target}",
        description="Fingerprint the target operating system",
    ),
]

OPTIONAL_TOOLS: list[Tool] = [
    Tool(
        id="gobuster",
        label="gobuster",
        command_template="gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
        description="Web directory enumeration",
        optional=True,
        condition="port_web",
    ),
    Tool(
        id="dnsenum",
        label="dnsenum",
        command_template="dnsenum {target}",
        description="DNS record enumeration",
        optional=True,
        condition="domain_target",
    ),
    Tool(
        id="enum4linux",
        label="enum4linux",
        command_template="enum4linux -a {target}",
        description="SMB/NetBIOS information gathering",
        optional=True,
        condition="port_smb",
    ),
    Tool(
        id="smtp_user_enum",
        label="smtp-user-enum",
        command_template="smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {target}",
        description="SMTP user enumeration via VRFY",
        optional=True,
        condition="port_smtp",
    ),
]


def get_tools(target: str, open_ports: set[int] | None = None) -> list[Tool]:
    """Return the tool list for Phase 1 based on target type and detected ports.

    When open_ports is None (before any scan), only basic tools are returned.
    Optional tools are appended once port data is available.
    """
    tools = list(BASIC_TOOLS)

    if open_ports is None:
        return tools

    conditions: dict[str, bool] = {
        "port_web": bool(open_ports & {80, 443, 8080, 8443}),
        "port_smb": bool(open_ports & {445, 139}),
        "port_smtp": bool(open_ports & {25, 587}),
        "domain_target": not target.replace(".", "").isdigit(),
    }

    for tool in OPTIONAL_TOOLS:
        if tool.condition and conditions.get(tool.condition, False):
            tools.append(tool)

    return tools
