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
        id="gobuster_vhost",
        label="gobuster (vhost)",
        command_template="gobuster vhost -u http://{target} -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain",
        description="Virtual host enumeration — finds hidden subdomains",
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
        id="smbclient_list",
        label="smbclient (null session)",
        command_template="smbclient -L //{target} -N",
        description="List SMB shares via null session — checks anonymous access",
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
    Tool(
        id="nmap_distcc",
        label="nmap (distcc-cve2004-2687)",
        command_template="nmap --script distcc-cve2004-2687 -p 3632 {target}",
        description="Check distccd RCE — CVE-2004-2687 (HTB Lame vector)",
        optional=True,
        condition="port_distcc",
    ),
    Tool(
        id="nmap_rpcinfo",
        label="nmap (rpcinfo)",
        command_template="nmap --script rpcinfo -p 111 {target}",
        description="Enumerate RPC services — reveals NFS, mountd, etc.",
        optional=True,
        condition="port_rpc",
    ),
    Tool(
        id="nmap_nfs",
        label="nmap (nfs-showmount)",
        command_template="nmap --script nfs-showmount -p 2049 {target}",
        description="List NFS exports — misconfigured shares may allow direct mount",
        optional=True,
        condition="port_nfs",
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
        "port_distcc": bool(open_ports & {3632}),
        "port_rpc": bool(open_ports & {111}),
        "port_nfs": bool(open_ports & {2049}),
        "domain_target": not target.replace(".", "").isdigit(),
    }

    for tool in OPTIONAL_TOOLS:
        if tool.condition and conditions.get(tool.condition, False):
            tools.append(tool)

    return tools
