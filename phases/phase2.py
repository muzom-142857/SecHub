import httpx
from typing import Any

from phases.common import Tool


BASIC_TOOLS: list[Tool] = [
    Tool(
        id="searchsploit",
        label="searchsploit",
        command_template="searchsploit {query}",
        description="Search ExploitDB; results sorted by relevance score",
        requires_input=["query"],
    ),
]

OPTIONAL_TOOLS: list[Tool] = [
    Tool(
        id="nikto",
        label="nikto",
        command_template="nikto -h {target}",
        description="Web vulnerability scanner",
        optional=True,
        condition="port_web",
    ),
    Tool(
        id="whatweb",
        label="whatweb",
        command_template="whatweb {target}",
        description="Identify web technologies and frameworks",
        optional=True,
        condition="port_web",
    ),
    Tool(
        id="nmap_http_vuln",
        label="nmap (http-vuln)",
        command_template="nmap --script http-vuln-* -p 80,443 {target}",
        description="HTTP vulnerability scripts — LFI, shellshock, CVE checks",
        optional=True,
        condition="port_web",
    ),
    Tool(
        id="nmap_smb_vuln",
        label="nmap (smb-vuln)",
        command_template="nmap --script smb-vuln-* -p 445 {target}",
        description="SMB vulnerability scan (EternalBlue, MS17-010, etc.)",
        optional=True,
        condition="port_smb",
    ),
    Tool(
        id="smbmap",
        label="smbmap",
        command_template="smbmap -H {target}",
        description="Map SMB shares and permissions — identifies writable shares",
        optional=True,
        condition="port_smb",
    ),
    Tool(
        id="nmap_ftp_anon",
        label="nmap (ftp-anon)",
        command_template="nmap --script ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor -p 21 {target}",
        description="Check anonymous FTP access and known FTP backdoors",
        optional=True,
        condition="port_ftp",
    ),
    Tool(
        id="nmap_mysql",
        label="nmap (mysql)",
        command_template="nmap --script mysql-info,mysql-empty-password -p 3306 {target}",
        description="MySQL information gathering and empty-password check",
        optional=True,
        condition="port_mysql",
    ),
    Tool(
        id="nmap_distcc_vuln",
        label="nmap (distcc RCE)",
        command_template="nmap --script distcc-cve2004-2687 -p 3632 {target}",
        description="Confirm distccd RCE — CVE-2004-2687 (common HTB Lame path)",
        optional=True,
        condition="port_distcc",
    ),
    Tool(
        id="nmap_nfs_vuln",
        label="nmap (nfs-ls)",
        command_template="nmap --script nfs-ls,nfs-statfs -p 2049 {target}",
        description="List NFS share contents — may expose world-readable sensitive files",
        optional=True,
        condition="port_nfs",
    ),
]


def get_tools(open_ports: set[int]) -> list[Tool]:
    """Return Phase 2 tools based on which ports are open."""
    tools = list(BASIC_TOOLS)
    conditions: dict[str, bool] = {
        "port_web": bool(open_ports & {80, 443, 8080, 8443}),
        "port_smb": bool(open_ports & {445, 139}),
        "port_ftp": bool(open_ports & {21}),
        "port_mysql": bool(open_ports & {3306}),
        "port_distcc": bool(open_ports & {3632}),
        "port_nfs": bool(open_ports & {2049}),
    }
    for tool in OPTIONAL_TOOLS:
        if tool.condition and conditions.get(tool.condition, False):
            tools.append(tool)
    return tools


async def lookup_nvd(service: str, version: str) -> list[dict[str, Any]]:
    """Query the NIST NVD API and return CVE entries sorted by CVSS score descending."""
    query = f"{service} {version}".strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": 10}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return []

    results: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_score: float | None = None
        cvss_vector: str | None = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                break

        results.append({
            "cve_id": cve_id,
            "description": desc,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
        })

    results.sort(key=lambda x: x.get("cvss_score") or 0.0, reverse=True)
    return results
