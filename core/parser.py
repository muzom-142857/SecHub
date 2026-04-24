import re
from typing import Any


def parse_nmap(stdout: str) -> dict[str, Any]:
    """Parse nmap stdout into a structured dict of ports, OS, and hostname."""
    result: dict[str, Any] = {"ports": [], "os": None, "hostname": None}

    for line in stdout.splitlines():
        # Port line: "22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu"
        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?", line
        )
        if port_match:
            result["ports"].append({
                "port": int(port_match.group(1)),
                "protocol": port_match.group(2),
                "state": port_match.group(3),
                "service": port_match.group(4),
                "version": port_match.group(5).strip() if port_match.group(5) else None,
            })
            continue

        os_match = re.search(r"OS details?:\s*(.+)", line)
        if os_match:
            result["os"] = os_match.group(1).strip()
            continue

        host_match = re.search(r"Nmap scan report for (.+)", line)
        if host_match:
            result["hostname"] = host_match.group(1).strip()

    return result


def parse_whois(stdout: str) -> dict[str, Any]:
    """Parse whois stdout into a structured dict of registration fields."""
    result: dict[str, Any] = {}
    # Maps whois field prefixes to normalised key names
    field_map: dict[str, str] = {
        "Registrar": "registrar",
        "Registrant Organization": "org",
        "Creation Date": "created",
        "Updated Date": "updated",
        "Expiry Date": "expires",
        "Name Server": "nameservers",
    }
    nameservers: list[str] = []

    for line in stdout.splitlines():
        for prefix, key in field_map.items():
            if line.lower().startswith(prefix.lower()):
                value = line.split(":", 1)[-1].strip()
                if key == "nameservers":
                    nameservers.append(value)
                else:
                    result[key] = value

    if nameservers:
        result["nameservers"] = nameservers

    return result


def parse_searchsploit(stdout: str) -> list[dict[str, Any]]:
    """Parse searchsploit stdout into a list of {title, path} dicts.

    searchsploit output has the structure:
      <separator>
      <header row>   ← skip
      <separator>
      <data rows>    ← parse these
      <separator>

    Data rows sit between the 2nd and 3rd separator lines.
    """
    results: list[dict[str, Any]] = []
    sep_count = 0

    for line in stdout.splitlines():
        if re.match(r"-{5,}", line.strip()):
            sep_count += 1
            continue
        # Data section is between the 2nd and 3rd separator
        if sep_count != 2 or not line.strip():
            continue

        parts = re.split(r"\s+\|\s+", line, maxsplit=1)
        if len(parts) == 2:
            title, path = parts[0].strip(), parts[1].strip()
            if title and path:
                results.append({"title": title, "path": path})

    return results


def parse_nikto(stdout: str) -> list[dict[str, Any]]:
    """Parse nikto stdout; each finding starts with '+ '."""
    findings: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if line.startswith("+ ") and ":" in line:
            findings.append({"finding": line[2:].strip()})
    return findings


def score_exploits(
    exploits: list[dict[str, Any]],
    service: str,
    version: str | None,
    os_hint: str | None = None,
) -> list[dict[str, Any]]:
    """Score and sort searchsploit results by relevance.

    Scoring criteria (additive):
    - Exact version string found in title: +10
    - Service name found in title: +3
    - Platform matches detected OS: +5
    - Title contains 'remote': +2
    """
    platform_keywords: dict[str, list[str]] = {
        "linux": ["linux", "unix", "lnx"],
        "windows": ["windows", "win", "dos"],
    }
    os_platform: str | None = None
    if os_hint:
        hint_lower = os_hint.lower()
        for platform, keywords in platform_keywords.items():
            if any(k in hint_lower for k in keywords):
                os_platform = platform
                break

    # Normalise version string for partial matching (e.g. "Apache httpd 2.4.49" → "2.4.49")
    version_tokens: list[str] = []
    if version:
        version_tokens = [t for t in re.split(r"[\s/]", version) if t]

    scored: list[dict[str, Any]] = []
    for exploit in exploits:
        title_lower = exploit["title"].lower()
        score = 0

        if version_tokens and any(t.lower() in title_lower for t in version_tokens):
            score += 10
        elif service.lower() in title_lower:
            score += 3

        if os_platform and any(k in title_lower for k in platform_keywords[os_platform]):
            score += 5

        if "remote" in title_lower:
            score += 2

        scored.append({**exploit, "score": score})

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored
