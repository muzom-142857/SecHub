import re
from typing import Any


def parse_nmap(stdout: str) -> dict[str, Any]:
    """Parse nmap stdout into a structured dict of ports, OS, and hostname."""
    result: dict[str, Any] = {"ports": [], "os": None, "hostname": None}

    for line in stdout.splitlines():
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
    """Parse searchsploit stdout into a list of {title, path} dicts."""
    results: list[dict[str, Any]] = []
    sep_count = 0

    for line in stdout.splitlines():
        if re.match(r"-{5,}", line.strip()):
            sep_count += 1
            continue
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


def parse_gobuster(stdout: str) -> list[dict[str, Any]]:
    """Parse gobuster dir/vhost output into a list of discovered path entries."""
    results: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        # /admin (Status: 301) [Size: 313] [--> /admin/]
        m = re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)", line)
        if m:
            results.append({"path": m.group(1), "status": int(m.group(2))})
    return results


def parse_whatweb(stdout: str) -> list[dict[str, Any]]:
    """Parse whatweb stdout into detected URL/technology pairs."""
    results: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip() or line.startswith("ERROR"):
            continue
        # http://target [200 OK] Apache[2.4.49], PHP[8.0]...
        url_match = re.match(r"(https?://\S+)\s+\[(\d+)", line)
        if url_match:
            techs = re.findall(r"([\w][\w.\-/]+)\[([^\]]+)\]", line)
            results.append({
                "url": url_match.group(1),
                "status": int(url_match.group(2)),
                "technologies": [{"name": t[0], "version": t[1]} for t in techs],
            })
    return results


def parse_enum4linux(stdout: str) -> dict[str, Any]:
    """Extract users, shares, and OS info from enum4linux output."""
    result: dict[str, Any] = {"users": [], "shares": [], "os": None}
    in_users = False
    in_shares = False

    for line in stdout.splitlines():
        # OS detection line
        os_match = re.search(r"OS=\[([^\]]+)\]", line)
        if os_match:
            result["os"] = os_match.group(1)

        # User enumeration section
        if "user:" in line.lower() and "rid" in line.lower():
            in_users = True
        if in_users:
            user_match = re.search(r"user:\[(\w+)\]", line, re.IGNORECASE)
            if user_match:
                user = user_match.group(1)
                if user not in result["users"]:
                    result["users"].append(user)

        # Share enumeration section
        if "Sharename" in line:
            in_shares = True
            continue
        if in_shares and re.match(r"\s*\w+\s+Disk", line):
            share_match = re.match(r"\s*(\S+)\s+Disk", line)
            if share_match:
                result["shares"].append(share_match.group(1))
        elif in_shares and line.strip() == "":
            in_shares = False

    return result


def parse_hydra(stdout: str) -> list[dict[str, str]]:
    """Parse hydra output for successfully found credentials."""
    creds: list[dict[str, str]] = []
    for line in stdout.splitlines():
        # [22][ssh] host: 10.10.10.1   login: admin   password: password123
        m = re.search(
            r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
            line,
        )
        if m:
            creds.append({
                "port": m.group(1),
                "service": m.group(2),
                "host": m.group(3),
                "login": m.group(4),
                "password": m.group(5),
            })
    return creds


def parse_sqlmap(stdout: str) -> list[str]:
    """Extract database names from sqlmap enumeration output."""
    databases: list[str] = []
    in_databases = False
    for line in stdout.splitlines():
        if "available databases" in line.lower():
            in_databases = True
            continue
        if in_databases:
            m = re.match(r"\[\*\]\s+(.+)", line.strip())
            if m:
                databases.append(m.group(1).strip())
            elif line.strip() and not line.strip().startswith("["):
                in_databases = False
    return databases


def parse_sysinfo(stdout: str) -> dict[str, str]:
    """Extract user, kernel, and group info from combined sysinfo command output."""
    result: dict[str, str] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # id output: uid=33(www-data) gid=33(www-data) groups=...
        id_match = re.match(r"uid=\d+\((\w+)\)\s+gid=\d+\((\w+)\)", line)
        if id_match:
            result["user"] = id_match.group(1)
            result["group"] = id_match.group(2)
            continue
        # uname -a: Linux hostname 5.4.0 ...
        if line.startswith("Linux ") or re.match(r"\w+ \S+ \d+\.\d+\.\d+", line):
            result["kernel"] = line
            continue
        # hostname line (short, no spaces, no special chars from uname)
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,62}[a-zA-Z0-9])?$", line):
            if "hostname" not in result and "kernel" not in result:
                result["hostname"] = line
    return result


# Hash patterns: (regex, type_name, hashcat_mode)
_HASH_PATTERNS: list[tuple[str, str, str]] = [
    (r"\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{86}", "sha512crypt", "1800"),
    (r"\$5\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{43}", "sha256crypt", "7400"),
    (r"\$1\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{22}", "md5crypt", "500"),
    (r"\$2[aby]\$\d+\$[A-Za-z0-9./]{53}", "bcrypt", "3200"),
    (r"[a-f0-9]{64}", "SHA256", "1400"),
    (r"[a-f0-9]{40}", "SHA1", "100"),
    (r"[a-f0-9]{32}", "MD5", "0"),
]


def extract_hashes(text: str) -> list[dict[str, str]]:
    """Scan text for recognisable password hash strings and return unique entries."""
    results: list[dict[str, str]] = []
    seen: set[str] = set()

    for line in text.splitlines():
        # /etc/shadow format: username:$algo$salt$hash:...
        shadow_match = re.match(r"(\w[\w\-\.]+):(\$[^\s:]+)", line)
        if shadow_match:
            h = shadow_match.group(2)
            if h not in seen:
                seen.add(h)
                results.append({"hash": h, "user": shadow_match.group(1)})
            continue

        for pattern, name, mode in _HASH_PATTERNS:
            for m in re.finditer(pattern, line, re.IGNORECASE):
                h = m.group()
                if h not in seen:
                    seen.add(h)
                    results.append({"hash": h, "type": name, "mode": mode})

    return results


def score_exploits(
    exploits: list[dict[str, Any]],
    service: str,
    version: str | None,
    os_hint: str | None = None,
) -> list[dict[str, Any]]:
    """Score and sort searchsploit results by relevance to a single service/version."""
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


def score_exploits_multi(
    exploits: list[dict[str, Any]],
    ports: list[dict[str, Any]],
    os_hint: str | None = None,
) -> list[dict[str, Any]]:
    """Score exploits against all detected service/version pairs, taking the max score."""
    if not ports:
        return [{**e, "score": 0} for e in exploits]

    best: dict[str, int] = {}
    for port in ports:
        if not port.get("version"):
            continue
        svc = port.get("service", "")
        ver = port.get("version", "")
        for e in score_exploits(exploits, svc, ver, os_hint):
            path = e["path"]
            best[path] = max(best.get(path, 0), e["score"])

    result = [{**e, "score": best.get(e["path"], 0)} for e in exploits]
    result.sort(key=lambda x: x["score"], reverse=True)
    return result
