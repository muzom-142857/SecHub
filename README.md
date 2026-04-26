# SecHub

A terminal-based penetration testing workflow assistant that consolidates reconnaissance,
vulnerability analysis, exploitation, and post-exploitation into a single TUI — without
sacrificing any capability or control.

```
┌──────────────────────────────────────────────────────────┐
│  SecHub  |  Phase 2: Vulnerability Analysis  |  10.10.10.1│
├─────────────────────┬────────────────────────────────────┤
│  Tools              │  Output                            │
│                     │                                    │
│  ✓ searchsploit     │  [7] Apache 2.4.49 - Path Trav...  │
│  ▶ NVD lookup       │  CVE-2021-41773  CVSS:9.8  ...     │
│  ○ nikto [opt]      │  ...                               │
│                     │                                    │
├─────────────────────┴────────────────────────────────────┤
│  Recommendations                                         │
│  → sqlmap  — SQL injection (web service detected)        │
│  → hydra   — Credential brute-force                      │
├──────────────────────────────────────────────────────────┤
│  [r]Run [s]Skip [n]Next [b]Back [e]Expand [^C]Cancel [?] │
└──────────────────────────────────────────────────────────┘
```

---

## Why SecHub

A typical engagement uses a dozen tools across four phases.
Switching between terminals, tracking which commands ran, and remembering to parse
output before moving on creates friction that slows learning.

SecHub solves this by:
- presenting the right tool at the right time based on what was actually found
- streaming tool output in real time inside the same window
- parsing results automatically and updating recommendations instantly
- saving every result to disk so sessions can be paused and resumed
- generating a structured report at any point

---

## Prerequisites

SecHub orchestrates external tools — they must be installed and on your `$PATH`.
If a tool is missing, SecHub shows an error instead of running and marks it as failed.

| Tool | Phase | Install (Debian/Kali) |
|------|-------|-----------------------|
| `nmap` | 1 | `apt install nmap` |
| `whois` | 1 | `apt install whois` |
| `gobuster` | 1 | `apt install gobuster` |
| `dnsenum` | 1 | `apt install dnsenum` |
| `enum4linux` | 1 | `apt install enum4linux` |
| `smtp-user-enum` | 1 | `apt install smtp-user-enum` |
| `searchsploit` | 2, 3 | `apt install exploitdb` |
| `nikto` | 2 | `apt install nikto` |
| `whatweb` | 2 | `apt install whatweb` |
| `smbmap` | 2 | `apt install smbmap` |
| `metasploit-framework` | 3 | `apt install metasploit-framework` |
| `hydra` | 3 | `apt install hydra` |
| `sqlmap` | 3 | `apt install sqlmap` |
| `john` | 4 | `apt install john` |
| `hashcat` | 4 | `apt install hashcat` |

Python 3.11 or later is required.

---

## Installation

```bash
git clone https://github.com/muzom-142857/SecHub.git
cd SecHub
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Running

```bash
source .venv/bin/activate
python main.py
```

On the start screen, enter an IP address or domain name, choose **New session** or
**Resume previous session**, and press **Start** (or Enter).

---

## Workflow

### Phase 1 — Reconnaissance

Always runs: `whois`, `nmap -T4 -F`, `nmap -sV -sC`, `sudo nmap -O`.

After the fast scan completes, optional tools are added automatically:

| Detected | Tool added |
|----------|-----------|
| Port 80 / 443 | gobuster, gobuster (vhost) |
| Domain target | dnsenum |
| Port 445 | enum4linux, smbclient |
| Port 25 | smtp-user-enum |
| Port 111 | nmap rpcinfo |
| Port 2049 | nmap nfs-showmount |
| Port 3632 | nmap distcc check |

### Phase 2 — Vulnerability Analysis

`searchsploit` runs with a query automatically built from **every** service/version
string found in Phase 1. Results are scored against all ports and sorted by:

| Criterion | Score |
|-----------|-------|
| Version string found in exploit title | +10 |
| Service name found in exploit title | +3 |
| Platform matches detected OS | +5 |
| Title contains "remote" | +2 |

**NIST NVD lookup** is a runnable tool — select it to query the NVD API for CVEs
matched to all detected service/version pairs. Requires an internet connection.

Optional tools appear when their target port is open:

| Port | Tool |
|------|------|
| 80 / 443 | nikto, whatweb, nmap http-vuln |
| 445 | nmap smb-vuln, smbmap |
| 21 | nmap ftp-anon |
| 3306 | nmap mysql |
| 22 | nmap ssh-check |
| 3389 | nmap rdp-check |
| 3632 | nmap distcc RCE |
| 2049 | nmap nfs-ls |

### Phase 3 — Exploitation

Tools are chosen based on Phase 2 findings:

- **Metasploit** — when a module is mapped from the exploit list
- **Hydra** — when a credential service port is open (22, 21, 23, 25, 110, 143, 3389)
- **searchsploit -m** — always available to copy a script locally
- **sqlmap** — when a web port is open

**Reverse shell tools** (`bash`, `python3`) display the command in a modal for
copy/paste onto the target — they do **not** execute locally.

Tools that require parameters (wordlist paths, URL, MSF module name) display a
modal input dialog before running.

### Phase 4 — Post-Exploitation

Runs shell commands on the target after a session is obtained:

| Tool | Purpose |
|------|---------|
| System info | Confirm user, OS, kernel (auto-parsed) |
| sudo privileges | List sudo permissions |
| SUID binaries | Find SUID PE vectors |
| Linux capabilities | Find elevated-capability binaries |
| Cron jobs | Enumerate scheduled tasks |
| Writable paths | Find world-writable files |
| Process list | List running processes |
| Internal network | Open ports and services |
| Interesting files | SSH keys, backup files, config passwords |
| Credential hunt | Config files, shell history |
| john / hashcat | Hash cracking (appears when hashes detected in output) |

Hash strings are automatically extracted from **every** Phase 4 tool's output and
stored for cracking. linpeas / winpeas must be uploaded manually.

---

## Cancellation

Press **Ctrl+C** at any time to kill the currently running tool.
The process group (including child processes like `nmap` under `sudo`) is sent
`SIGKILL`, partial output is preserved, and the tool is marked as failed.
Use `q` to quit SecHub.

---

## Session Management

Sessions are stored in `sessions/<date>_<target>/` relative to the project root,
regardless of where you launch `main.py` from. Every tool execution saves its
result immediately — if SecHub is closed, the session can be resumed from the
start screen.

```
sessions/
└── 2026-04-24_10.10.10.1/
    ├── session.json   # metadata
    ├── phase1.json    # port/OS/whois data
    ├── phase2.json    # exploits, CVEs, scanner output
    ├── phase3.json    # credentials, databases
    ├── phase4.json    # system info, hashes
    └── report.md      # generated report
```

---

## Reports

Press `R` at any time to open the report screen.
Choose **Markdown** or **Plain Text** format; the file is saved to the session directory.

Reports include:
- Target, timestamps
- Port scan table (port / protocol / state / service / version)
- OS detection
- ExploitDB results (top 10 by score)
- CVE list with CVSS scores
- Discovered web directories and technologies
- Exploitation results (credentials, databases)
- System info (parsed), collected hashes

---

## Customising the Rule Table

The rule engine reads all `*.yaml` files from the `rules/` directory.
To add custom rules, create `rules/custom.yaml`:

```yaml
rules:
  - id: my_rule
    description: Detect custom service
    condition: port_open
    ports: [8888]
    actions:
      - my_custom_tool

  - id: known_vuln
    description: Known RCE in MyApp 1.0
    condition: version_match
    pattern: "myapp 1\\.0"
    cve: CVE-2025-99999
    actions:
      - searchsploit
      - msf_lookup
```

The default rules work without any customisation; custom rules are merged on top.

### Supported Conditions

| Condition | Required fields | Meaning |
|-----------|----------------|---------|
| `port_open` | `ports: [...]` | Any listed port is open |
| `service_version_detected` | — | Any port has a version string |
| `version_match` | `pattern: "regex"` | Version string matches regex |
| `cvss_gte` | `value: 7.0` | Any CVE has CVSS ≥ value |
| `exploit_available` | — | Phase 2 exploit list is non-empty |
| `web_service_detected` | — | Port 80/443/8080/8443 is open |
| `file_obtained` | `pattern: "/path"` | Path found in obtained_files |
| `hash_detected` | — | Hashes found in Phase 4 data |

---

## Keybindings

| Key | Action |
|-----|--------|
| `r` | Run selected tool |
| `s` | Skip to next tool |
| `n` | Advance to next phase |
| `b` | Return to previous phase |
| `e` | Toggle output panel fullscreen |
| `R` | Generate and save report |
| `Ctrl+C` | Cancel running tool |
| `q` | Quit |
| `?` | Help overlay |

---

## Project Structure

```
sechub/
├── main.py                  Entry point
├── requirements.txt         Python dependencies
├── CLAUDE.md                Project design doc (for Claude Code)
├── core/
│   ├── runner.py            Async subprocess execution + ProcessHandle
│   ├── parser.py            Tool output parsers (nmap, whois, gobuster, hydra, etc.)
│   ├── analyzer.py          Rule engine → recommendations
│   └── session.py           Session persistence
├── phases/
│   ├── common.py            Tool dataclass (timeout, display_only, api_tool) + build_command
│   ├── phase1.py            Reconnaissance tool definitions
│   ├── phase2.py            Vulnerability analysis + NVD API
│   ├── phase3.py            Exploitation tool definitions
│   └── phase4.py            Post-exploitation + hash detection
├── ui/
│   ├── app.py               App root, keybindings, phase logic
│   ├── layout.py            Screen classes (incl. CommandDisplayScreen)
│   └── style.tcss           Terminal stylesheet
├── rules/
│   └── default.yaml         Built-in rule table
├── report/
│   └── generator.py         Markdown / plain-text report builder
└── sessions/                Created at runtime (project root)
```

---

## Legal Notice

SecHub is intended for **authorised security testing, CTF competitions, and
educational lab environments only**.  
Running it against systems you do not own or have explicit written permission to
test is illegal. The authors accept no responsibility for misuse.
