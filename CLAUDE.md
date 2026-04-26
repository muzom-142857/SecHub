# SecHub — CLAUDE.md

## Project Direction

SecHub is a TUI tool that consolidates the penetration testing workflow into a single interface.
The goal is to simplify the multi-tool complexity of a real engagement without sacrificing
any capability, and to automate decisions intelligently while keeping the user in control.

> **Core principles:** Simplify · Complete · Automate · Customise

---

## Language Policy

**All source code must be written in English.**
This applies to:
- All identifiers (variables, functions, classes, modules)
- All comments and docstrings
- All UI strings, labels, button text, and log messages
- All YAML rule descriptions and keys
- All report output

Korean may be used only in this CLAUDE.md, in commit messages, and in direct conversation.
Never write Korean inside `.py`, `.yaml`, `.tcss`, or any other source file.

---

## Tech Stack

- **Language:** Python 3.11+
- **TUI framework:** [Textual](https://github.com/Textualize/textual) ≥ 0.47
- **Async execution:** asyncio (prevents UI blocking during long-running tools)
- **Session storage:** JSON (results), YAML (rule table)
- **External API:** NIST NVD API (CVE / CVSS lookup)

---

## Architecture

### Flow

```
Target input → Phase 1 → Phase 2 → Phase 3 → Phase 4 → Report
```

Single-session linear flow. After each phase, results are parsed and the analyzer
produces a recommendation list for the next phase.

### Directory Structure

```
sechub/
├── main.py                  Entry point; Python version check
├── requirements.txt
├── CLAUDE.md
├── README.md
├── core/
│   ├── runner.py            Async subprocess execution with stdout streaming
│   ├── parser.py            Tool output parsers → structured dicts
│   ├── analyzer.py          Rule-table evaluation → recommendation list
│   └── session.py           Session persistence (./sessions/)
├── phases/
│   ├── common.py            Shared Tool dataclass and build_command helper
│   ├── phase1.py            Reconnaissance tool definitions
│   ├── phase2.py            Vulnerability analysis tool definitions + NVD lookup
│   ├── phase3.py            Exploitation tool definitions
│   └── phase4.py            Post-exploitation tool definitions + hash detection
├── ui/
│   ├── app.py               Textual App, keybindings, phase transitions
│   ├── layout.py            All screen classes (5 screens)
│   └── style.tcss           GitHub Dark theme stylesheet
├── rules/
│   └── default.yaml         Default rule table (18 rules); custom.yaml merged automatically
├── report/
│   └── generator.py         Markdown and plain-text report builder
└── sessions/                Auto-created; one sub-directory per session
```

---

## Phase Tool Definitions

### Phase 1 — Reconnaissance

| Type | Tool | Command | Condition |
|------|------|---------|-----------|
| Basic | whois | `whois {target}` | always |
| Basic | nmap (fast) | `nmap -T4 -F {target}` | always |
| Basic | nmap (svc/ver) | `nmap -sV -sC {target}` | always |
| Basic | nmap (OS) | `sudo nmap -O {target}` | always |
| Optional | gobuster | directory brute-force | port 80/443 open |
| Optional | dnsenum | DNS enumeration | domain target |
| Optional | enum4linux | SMB/NetBIOS gathering | port 445 open |
| Optional | smtp-user-enum | SMTP user enumeration | port 25 open |

### Phase 2 — Vulnerability Analysis

| Type | Tool | Condition |
|------|------|-----------|
| Basic | searchsploit | always (query auto-built from all Phase 1 versions) |
| Basic | nvd_lookup (NIST NVD API) | always (api_tool — no subprocess) |
| Optional | nikto | port 80/443 open |
| Optional | whatweb | port 80/443 open |
| Optional | nmap http-vuln | port 80/443 open |
| Optional | nmap smb-vuln-* | port 445 open |
| Optional | smbmap | port 445 open |
| Optional | nmap ftp-anon | port 21 open |
| Optional | nmap mysql-* | port 3306 open |
| Optional | nmap rdp-check | port 3389 open |
| Optional | nmap ssh-check | port 22 open |
| Optional | nmap distcc RCE | port 3632 open |
| Optional | nmap nfs-ls | port 2049 open |

searchsploit results are scored against **all** detected service/version pairs
(not just the first port); the max score per exploit is used, then sorted descending.

### Phase 3 — Exploitation

| Tool | Condition | Notes |
|------|-----------|-------|
| msfconsole -x | MSF module mapped from Phase 2 | |
| Hydra | credential services open (22, 21, 23, 25, 110, 143, 3389) | |
| searchsploit -m | always available | |
| sqlmap | port 80/443 open | |
| reverse_shell_bash | port 80/443 open | `display_only=True` — shows command, does NOT execute |
| reverse_shell_python | port 80/443 open | `display_only=True` — shows command, does NOT execute |
| nc listener | always available | |
| webshell_curl | port 80/443 open | |

Wordlist paths and other parameters are collected via a modal input dialog before running.
`display_only=True` tools open `CommandDisplayScreen` with the built command for copy/paste.

### Phase 4 — Post-Exploitation

| Tool | Condition |
|------|-----------|
| System info (whoami, id, uname…) | always |
| sudo privilege check | always |
| SUID binary search | always |
| Process list | always |
| Internal network | always |
| Credential hunt | always |
| john / hashcat | only when hashes are detected in result store |

linpeas/winpeas are uploaded manually by the user; SecHub parses their output.

---

## Automation Algorithm

```
Tool stdout → Parser → ResultStore (JSON) → Analyzer → Recommendations → User selects → Execute
```

**Semi-automatic:** The algorithm displays a ranked recommendation list; the user
chooses which action to take. Nothing runs without explicit user confirmation.

### Rule Table (rules/default.yaml)

Rules are YAML objects with a `condition` field and an `actions` list.
All *.yaml files in `rules/` are merged at startup; `default.yaml` is always loaded first.
The project works correctly with only the default rules — no customisation required.

Supported conditions:

| Condition | Trigger |
|-----------|---------|
| `port_open` | Any of `ports` are in the open port set |
| `service_version_detected` | Any port has a non-empty version string |
| `version_match` | A port's "service version" string matches `pattern` (regex) |
| `cvss_gte` | Any CVE in result store has CVSS ≥ `value` |
| `exploit_available` | Phase 2 exploits list is non-empty |
| `web_service_detected` | Port 80/443/8080/8443 is open |
| `file_obtained` | `pattern` found in obtained_files list |
| `hash_detected` | Phase 4 hashes list is non-empty |

---

## UI / UX Layout

```
┌──────────────────────────────────────────────────────┐
│  SecHub  |  Phase 2: Vulnerability Analysis  |  Target │
├────────────────────┬─────────────────────────────────┤
│                    │                                  │
│  Tools panel       │  Output panel                    │
│                    │  (real-time stdout stream)       │
│  ▶ searchsploit    │                                  │
│    nikto           │                                  │
│    whatweb         │                                  │
│                    │                                  │
├────────────────────┴─────────────────────────────────┤
│  Recommendations panel                                │
│  → nikto   — Web vulnerability scanner               │
│  → sqlmap  — SQL injection (web service detected)    │
├──────────────────────────────────────────────────────┤
│  [r]Run  [s]Skip  [n]Next  [b]Back  [e]Expand  [?]  │
└──────────────────────────────────────────────────────┘
```

### Keybindings

| Key | Action |
|-----|--------|
| `r` | Run selected tool |
| `s` | Skip to next tool |
| `n` | Advance to next phase |
| `b` | Return to previous phase |
| `e` | Toggle output panel fullscreen |
| `R` | Generate and save report |
| `Ctrl+C` | Cancel running tool (kills process group) |
| `q` | Quit |
| `?` | Show help overlay |

---

## Session Management

- Sessions are stored in `./sessions/<YYYY-MM-DD>_<target>/`
- Each tool execution auto-saves its phase JSON immediately
- On restart, incomplete sessions can be resumed from the start screen
- Corrupted phase files are silently skipped to preserve other phase data

Sessions are stored at `<project_root>/sessions/` regardless of launch directory.

```
sessions/
└── 2026-04-24_10.10.10.1/
    ├── session.json   (metadata: target, phase, timestamps)
    ├── phase1.json
    ├── phase2.json
    ├── phase3.json    (credentials, databases)
    ├── phase4.json    (sysinfo, hashes)
    └── report.md      (or report.txt)
```

---

## Report Generation

Reports are generated on demand (`R` key) and saved to the session directory.

| Format | Content |
|--------|---------|
| Markdown | Phase summaries, port table, exploit table, CVE table, system info, hashes |
| Plain Text | Same content in fixed-width format |

---

## Development Principles

1. **Simplify + Complete:** reduce workflow complexity without dropping any capability
2. **Automate + Customise:** recommend automatically, decide manually
3. **Learning-friendly:** the user sees *why* each tool is recommended at every step
4. **Extensible:** new tools and rules can be added without touching core logic
5. **Safe:** dangerous commands are surfaced clearly; nothing runs without confirmation
6. **English-only source:** all code, comments, and UI text must be in English
