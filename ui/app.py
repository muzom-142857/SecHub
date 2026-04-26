import ipaddress
import re
import shutil
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import ListView

from core.analyzer import Analyzer
from core.parser import (
    extract_hashes,
    parse_enum4linux,
    parse_gobuster,
    parse_hydra,
    parse_nikto,
    parse_nmap,
    parse_searchsploit,
    parse_sysinfo,
    parse_sqlmap,
    parse_whatweb,
    parse_whois,
    score_exploits_multi,
)
from core.runner import ProcessHandle, stream_command
from core.session import Session
from phases import phase1, phase2, phase3, phase4
from phases.common import build_command
from report.generator import generate_report
from ui.layout import (
    CommandDisplayScreen,
    HelpScreen,
    PhaseLayout,
    ReportScreen,
    SessionSelectScreen,
    TargetInputScreen,
    ToolInputScreen,
)


class SecHubApp(App):
    """SecHub — penetration testing workflow TUI."""

    TITLE = "SecHub"
    CSS_PATH = Path(__file__).parent / "style.tcss"
    BINDINGS = [
        Binding("r", "run_tool", "Run", show=True),
        Binding("s", "skip_tool", "Skip", show=True),
        Binding("n", "next_phase", "Next Phase", show=True),
        Binding("b", "prev_phase", "Prev Phase", show=True),
        Binding("e", "toggle_expand", "Expand Output", show=True),
        Binding("R", "generate_report", "Report", show=True),
        Binding("ctrl+c", "cancel_tool", "Cancel", show=True, priority=True),
        Binding("q", "quit", "Quit", show=True),
        Binding("question_mark", "show_help", "Help", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.session: Session | None = None
        self.analyzer = Analyzer()
        self.current_tools: list[Any] = []
        self.selected_tool_index: int = 0
        self._proc_handle: ProcessHandle | None = None

    # ── Startup ───────────────────────────────────────────────

    def on_mount(self) -> None:
        self.push_screen(TargetInputScreen(), self._on_target_selected)

    def _on_target_selected(self, result: dict[str, Any] | None) -> None:
        if not result:
            self.exit()
            return
        target = result.get("target", "")
        if not self._is_valid_target(target):
            self.notify(f"'{target}' is not a valid IP address or domain name.", severity="error")
            self.push_screen(TargetInputScreen(), self._on_target_selected)
            return
        if result.get("resume"):
            self.push_screen(SessionSelectScreen(), self._on_session_selected)
        else:
            self.session = Session(target)
            self._enter_phase(1)

    def _on_session_selected(self, session_dir: str | None) -> None:
        if not session_dir:
            self.push_screen(TargetInputScreen(), self._on_target_selected)
            return
        self.session = Session.load(Path(session_dir))
        self._enter_phase(self.session.current_phase)

    # ── Phase navigation ──────────────────────────────────────

    def _enter_phase(self, phase: int) -> None:
        if self.session is None:
            return

        self.session.set_phase(phase)
        open_ports = self._get_open_ports()

        if phase == 1:
            self.current_tools = phase1.get_tools(self.session.target, open_ports)
        elif phase == 2:
            self.current_tools = phase2.get_tools(open_ports)
        elif phase == 3:
            exploit_info = self.session.result_store.get("phase2", {})
            self.current_tools = phase3.get_tools(open_ports, exploit_info)
        elif phase == 4:
            self.current_tools = phase4.get_tools(self.session.result_store)

        recommendations = self.analyzer.analyze(self.session.result_store)
        self.selected_tool_index = 0

        if isinstance(self.screen, PhaseLayout):
            self.screen.refresh_tools(
                phase, self.session.target, self.current_tools, recommendations
            )
        else:
            self.push_screen(
                PhaseLayout(phase, self.session.target, self.current_tools, recommendations)
            )

    def _get_open_ports(self) -> set[int]:
        if self.session is None:
            return set()
        return {
            p["port"]
            for p in self.session.result_store.get("phase1", {}).get("ports", [])
            if p.get("state") == "open"
        }

    # ── Tool execution ────────────────────────────────────────

    async def action_run_tool(self) -> None:
        if not self.current_tools or self.session is None:
            return

        tool = self.current_tools[self.selected_tool_index]
        layout = self.screen
        if not isinstance(layout, PhaseLayout):
            return

        # API tools — run in-process, no subprocess
        if tool.api_tool:
            layout.set_tool_running(tool.label)
            layout.clear_output()
            layout.set_tool_status(self.selected_tool_index, "running")
            if tool.id == "nvd_lookup":
                await self._run_nvd_lookup(layout)
            layout.set_tool_done(tool.label, True)
            layout.set_tool_status(self.selected_tool_index, "done")
            return

        # Collect required inputs
        extra: dict[str, str] = {}
        if tool.requires_input:
            if tool.id == "searchsploit":
                extra["query"] = self._build_searchsploit_query()
            else:
                inputs = await self.push_screen_wait(
                    ToolInputScreen(tool.label, tool.requires_input)
                )
                if inputs is None:
                    return
                extra = inputs

        # Display-only tools — show the command without executing it
        if tool.display_only:
            command = build_command(tool, self.session.target, **extra)
            if command:
                await self.push_screen_wait(CommandDisplayScreen(tool.label, command))
            return

        # Build command
        command = build_command(tool, self.session.target, **extra)
        if not command:
            self._show_error(f"Could not build command for '{tool.label}' — missing inputs.")
            return

        # Check binary availability
        if not self._check_tool_available(tool):
            binary = self._get_binary_name(tool)
            self._show_error(f"'{binary}' not found on PATH — install it first.")
            layout.set_tool_status(self.selected_tool_index, "failed")
            return

        layout.set_tool_running(tool.label)
        layout.clear_output()
        layout.set_tool_status(self.selected_tool_index, "running")

        self._proc_handle = ProcessHandle()
        result = await stream_command(
            command,
            on_stdout=lambda line: layout.append_output(line),
            on_stderr=lambda line: layout.append_output(f"[dim][stderr] {line}[/dim]"),
            timeout=tool.timeout,
            handle=self._proc_handle,
        )
        self._proc_handle = None

        if result.timed_out:
            layout.append_output(
                f"\n[yellow]⏱ Timed out after {tool.timeout}s — partial results saved.[/yellow]\n"
            )

        await self._process_result(tool, result.stdout)
        layout.set_tool_done(tool.label, result.success)
        layout.set_tool_status(
            self.selected_tool_index, "done" if result.success else "failed"
        )

        recommendations = self.analyzer.analyze(self.session.result_store)
        layout.update_recommendations(recommendations)

    async def _run_nvd_lookup(self, layout: PhaseLayout) -> None:
        if self.session is None:
            return

        ports = self.session.result_store.get("phase1", {}).get("ports", [])
        services = [
            (p.get("service", ""), p.get("version", ""))
            for p in ports
            if p.get("version")
        ]

        if not services:
            layout.append_output(
                "[dim]No service versions found from Phase 1 — run nmap -sV first.[/dim]\n"
            )
            return

        all_cves: list[dict[str, Any]] = []
        seen_cve_ids: set[str] = set()

        for svc, ver in services:
            layout.append_output(f"[dim]Querying NVD: {svc} {ver}...[/dim]\n")
            cves = await phase2.lookup_nvd(svc, ver)
            for cve in cves:
                if cve["cve_id"] not in seen_cve_ids:
                    seen_cve_ids.add(cve["cve_id"])
                    all_cves.append(cve)
                    score_str = str(cve.get("cvss_score", "N/A"))
                    desc = (cve.get("description") or "")[:80]
                    layout.append_output(
                        f"  [bold red]{cve['cve_id']}[/bold red]  "
                        f"CVSS:[bold]{score_str}[/bold]  {desc}\n"
                    )

        all_cves.sort(key=lambda x: x.get("cvss_score") or 0.0, reverse=True)
        self.session.update_phase(2, {"cves": all_cves})

        recommendations = self.analyzer.analyze(self.session.result_store)
        layout.update_recommendations(recommendations)
        layout.append_output(
            f"\n[green]NVD lookup complete — {len(all_cves)} unique CVE(s) found.[/green]\n"
        )

    async def _process_result(self, tool: Any, stdout: str) -> None:
        """Parse tool output and merge structured data into the session result store."""
        if self.session is None:
            return

        phase = self.session.current_phase
        key = f"phase{phase}"
        data: dict[str, Any] = {}

        if tool.id in ("nmap_fast", "nmap_svc", "nmap_os"):
            parsed = parse_nmap(stdout)
            existing_ports = {
                p["port"]: p
                for p in self.session.result_store.get(key, {}).get("ports", [])
            }
            for port in parsed.get("ports", []):
                existing_ports[port["port"]] = port
            data["ports"] = list(existing_ports.values())
            if parsed.get("os"):
                data["os"] = parsed["os"]
            if parsed.get("hostname"):
                data["hostname"] = parsed["hostname"]

        elif tool.id == "whois":
            data["whois"] = parse_whois(stdout)

        elif tool.id == "searchsploit":
            raw = parse_searchsploit(stdout)
            p1 = self.session.result_store.get("phase1", {})
            os_hint = p1.get("os")
            ports_data = p1.get("ports", [])
            data["exploits"] = score_exploits_multi(raw, ports_data, os_hint)

        elif tool.id == "nikto":
            data["nikto"] = parse_nikto(stdout)

        elif tool.id == "gobuster":
            data["gobuster"] = parse_gobuster(stdout)

        elif tool.id == "whatweb":
            data["whatweb"] = parse_whatweb(stdout)

        elif tool.id == "enum4linux":
            data["enum4linux"] = parse_enum4linux(stdout)

        elif tool.id == "hydra":
            creds = parse_hydra(stdout)
            if creds:
                data["credentials"] = creds

        elif tool.id == "sqlmap":
            dbs = parse_sqlmap(stdout)
            if dbs:
                data["databases"] = dbs

        elif tool.id == "sysinfo":
            data["sysinfo"] = stdout
            data["sysinfo_parsed"] = parse_sysinfo(stdout)

        # Scan all Phase 4 output for hashes
        if phase == 4 and stdout:
            found = extract_hashes(stdout)
            if found:
                existing = self.session.result_store.get("phase4", {}).get("hashes", [])
                merged = list({h for h in existing} | {h["hash"] for h in found})
                data["hashes"] = merged

        if data:
            self.session.update_phase(phase, data)

    def _build_searchsploit_query(self) -> str:
        """Construct a searchsploit query from all detected service/version strings."""
        if self.session is None:
            return ""
        ports = self.session.result_store.get("phase1", {}).get("ports", [])
        parts = [
            f"{p.get('service', '')} {p.get('version', '')}".strip()
            for p in ports
            if p.get("version")
        ]
        return " ".join(parts[:3]) if parts else self.session.target

    def _check_tool_available(self, tool: Any) -> bool:
        binary = self._get_binary_name(tool)
        return not binary or bool(shutil.which(binary))

    @staticmethod
    def _get_binary_name(tool: Any) -> str:
        parts = tool.command_template.split()
        if not parts:
            return ""
        binary = parts[0]
        if binary == "sudo" and len(parts) > 1:
            binary = parts[1]
        return binary

    @staticmethod
    def _is_valid_target(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        # Basic domain/hostname pattern
        return bool(
            re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$", target)
        )

    def _show_error(self, message: str) -> None:
        if isinstance(self.screen, PhaseLayout):
            self.screen.append_output(f"[bold red][ERROR] {message}[/bold red]\n")

    # ── Keybinding actions ────────────────────────────────────

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.list_view.id == "tool_list" and event.item is not None:
            index = event.list_view.index
            if index is not None:
                self.selected_tool_index = index

    def action_skip_tool(self) -> None:
        if self.current_tools:
            self.selected_tool_index = min(
                self.selected_tool_index + 1, len(self.current_tools) - 1
            )
            if isinstance(self.screen, PhaseLayout):
                self.screen.select_tool(self.selected_tool_index)

    def action_next_phase(self) -> None:
        if self.session and self.session.current_phase < 4:
            self._enter_phase(self.session.current_phase + 1)

    def action_prev_phase(self) -> None:
        if self.session and self.session.current_phase > 1:
            self._enter_phase(self.session.current_phase - 1)

    def action_toggle_expand(self) -> None:
        if isinstance(self.screen, PhaseLayout):
            self.screen.toggle_expand()

    def action_generate_report(self) -> None:
        if self.session:
            md, txt = generate_report(self.session)
            self.push_screen(ReportScreen(md, txt, self.session.session_dir))

    def action_cancel_tool(self) -> None:
        if self._proc_handle and self._proc_handle.process:
            self._proc_handle.cancel()
            if isinstance(self.screen, PhaseLayout):
                self.screen.append_output("\n[yellow]⏹ Tool execution cancelled.[/yellow]\n")
                self.screen.set_tool_status(self.selected_tool_index, "failed")

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())
