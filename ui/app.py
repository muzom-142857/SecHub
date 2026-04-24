from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import ListView

from core.analyzer import Analyzer
from core.parser import parse_nmap, parse_whois, parse_searchsploit, parse_nikto, score_exploits
from core.runner import stream_command
from core.session import Session
from phases import phase1, phase2, phase3, phase4
from phases.common import build_command
from report.generator import generate_report
from ui.layout import (
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
        Binding("q", "quit", "Quit", show=True),
        Binding("question_mark", "show_help", "Help", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.session: Session | None = None
        self.analyzer = Analyzer()
        self.current_tools: list[Any] = []
        self.selected_tool_index: int = 0

    # ── Startup ───────────────────────────────────────────────────

    def on_mount(self) -> None:
        self.push_screen(TargetInputScreen(), self._on_target_selected)

    def _on_target_selected(self, result: dict[str, Any] | None) -> None:
        if not result:
            self.exit()
            return
        if result.get("resume"):
            self.push_screen(SessionSelectScreen(), self._on_session_selected)
        else:
            target = result.get("target", "")
            self.session = Session(target)
            self._enter_phase(1)

    def _on_session_selected(self, session_dir: str | None) -> None:
        if not session_dir:
            # Cancelled — go back to start screen
            self.push_screen(TargetInputScreen(), self._on_target_selected)
            return
        self.session = Session.load(Path(session_dir))
        self._enter_phase(self.session.current_phase)

    # ── Phase navigation ──────────────────────────────────────────

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

    # ── Tool execution ────────────────────────────────────────────

    async def action_run_tool(self) -> None:
        if not self.current_tools or self.session is None:
            return

        tool = self.current_tools[self.selected_tool_index]

        # Collect any required user inputs via a modal dialog
        extra: dict[str, str] = {}
        if tool.requires_input:
            # Auto-fill searchsploit query from Phase 1 results
            if tool.id == "searchsploit" and not extra:
                extra["query"] = self._build_searchsploit_query()
            else:
                inputs = await self.push_screen_wait(
                    ToolInputScreen(tool.label, tool.requires_input)
                )
                if inputs is None:
                    return  # User cancelled
                extra = inputs

        command = build_command(tool, self.session.target, **extra)
        if not command:
            self._show_error(f"Could not build command for '{tool.label}' — missing inputs.")
            return

        layout = self.screen
        if not isinstance(layout, PhaseLayout):
            return

        layout.set_tool_running(tool.label)
        layout.clear_output()

        result = await stream_command(
            command,
            on_stdout=lambda line: layout.append_output(line),
            on_stderr=lambda line: layout.append_output(f"[dim][stderr] {line}[/dim]"),
        )

        await self._process_result(tool, result.stdout)
        layout.set_tool_done(tool.label, result.success)

        recommendations = self.analyzer.analyze(self.session.result_store)
        layout.update_recommendations(recommendations)

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
            if ports_data:
                svc = ports_data[0].get("service", "")
                ver = ports_data[0].get("version", "")
                data["exploits"] = score_exploits(raw, svc, ver, os_hint)
            else:
                data["exploits"] = raw

        elif tool.id == "nikto":
            data["nikto"] = parse_nikto(stdout)

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

    def _show_error(self, message: str) -> None:
        if isinstance(self.screen, PhaseLayout):
            self.screen.append_output(f"[bold red][ERROR] {message}[/bold red]\n")

    # ── Keybinding actions ────────────────────────────────────────

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

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())
