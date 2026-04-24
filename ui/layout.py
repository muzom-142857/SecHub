from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Input,
    Label,
    ListItem,
    ListView,
    RadioButton,
    RadioSet,
    RichLog,
    Static,
    TextArea,
)


# ── Target input screen ────────────────────────────────────────────

class TargetInputScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Vertical(
            Static(
                "  ███████╗███████╗ ██████╗██╗  ██╗██╗   ██╗██████╗ \n"
                "  ██╔════╝██╔════╝██╔════╝██║  ██║██║   ██║██╔══██╗\n"
                "  ███████╗█████╗  ██║     ███████║██║   ██║██████╔╝\n"
                "  ╚════██║██╔══╝  ██║     ██╔══██║██║   ██║██╔══██╗\n"
                "  ███████║███████╗╚██████╗██║  ██║╚██████╔╝██████╔╝\n"
                "  ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ \n",
                id="banner",
            ),
            Static("Penetration Testing Workflow Assistant", id="subtitle"),
            Static(""),
            Label("Target (IP / Domain):"),
            Input(placeholder="e.g. 10.10.10.1 or example.com", id="target_input"),
            Static(""),
            RadioSet(
                RadioButton("New session", id="new_session", value=True),
                RadioButton("Resume previous session", id="resume_session"),
                id="mode_select",
            ),
            Static(""),
            Button("Start", variant="primary", id="start_btn"),
            id="target_container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "start_btn":
            return
        target = self.query_one("#target_input", Input).value.strip()
        if not target:
            return
        radio_set = self.query_one("#mode_select", RadioSet)
        resume = radio_set.pressed_button.id == "resume_session"
        self.dismiss({"target": target, "resume": resume})


# ── Session selection screen ───────────────────────────────────────

class SessionSelectScreen(Screen):
    def __init__(self) -> None:
        super().__init__()
        from core.session import Session
        self.sessions = Session.list_sessions()

    def compose(self) -> ComposeResult:
        if self.sessions:
            items = [
                ListItem(
                    Label(
                        f"{s['target']}  [{s['created_at'][:10]}]  "
                        f"Phase {s['current_phase']}"
                    )
                )
                for s in self.sessions
            ]
        else:
            items = [ListItem(Label("No saved sessions found."))]

        yield Vertical(
            Static("Select a previous session", id="title"),
            ListView(*items, id="session_list"),
            Button("Cancel", id="cancel_btn"),
            id="session_container",
        )

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        index = event.list_view.index
        if self.sessions and index is not None and index < len(self.sessions):
            self.dismiss(self.sessions[index]["dir"])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel_btn":
            self.dismiss(None)


# ── Tool input modal ───────────────────────────────────────────────

class ToolInputScreen(ModalScreen):
    """Prompt the user to supply required parameters for a tool."""

    def __init__(self, tool_label: str, required_fields: list[str]) -> None:
        super().__init__()
        self.tool_label = tool_label
        self.required_fields = required_fields

    def compose(self) -> ComposeResult:
        fields: list[Any] = [Static(f"Parameters for: {self.tool_label}", id="tool_input_title")]
        for field in self.required_fields:
            fields.append(Label(field))
            fields.append(Input(placeholder=field, id=f"input_{field}"))
        fields.append(Static(""))
        fields.append(
            Horizontal(
                Button("Run", variant="primary", id="run_btn"),
                Button("Cancel", id="cancel_btn"),
            )
        )
        yield Vertical(*fields, id="tool_input_container")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel_btn":
            self.dismiss(None)
            return
        if event.button.id == "run_btn":
            values: dict[str, str] = {}
            for field in self.required_fields:
                widget = self.query_one(f"#input_{field}", Input)
                values[field] = widget.value.strip()
            self.dismiss(values)


# ── Main phase layout ──────────────────────────────────────────────

class PhaseLayout(Screen):
    PHASE_LABELS: dict[int, str] = {
        1: "Reconnaissance",
        2: "Vulnerability Analysis",
        3: "Exploitation",
        4: "Post-Exploitation",
    }

    def __init__(
        self,
        phase: int,
        target: str,
        tools: list[Any],
        recommendations: list[Any],
    ) -> None:
        super().__init__()
        self.phase = phase
        self.target = target
        self.tools = tools
        self.recommendations = recommendations
        self._expanded = False

    def compose(self) -> ComposeResult:
        yield Static(self._header_text(), id="header_bar")
        yield Horizontal(
            Vertical(
                Static("Tools", classes="panel_title"),
                ListView(
                    *[ListItem(Label(self._tool_label(t))) for t in self.tools],
                    id="tool_list",
                ),
                id="tool_panel",
            ),
            Vertical(
                Static("Output", classes="panel_title"),
                RichLog(id="output_log", highlight=True, markup=True),
                id="output_panel",
            ),
            id="main_panels",
        )
        yield Vertical(
            Static("Recommendations", classes="panel_title"),
            RichLog(id="rec_log", highlight=True, markup=True),
            id="rec_panel",
        )

    def on_mount(self) -> None:
        self._render_recommendations()

    # ── Internal helpers ──────────────────────────────────────────

    def _header_text(self) -> str:
        label = self.PHASE_LABELS.get(self.phase, "")
        return f" SecHub  |  Phase {self.phase}: {label}  |  Target: {self.target} "

    def _tool_label(self, tool: Any) -> str:
        suffix = " [optional]" if getattr(tool, "optional", False) else ""
        return f"  {tool.label}{suffix}"

    def _render_recommendations(self) -> None:
        log = self.query_one("#rec_log", RichLog)
        log.clear()
        if not self.recommendations:
            log.write("[dim]Waiting for Phase 1 results...[/dim]")
            return
        for rec in self.recommendations:
            cve = f"  [bold red][{rec['cve']}][/bold red]" if rec.get("cve") else ""
            log.write(f"[green]→[/green] [bold]{rec['action']}[/bold]{cve}  — {rec['description']}")

    # ── Public API called by SecHubApp ────────────────────────────

    def refresh_tools(
        self,
        phase: int,
        target: str,
        tools: list[Any],
        recommendations: list[Any],
    ) -> None:
        self.phase = phase
        self.target = target
        self.tools = tools
        self.recommendations = recommendations
        self.query_one("#header_bar", Static).update(self._header_text())
        tool_list = self.query_one("#tool_list", ListView)
        tool_list.clear()
        for tool in tools:
            tool_list.append(ListItem(Label(self._tool_label(tool))))
        self.update_recommendations(recommendations)
        self.clear_output()

    def select_tool(self, index: int) -> None:
        self.query_one("#tool_list", ListView).index = index

    def set_tool_running(self, tool_label: str) -> None:
        self.query_one("#output_log", RichLog).write(
            f"\n[bold yellow]▶ Running: {tool_label}[/bold yellow]\n"
        )

    def set_tool_done(self, tool_label: str, success: bool) -> None:
        status = "[bold green]Done[/bold green]" if success else "[bold red]Failed[/bold red]"
        self.query_one("#output_log", RichLog).write(
            f"\n[bold]{tool_label}[/bold] — {status}\n"
        )

    def append_output(self, text: str) -> None:
        self.query_one("#output_log", RichLog).write(text)

    def clear_output(self) -> None:
        self.query_one("#output_log", RichLog).clear()

    def update_recommendations(self, recommendations: list[Any]) -> None:
        self.recommendations = recommendations
        self._render_recommendations()

    def toggle_expand(self) -> None:
        self._expanded = not self._expanded
        self.query_one("#tool_panel").display = not self._expanded
        self.query_one("#rec_panel").display = not self._expanded


# ── Report screen ──────────────────────────────────────────────────

class ReportScreen(ModalScreen):
    def __init__(self, md_content: str, txt_content: str, session_dir: Path) -> None:
        super().__init__()
        self.md_content = md_content
        self.txt_content = txt_content
        self.session_dir = session_dir

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("Generate Report", id="title"),
            RadioSet(
                RadioButton("Markdown", id="fmt_md", value=True),
                RadioButton("Plain Text", id="fmt_txt"),
                id="format_select",
            ),
            TextArea(self.md_content, id="report_area"),
            Horizontal(
                Button("Save", variant="primary", id="save_btn"),
                Button("Close", id="close_btn"),
            ),
            id="report_container",
        )

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        area = self.query_one("#report_area", TextArea)
        if event.pressed.id == "fmt_md":
            area.load_text(self.md_content)
        else:
            area.load_text(self.txt_content)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save_btn":
            radio_set = self.query_one("#format_select", RadioSet)
            fmt = "md" if radio_set.pressed_button.id == "fmt_md" else "txt"
            content = self.query_one("#report_area", TextArea).text
            out_path = self.session_dir / f"report.{fmt}"
            out_path.write_text(content, encoding="utf-8")
            self.dismiss()
        elif event.button.id == "close_btn":
            self.dismiss()


# ── Help screen ────────────────────────────────────────────────────

class HelpScreen(ModalScreen):
    HELP_TEXT = """\
[bold]SecHub Keybindings[/bold]

  [bold cyan]r[/bold cyan]  Run selected tool
  [bold cyan]s[/bold cyan]  Skip to next tool
  [bold cyan]n[/bold cyan]  Advance to next phase
  [bold cyan]b[/bold cyan]  Go back to previous phase
  [bold cyan]e[/bold cyan]  Toggle output panel fullscreen
  [bold cyan]R[/bold cyan]  Generate and save report
  [bold cyan]q[/bold cyan]  Quit
  [bold cyan]?[/bold cyan]  Show this help

[bold]Phase Flow[/bold]

  Phase 1 → Reconnaissance      (whois, nmap)
  Phase 2 → Vulnerability Analysis  (searchsploit, nikto, NVD API)
  Phase 3 → Exploitation         (MSF, Hydra, sqlmap)
  Phase 4 → Post-Exploitation    (PE, credential hunt, hash cracking)
"""

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static(self.HELP_TEXT, id="help_text"),
            Button("Close", id="close_btn"),
            id="help_container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close_btn":
            self.dismiss()
