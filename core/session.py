import json
from datetime import datetime
from pathlib import Path
from typing import Any


SESSIONS_DIR = Path("sessions")


class Session:
    """Manages state and results for a single penetration test session."""

    def __init__(self, target: str, session_dir: Path | None = None) -> None:
        self.target = target
        self.created_at = datetime.now().isoformat()
        self.current_phase = 1
        self.result_store: dict[str, Any] = {
            "phase1": {},
            "phase2": {},
            "phase3": {},
            "phase4": {},
        }

        if session_dir:
            self.session_dir = session_dir
        else:
            date_str = datetime.now().strftime("%Y-%m-%d")
            safe_target = target.replace("/", "_").replace(":", "_")
            self.session_dir = SESSIONS_DIR / f"{date_str}_{safe_target}"

        self.session_dir.mkdir(parents=True, exist_ok=True)

    # ── Persistence ───────────────────────────────────────────────

    def save(self) -> None:
        """Write full session metadata and all phase results to disk."""
        meta = {
            "target": self.target,
            "created_at": self.created_at,
            "current_phase": self.current_phase,
            "saved_at": datetime.now().isoformat(),
        }
        self._write_json("session.json", meta)
        for phase in range(1, 5):
            key = f"phase{phase}"
            if self.result_store.get(key):
                self._write_json(f"{key}.json", self.result_store[key])

    def save_phase(self, phase: int) -> None:
        """Write a single phase result immediately after tool execution."""
        key = f"phase{phase}"
        self._write_json(f"{key}.json", self.result_store.get(key, {}))

    def _write_json(self, filename: str, data: Any) -> None:
        path = self.session_dir / filename
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    # ── Loading ───────────────────────────────────────────────────

    @classmethod
    def load(cls, session_dir: Path) -> "Session":
        """Restore a session from a previously saved directory."""
        meta_path = session_dir / "session.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"Session file not found: {meta_path}")

        with meta_path.open(encoding="utf-8") as f:
            meta = json.load(f)

        session = cls(target=meta["target"], session_dir=session_dir)
        session.created_at = meta.get("created_at", session.created_at)
        session.current_phase = meta.get("current_phase", 1)

        for phase in range(1, 5):
            key = f"phase{phase}"
            phase_path = session_dir / f"{key}.json"
            if phase_path.exists():
                try:
                    with phase_path.open(encoding="utf-8") as f:
                        session.result_store[key] = json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass  # Keep empty dict for corrupt phase files

        return session

    # ── Listing ───────────────────────────────────────────────────

    @staticmethod
    def list_sessions(base_dir: Path | None = None) -> list[dict[str, Any]]:
        """Return metadata for all saved sessions, newest first."""
        base = base_dir or SESSIONS_DIR
        if not base.exists():
            return []

        sessions: list[dict[str, Any]] = []
        for session_dir in sorted(base.iterdir(), reverse=True):
            meta_path = session_dir / "session.json"
            if not meta_path.exists():
                continue
            try:
                with meta_path.open(encoding="utf-8") as f:
                    meta = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            sessions.append({
                "dir": str(session_dir),
                "target": meta.get("target", "unknown"),
                "created_at": meta.get("created_at", ""),
                "current_phase": meta.get("current_phase", 1),
            })

        return sessions

    # ── Mutation helpers ──────────────────────────────────────────

    def update_phase(self, phase: int, data: dict[str, Any]) -> None:
        """Merge data into a phase result dict and auto-save."""
        key = f"phase{phase}"
        self.result_store[key].update(data)
        self.save_phase(phase)

    def set_phase(self, phase: int) -> None:
        """Update current phase and persist session metadata."""
        self.current_phase = phase
        self.save()
