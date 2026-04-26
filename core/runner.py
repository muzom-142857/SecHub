import asyncio
import os
import shlex
import signal
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class RunResult:
    """Holds the result of a completed subprocess execution."""
    command: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    success: bool = field(init=False)

    def __post_init__(self) -> None:
        self.success = self.returncode == 0 and not self.timed_out


@dataclass
class ProcessHandle:
    """Holds a reference to the running subprocess for external cancellation."""
    process: asyncio.subprocess.Process | None = None

    def cancel(self) -> None:
        if self.process and self.process.returncode is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    self.process.kill()
                except (ProcessLookupError, PermissionError):
                    pass


async def stream_command(
    command: str,
    on_stdout: Callable[[str], None] | None = None,
    on_stderr: Callable[[str], None] | None = None,
    timeout: float | None = None,
    handle: ProcessHandle | None = None,
) -> RunResult:
    """Run an external tool asynchronously, streaming stdout line-by-line.

    on_stdout / on_stderr are called for each line as it arrives so the UI
    can update in real time.  The process group is killed on timeout or cancellation.
    """
    args = shlex.split(command)
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )

    if handle is not None:
        handle.process = process

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    async def _read(
        stream: asyncio.StreamReader,
        buf: list[str],
        cb: Callable[[str], None] | None,
    ) -> None:
        while True:
            line = await stream.readline()
            if not line:
                break
            decoded = line.decode(errors="replace")
            buf.append(decoded)
            if cb:
                cb(decoded)

    def _kill_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill()
            except (ProcessLookupError, PermissionError):
                pass

    timed_out = False
    try:
        await asyncio.wait_for(
            asyncio.gather(
                _read(process.stdout, stdout_lines, on_stdout),
                _read(process.stderr, stderr_lines, on_stderr),
            ),
            timeout=timeout,
        )
        await process.wait()
    except asyncio.TimeoutError:
        timed_out = True
        _kill_group()
        await process.wait()
    except asyncio.CancelledError:
        _kill_group()
        await process.wait()
        raise
    finally:
        if handle is not None:
            handle.process = None

    return RunResult(
        command=command,
        returncode=process.returncode if process.returncode is not None else -1,
        stdout="".join(stdout_lines),
        stderr="".join(stderr_lines),
        timed_out=timed_out,
    )


async def run_command(command: str, timeout: float | None = None) -> RunResult:
    """Run a command and return its full output after completion (no streaming)."""
    return await stream_command(command, timeout=timeout)
