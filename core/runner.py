import asyncio
import shlex
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class RunResult:
    """Holds the result of a completed subprocess execution."""
    command: str
    returncode: int
    stdout: str
    stderr: str
    success: bool = field(init=False)

    def __post_init__(self) -> None:
        self.success = self.returncode == 0


async def stream_command(
    command: str,
    on_stdout: Callable[[str], None] | None = None,
    on_stderr: Callable[[str], None] | None = None,
    timeout: float | None = None,
) -> RunResult:
    """Run an external tool asynchronously, streaming stdout line-by-line.

    on_stdout / on_stderr are called for each line as it arrives so the UI
    can update in real time.  The process is killed on timeout.
    """
    args = shlex.split(command)
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    async def _read(stream: asyncio.StreamReader, buf: list[str], cb: Callable[[str], None] | None) -> None:
        while True:
            line = await stream.readline()
            if not line:
                break
            decoded = line.decode(errors="replace")
            buf.append(decoded)
            if cb:
                cb(decoded)

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
        process.kill()
        await process.wait()

    return RunResult(
        command=command,
        returncode=process.returncode if process.returncode is not None else -1,
        stdout="".join(stdout_lines),
        stderr="".join(stderr_lines),
    )


async def run_command(command: str, timeout: float | None = None) -> RunResult:
    """Run a command and return its full output after completion (no streaming)."""
    return await stream_command(command, timeout=timeout)
