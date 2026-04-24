from dataclasses import dataclass, field


@dataclass
class Tool:
    """Represents a single executable tool within a phase."""
    id: str
    label: str
    command_template: str
    description: str
    optional: bool = False
    condition: str | None = None
    requires_input: list[str] = field(default_factory=list)


def build_command(tool: Tool, target: str, **kwargs: str) -> str:
    """Fill tool.command_template with target and any extra keyword arguments.

    Falls back gracefully if a placeholder has no matching kwarg — returns
    an empty string so the caller can detect and handle the missing input.
    """
    try:
        return tool.command_template.format(target=target, **kwargs)
    except KeyError:
        return ""
