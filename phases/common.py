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
    timeout: int | None = None
    display_only: bool = False
    api_tool: bool = False


def build_command(tool: Tool, target: str, **kwargs: str) -> str:
    """Fill tool.command_template with target and any extra keyword arguments.

    Returns an empty string if a required placeholder is missing.
    """
    try:
        return tool.command_template.format(target=target, **kwargs)
    except KeyError:
        return ""
