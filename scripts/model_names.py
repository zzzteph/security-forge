"""Conservative CLI model aliases and routing; no model availability assumptions."""
import re


def _compact(model: str) -> str:
    return re.sub(r"\s+", "", (model or "").strip().lower()).replace("_", "-")


def infer_backend(model: str) -> str:
    name = _compact(model)
    if name.startswith("anthropic/"):
        name = name.split("/", 1)[1]
    if re.match(r"^(?:claude(?:-|$)|(?:opus|sonnet|haiku|fable)(?:[-.\d\[]|$))", name):
        return "claude-code"
    if name.startswith("openai/"):
        name = name.split("/", 1)[1]
    if re.match(r"^(?:(?:gpt|chatgpt|codex)(?:[-./\d]|$)|o[134](?:[-.]|$))", name):
        return "codex"
    return ""


def select_backend(model: str, explicit: str = "", fallback: str = "claude-code",
                   agent_cmd: str = "") -> str:
    if explicit and explicit != "auto":
        return explicit
    if agent_cmd:
        return "cli-adapter"
    return infer_backend(model) or (fallback if fallback and fallback != "auto" else "claude-code")


def normalize_claude(model: str) -> str:
    name = _compact(model)
    if name.startswith("anthropic/"):
        name = name.split("/", 1)[1]
    if name in {"opus", "sonnet", "haiku", "default"}:
        return name
    match = re.fullmatch(r"(?:claude-?)?(opus|sonnet|haiku|fable)[-.]?(\d+(?:[.-]\d+)*)(\[1m\])?", name)
    if match:
        family, version, context = match.groups()
        return f"claude-{family}-{version.replace('.', '-')}{context or ''}"
    if name.startswith("claude-"):
        return name
    return (model or "").strip()


def normalize_codex(model: str) -> str:
    name = _compact(model)
    if name.startswith("openai/"):
        name = name.split("/", 1)[1]
    if name in {"codex", "chatgpt", "gpt"}:
        return ""  # Use the installed CLI's configured default.
    if name.startswith("chatgpt-") and name.endswith("-latest"):
        return name
    # ChatGPT 5.4 / GPT5.4 / GPT_5_4 -> gpt-5.4. Keep suffixes and snapshots.
    match = re.fullmatch(r"(?:gpt|chatgpt)-?(\d+)(?:[.-](\d{1,2})(?!\d))?(o)?(.*)", name)
    if match:
        major, minor, omni, suffix = match.groups()
        if suffix and not suffix.startswith("-"):
            suffix = "-" + suffix
        return f"gpt-{major}{'.' + minor if minor else ''}{omni or ''}{suffix}"
    if re.fullmatch(r"o[134](?:-.*)?", name) or name.startswith("codex-"):
        return name
    return (model or "").strip()
