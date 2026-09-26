"""Local Codex CLI commands and JSONL events (no API SDK required)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from scripts.model_names import normalize_codex

ROOT = Path(__file__).resolve().parent.parent


def binary() -> str:
    return os.environ.get("CODEX_BIN") or shutil.which("codex") or "codex"


def home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex").expanduser()


def authenticated() -> bool | None:
    """Ask the CLI; a config directory alone does not establish a login."""
    try:
        result = subprocess.run([binary(), "login", "status"], capture_output=True,
                                timeout=5, stdin=subprocess.DEVNULL)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return None


def command(model: str = "", effort: str = "", executable: str | None = None,
            sandbox: str = "workspace-write", writable_dirs=(),
            output_file: Path | None = None) -> list[str]:
    """Read the prompt from stdin, retaining the user's Codex config and login."""
    cmd = [executable or binary(), "exec", "--json", "--color", "never",
           "--skip-git-repo-check", "--sandbox", sandbox, "--cd", str(ROOT)]
    model = normalize_codex(model)
    if model.strip():
        cmd += ["--model", model.strip()]
    # The shared UI scale includes 'max'; use high for model portability.
    level = {"normal": "medium", "max": "high"}.get(effort, effort)
    if level and level not in {"off", "default", "none"}:
        cmd += ["-c", "model_reasoning_effort=" + json.dumps(level)]
    for directory in dict.fromkeys(str(Path(d).expanduser().resolve())
                                   for d in writable_dirs if d):
        cmd += ["--add-dir", directory]
    if output_file is not None:
        cmd += ["--output-last-message", str(output_file)]
    return [*cmd, "-"]


class Events:
    """Track Codex's native events; cache/reasoning counts are usage subsets."""

    def __init__(self):
        self.turns = self.tools = 0
        self.input_tokens = self.cached_input_tokens = self.output_tokens = 0
        self.reasoning_output_tokens = 0
        self.last = "starting Codex"
        self.error = None
        self.completed = False
        self._tools_seen = set()

    def feed(self, event: dict) -> None:
        kind = event.get("type")
        if kind == "thread.started":
            self.last = "Codex session started"
        elif kind == "turn.started":
            self.turns += 1
        elif kind == "turn.completed":
            usage = event.get("usage") or {}
            for key in ("input_tokens", "cached_input_tokens", "output_tokens",
                        "reasoning_output_tokens"):
                setattr(self, key, getattr(self, key) + int(usage.get(key) or 0))
            self.completed = True
            self.error = None
        elif kind == "turn.failed":
            error = event.get("error") or {}
            self.error = error.get("message", "Codex turn failed") if isinstance(error, dict) else str(error)
        elif kind == "error":
            self.last = str(event.get("message") or "Codex error")[:160]
        elif kind in {"item.started", "item.updated", "item.completed"}:
            item = event.get("item") or {}
            item_type = item.get("type", "item")
            if item_type in {"command_execution", "file_change", "mcp_tool_call",
                             "web_search", "collab_tool_call"}:
                item_id = item.get("id")
                if item_id and item_id not in self._tools_seen:
                    self._tools_seen.add(item_id)
                    self.tools += 1
                detail = item.get("command") or item.get("tool") or item.get("query") or ""
                self.last = f"{item_type}: {' '.join(str(detail).split())[:100]}"
            elif item_type in {"agent_message", "reasoning"}:
                self.last = " ".join(str(item.get("text") or item_type).split())[:120]

    def usage(self) -> dict:
        return {key: getattr(self, key) for key in
                ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens")}
