"""Target repository management: clone/update, diff, and shape detection.

The target is cloned into ./target inside this copy of the pipeline. Updates
are done with fetch + hard reset to the tracked branch so unattended runs never
hit an interactive merge prompt (the clone is a read-only analysis mirror).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import TARGET_DIR, STATE_DIR, run, eprint, target_repo  # noqa: E402

LAST_COMMIT = STATE_DIR / "last_commit.txt"

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
             "__pycache__", ".next", "target", ".gradle", ".idea"}

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".go": "go", ".rb": "ruby", ".php": "php", ".java": "java",
    ".rs": "rust", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cs": "csharp",
    ".sh": "shell", ".sol": "solidity", ".kt": "kotlin", ".scala": "scala", ".ex": "elixir",
}
MANIFESTS = {"requirements.txt", "pyproject.toml", "setup.py", "package.json", "go.mod",
             "Gemfile", "composer.json", "pom.xml", "build.gradle", "Cargo.toml",
             "yarn.lock", "package-lock.json", "poetry.lock"}
ENTRY_HINTS = {"app.py", "main.py", "manage.py", "wsgi.py", "asgi.py", "run.py",
               "server.js", "index.js", "app.js", "main.go", "main.rs", "Program.cs"}
COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


def git(args, cwd=TARGET_DIR):
    if cwd and not Path(cwd).exists():
        return 128, "", f"cwd does not exist: {cwd}"
    return run(["git", *args], cwd=cwd)


def current_commit() -> str | None:
    if not (TARGET_DIR / ".git").exists():
        return None
    rc, out, _ = git(["rev-parse", "HEAD"])
    return out.strip() if rc == 0 else None


def _diff_files(a: str | None, b: str | None) -> list[str]:
    if not a or not b or a == b:
        return []
    rc, out, _ = git(["diff", "--name-only", a, b])
    return [ln for ln in out.splitlines() if ln.strip()] if rc == 0 else []


def read_last_commit() -> str | None:
    return LAST_COMMIT.read_text(encoding="utf-8").strip() if LAST_COMMIT.exists() else None


def write_last_commit(commit: str | None) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    LAST_COMMIT.write_text(commit or "", encoding="utf-8")


def clone_or_update(cfg: dict) -> dict:
    target = cfg.get("target", {}) or {}
    url = target_repo(cfg)   # SECFORGE_TARGET_REPO env overrides config.yaml
    branch = (target.get("branch") or "").strip() or None
    depth = target.get("depth")  # None = full history (needed for secret scanning)
    if not url:
        raise SystemExit("config.yaml: target.repo is empty. Set the GitHub URL to analyze.")

    prev = read_last_commit()
    if not (TARGET_DIR / ".git").exists():
        eprint(f"[repo] cloning {url}")
        args = ["clone"]
        if depth:
            args += ["--depth", str(depth)]
        if branch:
            args += ["--branch", branch]
        args += [url, str(TARGET_DIR)]
        rc, _, err = run(["git", *args])
        if rc != 0:
            raise SystemExit(f"[repo] clone failed: {err}")
    else:
        eprint("[repo] updating existing clone")
        git(["fetch", "--all", "--prune", "--tags"])
        rc, out, _ = git(["rev-parse", "--abbrev-ref", "HEAD"])
        cur_branch = branch or (out.strip() if rc == 0 else "HEAD")
        if branch:
            git(["checkout", branch])
        git(["reset", "--hard", f"origin/{cur_branch}"])

    new = current_commit()
    changed = _diff_files(prev, new)
    return {
        "repo": url,
        "branch": branch,
        "prev_commit": prev,
        "commit": new,
        "changed_files": changed,
        "changed_count": len(changed),
        "is_first_scan": prev is None,
    }


def detect_shape() -> dict:
    """Cheap heuristic map of the repo: languages, manifests, docker, entrypoints."""
    shape = {
        "languages": {}, "manifests": [], "dockerfiles": [], "compose": [],
        "entrypoints": [], "env_files": [], "file_count": 0,
    }
    if not TARGET_DIR.exists():
        return shape
    for p in TARGET_DIR.rglob("*"):
        if any(part in SKIP_DIRS for part in p.relative_to(TARGET_DIR).parts[:-1]):
            continue
        if not p.is_file():
            continue
        shape["file_count"] += 1
        rel = p.relative_to(TARGET_DIR).as_posix()
        name = p.name
        ext = p.suffix.lower()
        if ext in EXT_LANG:
            lang = EXT_LANG[ext]
            shape["languages"][lang] = shape["languages"].get(lang, 0) + 1
        if name in MANIFESTS:
            shape["manifests"].append(rel)
        if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
            shape["dockerfiles"].append(rel)
        if name in COMPOSE_NAMES:
            shape["compose"].append(rel)
        if name in ENTRY_HINTS:
            shape["entrypoints"].append(rel)
        if name in (".env", ".env.example", ".env.sample") or name.startswith(".env."):
            shape["env_files"].append(rel)
    shape["languages"] = dict(sorted(shape["languages"].items(), key=lambda kv: -kv[1]))
    return shape
