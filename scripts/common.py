"""Shared helpers: paths, config/env loading, subprocess, fingerprints.

Everything is resolved relative to the repo root (the parent of scripts/), so
the whole folder can be copied per target and stays self-contained.
"""
from __future__ import annotations

import datetime
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# --- Paths ------------------------------------------------------------------
# ROOT is this copy of the CODE (scripts/, opt/, sast/, config.yaml …).
ROOT = Path(__file__).resolve().parent.parent

# DATA_ROOT is where run ARTIFACTS go: db/, logs/, reports/, pocs/, knowledge/,
# and the disposable target/ + state/ scratch. Defaults to ROOT, but
# SECFORGE_DATA_DIR redirects it — e.g. so an installed plugin (or an org-wide
# orchestrator run) writes to a visible folder instead of the hidden
# ~/.claude/plugins/... cache. Code is read from ROOT; results are written here.
DATA_ROOT = Path(os.environ.get("SECFORGE_DATA_DIR") or ROOT).expanduser().resolve()


def is_local_path(value: str) -> bool:
    """True when `value` names a LOCAL source folder rather than a remote git URL:
    a `file://` URL, an absolute/relative POSIX path (`/…`, `./…`, `../…`, `~/…`),
    a Windows drive path (`C:\\…`), or a UNC share (`\\\\host\\…`). Purely by shape,
    so the answer is stable even after the folder moves or disappears."""
    s = (value or "").strip()
    if not s:
        return False
    if s.startswith("file://"):
        return True
    if s in (".", "..") or s.startswith(("/", "./", "../", "~/", "~\\", ".\\", "..\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", s):     # C:\ or C:/
        return True
    if s.startswith("\\\\"):                # UNC \\server\share
        return True
    return False


def local_path_of(value: str) -> str:
    """The filesystem path a local target points at (strips a `file://` scheme)."""
    s = (value or "").strip()
    return s[len("file://"):] if s.startswith("file://") else s


def target_slug(value: str) -> str:
    """Normalize a repo URL (or an existing slug) to a filesystem-safe
    host/owner/repo key, so ONE security-forge copy can track MANY targets.

    'https://u:tok@github.com/owner/App.git' -> 'github.com/owner/App'
    'git@github.com:owner/app.git'           -> 'github.com/owner/app'
    'github.com/owner/app' (already a slug)  -> 'github.com/owner/app'
    '/home/me/projectX'  (a local folder)    -> 'local/projectX'
    """
    s = (value or "").strip()
    if not s:
        return ""
    if is_local_path(s):                 # a local source folder -> local/<basename>
        p = local_path_of(s).replace("\\", "/").rstrip("/")
        base = p.split("/")[-1] or "local"
        return "local/" + (re.sub(r"[^A-Za-z0-9._-]", "-", base) or "local")
    if "://" in s:                       # strip scheme
        s = s.split("://", 1)[1]
    elif s.startswith("git@"):           # scp-like ssh form
        s = s[len("git@"):].replace(":", "/", 1)
    if "@" in s:                         # strip user:pass@ credentials
        s = s.split("@", 1)[1]
    if s.endswith(".git"):
        s = s[:-4]
    s = s.strip("/").replace("\\", "/")
    s = re.sub(r"[^A-Za-z0-9._/-]", "-", s)   # only path-safe chars
    return re.sub(r"/{2,}", "/", s)


# One env var IS the entry point: SECFORGE_TARGET_REPO (the URL) keys every path.
# SECFORGE_TARGET may carry a pre-computed slug; otherwise we derive it from the
# repo URL. Unset -> legacy single-target layout (backward compatible).
_SLUG = target_slug(os.environ.get("SECFORGE_TARGET")
                    or os.environ.get("SECFORGE_TARGET_REPO") or "")

KNOWLEDGE_ROOT = DATA_ROOT / "knowledge"   # per-target model + findings + notifications.log
if _SLUG:
    TARGET_DIR = DATA_ROOT / "target" / _SLUG      # the cloned target repository
    STATE_DIR = DATA_ROOT / "state" / _SLUG        # ephemeral per-target scratch
    KNOWLEDGE_DIR = KNOWLEDGE_ROOT / _SLUG          # model.json + knowledge docs + findings
else:
    TARGET_DIR = DATA_ROOT / "target"
    STATE_DIR = DATA_ROOT / "state"
    KNOWLEDGE_DIR = KNOWLEDGE_ROOT
LOG_DIR = DATA_ROOT / "logs"


def container_runtime() -> str:
    """The container CLI to drive: docker if present, else podman.

    security-forge speaks the docker CLI; podman is command-line compatible, so
    when docker is not installed we transparently fall back to podman (its `run`,
    `build`, `network`, `compose`, `logs`, `exec`, `ps`, `rm` all mirror docker).
    Override with SECFORGE_CONTAINER_CLI to force a specific runtime.
    """
    override = os.environ.get("SECFORGE_CONTAINER_CLI", "").strip()
    if override:
        return override
    for cli in ("docker", "podman"):
        if shutil.which(cli):
            return cli
    return "docker"   # nothing found; callers degrade gracefully when it's absent


CONTAINER_CLI = container_runtime()


def configure_stdio() -> None:
    """Force UTF-8 on stdout/stderr so non-ASCII findings never crash a print.

    Windows defaults a redirected pipe to cp1252; target code snippets, secrets,
    or non-Latin text would otherwise raise UnicodeEncodeError mid-cycle.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


def ensure_dirs() -> None:
    for d in (STATE_DIR, LOG_DIR, KNOWLEDGE_DIR):
        d.mkdir(parents=True, exist_ok=True)


def target_repo(cfg: dict) -> str:
    """The repo to analyze. SECFORGE_TARGET_REPO env overrides config.yaml, so
    the whole flow can be pointed at a repo with one env var (the entry point)."""
    env = os.environ.get("SECFORGE_TARGET_REPO", "").strip()
    if env:
        return env
    return ((cfg.get("target") or {}).get("repo") or "").strip()


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def eprint(*a) -> None:
    print(*a, file=sys.stderr, flush=True)


def load_env() -> None:
    """Load .env (KEY=VALUE) into os.environ without overriding real env vars."""
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


def load_config() -> dict:
    """Load config.yaml from the repo root."""
    try:
        import yaml  # type: ignore
    except ImportError:
        raise SystemExit(
            "PyYAML is required. Install deps with: python -m pip install -r requirements.txt"
        )
    cfg_path = ROOT / "config.yaml"
    if not cfg_path.exists():
        raise SystemExit(
            "config.yaml not found. Copy config.example.yaml -> config.yaml and set target.repo."
        )
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def run(cmd, cwd=None, timeout=None, check=False, env=None):
    """Run a command (argv list). Returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or ""), f"timeout after {timeout}s"
    except OSError as e:
        # covers missing executable (FileNotFoundError) and missing/invalid cwd
        # (NotADirectoryError on Windows) — treat as a soft failure, not a crash.
        return 127, "", str(e)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {cmd}\n{proc.stderr}")
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def fingerprint(*parts) -> str:
    """Stable short id used to dedupe a finding across scans."""
    h = hashlib.sha1()
    for p in parts:
        h.update(str(p).encode("utf-8", "ignore"))
        h.update(b"\x00")
    return h.hexdigest()[:16]


SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}


def sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.get((sev or "UNKNOWN").upper(), 0)
