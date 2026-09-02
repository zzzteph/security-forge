"""Target repository management: clone/update, diff, and shape detection.

The target is cloned into ./target inside this copy of the pipeline. Updates
are done with fetch + hard reset to the tracked branch so unattended runs never
hit an interactive merge prompt (the clone is a read-only analysis mirror).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (TARGET_DIR, STATE_DIR, run, eprint, target_repo, load_env,  # noqa: E402
                    is_local_path, local_path_of)

LAST_COMMIT = STATE_DIR / "last_commit.txt"
TREE_MANIFEST = STATE_DIR / "tree_manifest.json"

_GH_COM = {"github.com", "www.github.com"}


def _rmtree_force(path) -> None:
    """Remove a directory tree even when it holds read-only files — git writes
    read-only pack files into .git/objects, and a plain shutil.rmtree(ignore_errors)
    silently SKIPS them on Windows, leaving the dir non-empty so the next clone
    fails 'destination already exists'. This clears the read-only bit and retries."""
    import shutil
    import stat

    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:  # noqa: BLE001
            pass

    try:
        # Python 3.12+ prefers onexc; fall back to onerror on older/newer alike.
        try:
            shutil.rmtree(path, onexc=lambda f, p, e: _onerror(f, p, e))
        except TypeError:
            shutil.rmtree(path, onerror=_onerror)
    except Exception:  # noqa: BLE001
        pass


def _host_of(url: str) -> str:
    s = (url or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[1]
    return s.split("/", 1)[0].split(":", 1)[0]


def _git_credential_token(host: str) -> str:
    """Token from git's credential store (Git Credential Manager) for this host —
    the same creds a console `git clone` uses. Injected into the clone URL so the
    clone works even where GCM won't respond non-interactively."""
    try:
        r = subprocess.run(["git", "credential", "fill"],
                           input=f"protocol=https\nhost={host}\n\n",
                           capture_output=True, text=True, timeout=15,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        if r.returncode == 0:
            d = dict(ln.split("=", 1) for ln in r.stdout.splitlines() if "=" in ln)
            return (d.get("password") or "").strip()
    except Exception:  # noqa: BLE001
        pass
    return ""


def _token_for(host: str) -> str:
    """Token to inject into the clone URL: a host-specific env var wins, then the
    generic enterprise token, then classic GITHUB_TOKEN/GH_TOKEN, then git's
    credential store (the console's own creds)."""
    load_env()
    cands = ["GITHUB_TOKEN_" + re.sub(r"[^A-Za-z0-9]", "_", host).upper()]
    if host not in _GH_COM:
        cands += ["GHE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"]
    cands += ["GITHUB_TOKEN", "GH_TOKEN"]
    for name in cands:
        v = (os.environ.get(name) or "").strip()
        if v:
            return v
    return _git_credential_token(host)


def _authed_url(url: str) -> str:
    """Inject a token into an https clone URL for private repos. Leaves URLs that
    already carry credentials, ssh URLs, and token-less hosts untouched. The
    clone is disposable and nuked after each session, so the credential living in
    .git/config for its lifetime is acceptable."""
    s = (url or "").strip()
    if not s.startswith("https://") or "@" in s.split("://", 1)[1].split("/", 1)[0]:
        return s
    tok = _token_for(_host_of(s))
    if not tok:
        return s
    return "https://x-access-token:" + tok + "@" + s[len("https://"):]


def _git_env() -> dict:
    """Git env for clone/fetch. Default is fail-fast (no credential prompt) so an
    UNATTENDED agent session never hangs. But when SECFORGE_GIT_INTERACTIVE is set
    — which the orchestrator sets for its OWN pre-clone step (it's attached to the
    user's console, where git + GCM authenticate normally) — allow the normal
    prompt/credential-manager flow so private repos clone just like from the console."""
    env = {**os.environ}
    if not (os.environ.get("SECFORGE_GIT_INTERACTIVE") or "").strip():
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GCM_INTERACTIVE"] = "never"
    return env

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
    # CRITICAL (tool runs from inside its own git repo): pin GIT_DIR/GIT_WORK_TREE
    # to THIS clone so git can never walk up into security-forge's own repo. Without
    # it, a fetch/reset on a missing/broken target clone ascends to the parent and
    # `git reset --hard origin/main` HARD-RESETS the tool's own working tree. Pinned,
    # such a command fails cleanly ("not a git repository") instead of wiping it.
    env = _git_env()
    env["GIT_DIR"] = str(Path(cwd) / ".git")
    env["GIT_WORK_TREE"] = str(cwd)
    return run(["git", *args], cwd=cwd, env=env)


def _is_valid_clone() -> bool:
    """True only if TARGET_DIR is its OWN git repo with >=1 commit. Guards against a
    partial/interrupted clone (a .git with only objects/ and no HEAD) that would
    otherwise get stuck in the 'update' path forever and report no commit."""
    if not (TARGET_DIR / ".git").exists():
        return False
    rc, out, _ = git(["rev-parse", "--show-toplevel"])
    if rc != 0 or not out.strip():
        return False
    try:
        if Path(out.strip()).resolve() != Path(TARGET_DIR).resolve():
            return False
    except Exception:  # noqa: BLE001
        return False
    return git(["rev-parse", "--verify", "HEAD"])[0] == 0


def current_commit() -> str | None:
    if not _is_valid_clone():
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


def _tree_manifest(root: Path) -> dict:
    """Cheap signature of a non-git source tree: {relpath: 'size:mtime'}, skipping
    the usual noise dirs. Lets a LOCAL folder get real changed-file detection
    (incremental analysis) without git."""
    man: dict = {}
    if not root.is_dir():
        return man
    for p in root.rglob("*"):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if p.is_file():
            try:
                st = p.stat()
                man[rel.as_posix()] = f"{st.st_size}:{int(st.st_mtime)}"
            except OSError:
                continue
    return man


def _manifest_diff(old: dict, new: dict) -> list[str]:
    return sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))


def _copy_tree(src: Path, dst: Path) -> None:
    import shutil
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*SKIP_DIRS),
                    symlinks=False, ignore_dangling_symlinks=True)


def _prep_local(url: str, branch: str | None, depth, prev: str | None) -> dict:
    """Prepare a LOCAL source folder as the target. If it's a git repo, clone it
    into the throwaway target/ (keeps history, so diffs work like a remote); if
    it's just a folder of files, copy it and detect changes via a tree manifest."""
    src = Path(local_path_of(url)).expanduser().resolve()
    if not src.is_dir():
        raise SystemExit(f"[repo] local source folder not found: {src}")
    is_git = (src / ".git").is_dir()

    if is_git:
        if not (TARGET_DIR / ".git").exists():
            eprint(f"[repo] cloning local git repo {src}")
            args = ["clone"]
            if depth:
                args += ["--depth", str(depth)]
            if branch:
                args += ["--branch", branch]
            args += [str(src), str(TARGET_DIR)]
            rc, _, err = run(["git", *args], env=_git_env())
            if rc != 0:
                raise SystemExit(f"[repo] local clone failed: {err}")
        else:
            eprint("[repo] refreshing local clone")
            git(["fetch", "--all", "--prune", "--tags"])
            rc, out, _ = git(["rev-parse", "--abbrev-ref", "HEAD"])
            cur_branch = branch or (out.strip() if rc == 0 else "HEAD")
            if branch:
                git(["checkout", branch])
            git(["reset", "--hard", f"origin/{cur_branch}"])
        new = current_commit()
        changed = _diff_files(prev, new)
        return {"repo": str(src), "branch": branch, "prev_commit": prev,
                "commit": new, "changed_files": changed, "changed_count": len(changed),
                "is_first_scan": prev is None, "local": True, "vcs": "git"}

    # Non-git folder: copy it in and diff by file-signature manifest.
    eprint(f"[repo] copying local folder {src} (no git — using tree manifest)")
    _copy_tree(src, TARGET_DIR)
    old_man = {}
    if TREE_MANIFEST.exists():
        try:
            import json
            old_man = json.loads(TREE_MANIFEST.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            old_man = {}
    new_man = _tree_manifest(TARGET_DIR)
    import hashlib
    import json
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    TREE_MANIFEST.write_text(json.dumps(new_man, ensure_ascii=False), encoding="utf-8")
    tree_hash = hashlib.sha1(
        json.dumps(new_man, sort_keys=True).encode("utf-8")).hexdigest()
    changed = _manifest_diff(old_man, new_man) if old_man else []
    return {"repo": str(src), "branch": None, "prev_commit": prev,
            "commit": tree_hash, "changed_files": changed, "changed_count": len(changed),
            "is_first_scan": prev is None, "local": True, "vcs": "none"}


def clone_or_update(cfg: dict) -> dict:
    target = cfg.get("target", {}) or {}
    url = target_repo(cfg)   # SECFORGE_TARGET_REPO env overrides config.yaml
    branch = (target.get("branch") or "").strip() or None
    depth = target.get("depth")  # None = full history (needed for secret scanning)
    if not url:
        raise SystemExit("config.yaml: target.repo is empty. Set the GitHub URL "
                         "(or a local folder path) to analyze.")

    prev = read_last_commit()
    if is_local_path(url):               # a local source folder, not a remote URL
        return _prep_local(url, branch, depth, prev)
    if not _is_valid_clone():
        # No clone yet, or a broken/partial one from a killed run — wipe and clone fresh.
        if TARGET_DIR.exists():
            eprint("[repo] removing stale/partial clone before re-cloning")
            _rmtree_force(TARGET_DIR)
            if TARGET_DIR.exists():   # something is holding files (AV / open handle)
                raise SystemExit(f"[repo] could not remove stale clone at {TARGET_DIR} — "
                                 f"close anything using it (editor/AV/git) and retry.")
        eprint(f"[repo] cloning {url}")
        args = ["clone"]
        if depth:
            args += ["--depth", str(depth)]
        if branch:
            args += ["--branch", branch]
        args += [_authed_url(url), str(TARGET_DIR)]
        rc, _, err = run(["git", *args], env=_git_env())
        if rc != 0:
            # Don't leak an injected token if the URL is echoed back in the error.
            raise SystemExit(f"[repo] clone failed: {re.sub(r'x-access-token:[^@]+@', 'x-access-token:***@', err)}")
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
