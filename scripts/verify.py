"""Sandboxed dynamic-verification helpers.

The finding-verifier subagent uses these to actually run the target app and
prove a vulnerability is reachable (not just present in source). Everything is
namespaced under `security-forge_` and runs on a dedicated bridge network with
resource caps, ports bound to 127.0.0.1 only, and no host bind mounts, so the
untrusted target code stays boxed in. `nuke` tears the whole sandbox down. The
container runtime is docker, or podman as a fallback when docker is absent (see
common.container_runtime).

SAFETY NOTE: this builds and runs untrusted third-party code. The container
runtime is a strong boundary but not perfect isolation. Run on a machine you are
willing to treat as the blast radius, keep the runtime updated, and prefer a VM
if the target is high-risk. The sandbox has network egress by default (apps
often need it to boot); set --no-egress to cut it.

CLI:
    python scripts/verify.py net-up
    python scripts/verify.py pull   --image kartoza/geoserver:2.26.0   # pre-pull a big base image (long timeout)
    python scripts/verify.py build  --tag app --path target [--file target/Dockerfile]
    python scripts/verify.py run    --image app --name web --port 8080:8080 [--env K=V ...] [--no-egress] [--no-pull]
    python scripts/verify.py compose-up   [--file target/docker-compose.yml]
    python scripts/verify.py probe  --url http://127.0.0.1:8080/ [--method GET] [--data '...'] [--header 'K: V' ...]
    python scripts/verify.py logs   --name web [--tail 200]
    python scripts/verify.py exec   --name web -- id
    python scripts/verify.py ps
    python scripts/verify.py stop   --name web
    python scripts/verify.py nuke
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONTAINER_CLI, TARGET_DIR, run, eprint, configure_stdio  # noqa: E402

configure_stdio()

NET = "security-forge_net"
PREFIX = "security-forge_"
COMPOSE_PROJECT = "security-forge_target"


def _out(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def net_up(internal: bool = False) -> dict:
    rc, out, _ = run([CONTAINER_CLI, "network", "inspect", NET])
    if rc == 0:
        return {"network": NET, "created": False}
    cmd = [CONTAINER_CLI, "network", "create", "--driver", "bridge"]
    if internal:
        cmd.append("--internal")
    cmd.append(NET)
    rc, out, err = run(cmd)
    if rc != 0:
        raise SystemExit(f"[verify] network create failed: {err}")
    return {"network": NET, "created": True}


def build(tag: str, path: str = "target", dockerfile: str | None = None) -> dict:
    image = f"{PREFIX}{tag}"
    ctx = str((Path(path).resolve()))
    cmd = [CONTAINER_CLI, "build", "-t", image]
    if dockerfile:
        cmd += ["-f", str(Path(dockerfile).resolve())]
    cmd += [ctx]
    rc, out, err = run(cmd, timeout=3600)
    return {"image": image, "ok": rc == 0, "log_tail": (err or out)[-1500:]}


def _resolve_image(image: str) -> str:
    """Map an image arg to the ref docker will run: a bare local build name gets
    the `security-forge_` prefix; an already-prefixed name or a real registry ref
    (has a ':' tag or a '/' path) is used as-is."""
    if image.startswith(PREFIX):
        return image
    return image if (":" in image or "/" in image) else f"{PREFIX}{image}"


def pull(image: str) -> dict:
    """Pre-pull an EXTERNAL image with a generous timeout. A large public base
    image (a full app image like a database or a GeoServer distribution) can take
    minutes to fetch; doing it here — rather than implicitly inside `run` — means
    the pull is not bounded by the short container-start timeout and won't get
    killed half-way. Local `security-forge_*` build tags have nothing to pull."""
    ref = _resolve_image(image)
    if ref.startswith(PREFIX):
        return {"image": ref, "pulled": False, "reason": "local build tag"}
    rc, out, err = run([CONTAINER_CLI, "pull", ref], timeout=3600)
    return {"image": ref, "pulled": rc == 0, "log_tail": (err or out)[-1200:]}


def run_container(image: str, name: str, ports: list[str], envs: list[str],
                  no_egress: bool = False, no_pull: bool = False) -> dict:
    net_up(internal=no_egress)
    full = f"{PREFIX}{name}"
    run([CONTAINER_CLI, "rm", "-f", full])
    ref = _resolve_image(image)
    # Pre-pull external images on a long timeout so a big fetch isn't counted
    # against (and killed by) the container-start timeout below. Cached across
    # runs — `nuke` removes containers + the network, never images — so only the
    # first target that needs an image pays for the pull.
    if not ref.startswith(PREFIX) and not no_pull:
        pull(ref)
    cmd = [
        CONTAINER_CLI, "run", "-d", "--name", full,
        "--network", NET,
        "--memory", "2g", "--cpus", "2", "--pids-limit", "512",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
    ]
    for p in ports:  # bind to loopback only
        host, _, cont = p.partition(":")
        cont = cont or host
        cmd += ["-p", f"127.0.0.1:{host}:{cont}"]
    for e in envs:
        cmd += ["-e", e]
    cmd.append(ref)
    rc, out, err = run(cmd, timeout=600)
    return {"name": full, "ok": rc == 0, "id": out.strip()[:12], "error": err.strip()[:400]}


def compose_up(file: str | None = None) -> dict:
    compose = file or _find_compose()
    if not compose:
        raise SystemExit("no docker-compose file found; pass --file")
    cmd = [CONTAINER_CLI, "compose", "-p", COMPOSE_PROJECT, "-f", str(Path(compose).resolve()),
           "up", "-d", "--build"]
    rc, out, err = run(cmd, cwd=TARGET_DIR, timeout=3600)
    return {"compose": compose, "ok": rc == 0, "log_tail": (err or out)[-1500:]}


def compose_down(file: str | None = None) -> dict:
    compose = file or _find_compose()
    cmd = [CONTAINER_CLI, "compose", "-p", COMPOSE_PROJECT]
    if compose:
        cmd += ["-f", str(Path(compose).resolve())]
    cmd += ["down", "-v", "--remove-orphans"]
    rc, out, err = run(cmd, cwd=TARGET_DIR, timeout=600)
    return {"ok": rc == 0}


def _find_compose() -> str | None:
    for n in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        p = TARGET_DIR / n
        if p.exists():
            return str(p)
    return None


def probe(url: str, method: str = "GET", data: str | None = None,
          headers: list[str] | None = None, retries: int = 5) -> dict:
    hdrs = {}
    for h in headers or []:
        k, _, v = h.partition(":")
        hdrs[k.strip()] = v.strip()
    body = data.encode("utf-8") if data is not None else None
    last_err = None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs, method=method.upper())
            t0 = time.monotonic()
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read(65536)
                return {
                    "url": url, "status": resp.status,
                    "elapsed_ms": int((time.monotonic() - t0) * 1000),
                    "headers": dict(resp.headers),
                    "body": content.decode("utf-8", "replace"),
                    "body_len": len(content),
                }
        except urllib.error.HTTPError as e:  # noqa: PERF203
            content = e.read(65536)
            return {"url": url, "status": e.code, "http_error": True,
                    "body": content.decode("utf-8", "replace"), "headers": dict(e.headers or {})}
        except Exception as e:  # noqa: BLE001  (app may still be booting)
            last_err = str(e)
            time.sleep(2)
    return {"url": url, "status": None, "error": last_err}


def logs(name: str, tail: int = 200) -> dict:
    full = name if name.startswith(PREFIX) else f"{PREFIX}{name}"
    rc, out, err = run([CONTAINER_CLI, "logs", "--tail", str(tail), full])
    return {"name": full, "logs": (out + err)[-6000:]}


def exec_in(name: str, argv: list[str]) -> dict:
    full = name if name.startswith(PREFIX) else f"{PREFIX}{name}"
    rc, out, err = run([CONTAINER_CLI, "exec", full, *argv], timeout=120)
    return {"name": full, "rc": rc, "stdout": out[-4000:], "stderr": err[-2000:]}


def ps() -> dict:
    rc, out, _ = run([CONTAINER_CLI, "ps", "-a", "--filter", f"name={PREFIX}",
                      "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}"])
    return {"containers": [ln for ln in out.splitlines() if ln.strip()]}


def stop(name: str) -> dict:
    full = name if name.startswith(PREFIX) else f"{PREFIX}{name}"
    run([CONTAINER_CLI, "rm", "-f", full])
    return {"stopped": full}


def nuke() -> dict:
    """Remove every security-forge_* container, the compose project, and the network."""
    compose_down()
    rc, out, _ = run([CONTAINER_CLI, "ps", "-aq", "--filter", f"name={PREFIX}"])
    ids = [x for x in out.split() if x]
    if ids:
        run([CONTAINER_CLI, "rm", "-f", *ids])
    run([CONTAINER_CLI, "network", "rm", NET])
    return {"nuked": True, "removed_containers": len(ids)}


def main() -> None:
    ap = argparse.ArgumentParser(description="security-forge dynamic-verification sandbox")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("net-up")
    p = sub.add_parser("pull"); p.add_argument("--image", required=True)
    p = sub.add_parser("build"); p.add_argument("--tag", required=True); p.add_argument("--path", default="target"); p.add_argument("--file")
    p = sub.add_parser("run"); p.add_argument("--image", required=True); p.add_argument("--name", required=True)
    p.add_argument("--port", action="append", default=[]); p.add_argument("--env", action="append", default=[]); p.add_argument("--no-egress", action="store_true")
    p.add_argument("--no-pull", action="store_true", help="skip the pre-pull (image is already local)")
    p = sub.add_parser("compose-up"); p.add_argument("--file")
    p = sub.add_parser("compose-down"); p.add_argument("--file")
    p = sub.add_parser("probe"); p.add_argument("--url", required=True); p.add_argument("--method", default="GET")
    p.add_argument("--data"); p.add_argument("--header", action="append", default=[])
    p = sub.add_parser("logs"); p.add_argument("--name", required=True); p.add_argument("--tail", type=int, default=200)
    p = sub.add_parser("exec"); p.add_argument("--name", required=True); p.add_argument("argv", nargs=argparse.REMAINDER)
    sub.add_parser("ps")
    p = sub.add_parser("stop"); p.add_argument("--name", required=True)
    sub.add_parser("nuke")

    a = ap.parse_args()
    if a.cmd == "net-up":
        _out(net_up())
    elif a.cmd == "pull":
        _out(pull(a.image))
    elif a.cmd == "build":
        _out(build(a.tag, a.path, a.file))
    elif a.cmd == "run":
        _out(run_container(a.image, a.name, a.port, a.env, a.no_egress, a.no_pull))
    elif a.cmd == "compose-up":
        _out(compose_up(a.file))
    elif a.cmd == "compose-down":
        _out(compose_down(a.file))
    elif a.cmd == "probe":
        _out(probe(a.url, a.method, a.data, a.header))
    elif a.cmd == "logs":
        _out(logs(a.name, a.tail))
    elif a.cmd == "exec":
        argv = a.argv[1:] if a.argv and a.argv[0] == "--" else a.argv
        _out(exec_in(a.name, argv))
    elif a.cmd == "ps":
        _out(ps())
    elif a.cmd == "stop":
        _out(stop(a.name))
    elif a.cmd == "nuke":
        _out(nuke())


if __name__ == "__main__":
    main()
