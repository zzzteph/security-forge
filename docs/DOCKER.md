# Running security-forge in Docker

security-forge is packaged as a container image that bundles the pipeline with
Python, `git`, `ripgrep`, and the Docker CLI + compose plugin. The one thing to
understand up front: **security-forge runs Docker itself** — its verification step
builds and runs the target application in throwaway containers to prove a finding
is real. So the container needs access to a Docker daemon.

## Image

Published to GitHub Container Registry on every push, multi-arch (`linux/amd64`
and `linux/arm64`, so it runs on a Raspberry Pi):

```bash
docker pull ghcr.io/zzzteph/security-forge:latest
```

Image tags:

| You push… | Image tags produced |
|---|---|
| a commit to the default branch | `latest`, `main`, `sha-<short>` |
| a commit to any other branch | `<branch>`, `sha-<short>` |
| a git tag `v1.2.3` | `1.2.3`, `1.2`, `1` (the bare major is skipped for `0.x`) |

So to cut a release, tag a commit and push the tag (keep it in step with the
plugin version in `.claude-plugin/plugin.json`):

```bash
git tag v0.20.0 && git push origin v0.20.0     # publishes ghcr.io/…:0.20.0 and :0.20
```

Pin a release in production with `ghcr.io/zzzteph/security-forge:0.20`, or track the
latest release line with `:0` once you're past `1.0` — `:latest` follows the default
branch, which may be ahead of the newest release.

> The GHCR package is **private** on first publish. For anonymous `docker pull`,
> set its visibility to Public under the repo's *Packages* settings; otherwise run
> `docker login ghcr.io` (username = your GitHub handle, password = a PAT with
> `read:packages`) first.

Build it yourself instead:

```bash
docker build -t security-forge .
# lean image without Node/Claude Code (uses the litellm backend):
docker build --build-arg INSTALL_CLAUDE=false -t security-forge .
```

## Giving the container a Docker daemon (Docker-out-of-Docker)

The simplest, reliable setup on a **Linux host** (mount the host's Docker socket
and share its network):

```bash
docker run --rm -it \
  --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/sf-data:/data" \
  -e ANTHROPIC_API_KEY=sk-... \
  ghcr.io/zzzteph/security-forge:latest --path /data/mysrc --model opus4.8
```

Why each flag:

- **`-v /var/run/docker.sock:/var/run/docker.sock`** — the verifier's
  `docker build/run/compose` commands drive the *host* daemon. The sandbox
  containers run as siblings on the host (namespaced `security-forge_*` and torn
  down after each run).
- **`--network host`** (Linux) — the sandbox publishes ports on `127.0.0.1` and
  the verifier probes `127.0.0.1`; host networking makes those the *same*
  loopback, so verification and the `verify-poc` gate work. Without it the probes
  can't reach the sibling containers.
- **`-v "$PWD/sf-data:/data"`** — all results (`db/`, `knowledge/`, `reports/`,
  `logs/`) persist here (`SECFORGE_DATA_DIR=/data` is baked in). Put local source
  you want to analyze here too and point `--path /data/<folder>` at it.

> **macOS / Windows (Docker Desktop):** `--network host` doesn't bridge to the VM
> the same way. The socket mount still works, but the loopback-probe step may not
> line up — prefer running the image on a Linux host/VM for the verification step.

### Stronger isolation (Docker-in-Docker)

If you'd rather not expose the host daemon, run a `dind` daemon and point the
image at it (heavier, needs `--privileged`):

```bash
docker network create sf
docker run -d --privileged --name sf-dind --network sf \
  -e DOCKER_TLS_CERTDIR= docker:dind --host=tcp://0.0.0.0:2375
docker run --rm -it --network sf \
  -e DOCKER_HOST=tcp://sf-dind:2375 \
  -v "$PWD/sf-data:/data" -e ANTHROPIC_API_KEY=sk-... \
  ghcr.io/zzzteph/security-forge:latest --path /data/mysrc --model opus4.8
```

## Picking a backend + keys

Pass provider keys as env vars (they never appear in the logs):

| Backend | Run with | Key |
|---|---|---|
| Claude Code (default) | `--model opus4.8` | `-e ANTHROPIC_API_KEY=…` |
| LiteLLM (no CLI) | `--backend litellm --model openai/gpt-5` | `-e OPENAI_API_KEY=…` |
| LiteLLM → Claude API | `--backend litellm --model anthropic/claude-3-7-sonnet` | `-e ANTHROPIC_API_KEY=…` |
| Local model | `--backend litellm --model ollama/llama3 --agent-base-url http://localhost:11434` | none |

Private repo listing/cloning needs `-e GITHUB_TOKEN=…`.

## docker-compose

A `docker-compose.yml` at the repo root wires up the socket, host networking, the
`/data` volume, and the key env vars:

```bash
ANTHROPIC_API_KEY=sk-... docker compose run --rm security-forge \
  --path /data/mysrc --model opus4.8
```

## Examples

```bash
# whole org, native LiteLLM backend, results + reports persisted in ./sf-data
docker run --rm -it --network host \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/sf-data:/data" \
  -e OPENAI_API_KEY=sk-... \
  ghcr.io/zzzteph/security-forge:latest --org OWNER --backend litellm --model openai/gpt-5

# re-check only the repos you've already analyzed (no org discovery)
docker run --rm -it --network host \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/sf-data:/data" \
  -e ANTHROPIC_API_KEY=sk-... \
  ghcr.io/zzzteph/security-forge:latest --known-only --model opus4.8

# browse everything found, across all projects
cat sf-data/reports/INDEX.txt

# open a shell in the image
docker run --rm -it --entrypoint bash ghcr.io/zzzteph/security-forge:latest
```

## Notes & limits

- The container runs as **root** so it can use the mounted Docker socket. Treat the
  host as the blast radius (it runs untrusted target code in sibling containers) —
  run it on a machine you're willing to treat that way, keep Docker updated.
- A target that ships a `docker-compose.yml` using **host bind mounts** may not
  verify cleanly under DooD (its paths resolve on the host daemon, not inside this
  container). security-forge's own sandbox avoids bind mounts.
- Everything the pipeline needs (`opt/`, `sast/`, `docs/`, `.claude/agents/`) is in
  the image; only your data/logs/secrets are excluded (`.dockerignore`).
