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

## The container does STATIC analysis only — no verification

Verification builds and runs the target app in throwaway containers, which means
the tool needs to *drive a Docker daemon*. Doing that from **inside** a container
requires Docker-in-Docker (a privileged nested daemon), which we don't want. So:

> **`--verify` is not supported in the container.** The image runs static analysis
> — it maps the code, finds and reports vulnerabilities, and writes advisories, but
> does not stand the target up to reproduce a PoC.

Run it as static analysis (no socket, no host networking):

```bash
docker run --rm -it \
  -v "$PWD/sf-data:/data" \
  -e OPENAI_API_KEY=sk-... \
  ghcr.io/zzzteph/security-forge:latest --path /data/mysrc --backend litellm --model openai/gpt-5
```

`-v "$PWD/sf-data:/data"` persists everything (`db/`, `knowledge/`, `reports/`,
`logs/`); put source to analyze there and point `--path /data/<folder>` at it.

### Want verification (reproduced PoCs)? Run on a host, not in a container

Verification is a **host workflow**: run the orchestrator directly on a machine
that has Docker, so it can build/run targets on that daemon:

```bash
# on a Docker host (bare metal / VM), from a checkout of this repo:
python orchestrate.py --repo https://github.com/OWNER/REPO --verify --model opus4.8
```

That's the only supported path for `--verify`; the container image and the web UI
are static-only by design.

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
docker run --rm -it -v "$PWD/sf-data:/data" -e OPENAI_API_KEY=sk-... \
  ghcr.io/zzzteph/security-forge:latest --org OWNER --backend litellm --model openai/gpt-5

# re-check only the repos you've already analyzed (no org discovery)
docker run --rm -it -v "$PWD/sf-data:/data" -e OPENAI_API_KEY=sk-... \
  ghcr.io/zzzteph/security-forge:latest --known-only --backend litellm --model openai/gpt-5

# browse everything found, across all projects
cat sf-data/reports/INDEX.txt

# open a shell in the image
docker run --rm -it --entrypoint bash ghcr.io/zzzteph/security-forge:latest
```

## Notes & limits

- **Static only** — no `--verify` in the container (that needs a Docker daemon and
  would require Docker-in-Docker). Verify on a host instead (see above).
- Everything the pipeline needs (`opt/`, `sast/`, `docs/`, `.claude/agents/`) is in
  the image; only your data/logs/secrets are excluded (`.dockerignore`).
