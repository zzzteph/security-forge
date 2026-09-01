# security-forge — container image.
#
# Bundles the pipeline with Python, git, ripgrep, and the Docker CLI + compose
# plugin, so it can run its verification sandbox against a HOST Docker daemon
# (Docker-out-of-Docker: mount /var/run/docker.sock and use --network host on Linux).
# Both the default claude-code backend and the native litellm backend are ready.
#
# Build (multi-arch handled by CI):   docker build -t security-forge .
# Lean, no Node/Claude (litellm only): docker build --build-arg INSTALL_CLAUDE=false -t security-forge .
FROM python:3.12-slim-bookworm

ARG INSTALL_CLAUDE=true
ARG NODE_MAJOR=20

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    SECFORGE_DATA_DIR=/data

# Base tools + Docker CLI/compose plugin. The CLI talks to a mounted host daemon;
# no dockerd runs inside this image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git ripgrep ca-certificates curl gnupg \
 && install -m0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
 && chmod a+r /etc/apt/keyrings/docker.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
 && rm -rf /var/lib/apt/lists/*

# Optional: Node + Claude Code CLI (the default backend). Skip with
# --build-arg INSTALL_CLAUDE=false for a lean image that runs `--backend litellm`
# (which can still drive Claude via `--model anthropic/…` + ANTHROPIC_API_KEY).
RUN if [ "$INSTALL_CLAUDE" = "true" ]; then \
      curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
      && apt-get install -y --no-install-recommends nodejs \
      && npm install -g @anthropic-ai/claude-code \
      && npm cache clean --force \
      && rm -rf /var/lib/apt/lists/* ; \
    fi

WORKDIR /app

# Python deps first (better layer caching). litellm powers the CLI-free backend.
COPY requirements.txt ./
RUN pip install -r requirements.txt litellm

COPY . /app

# All run artifacts (db, knowledge, reports, logs) live in this mounted volume,
# never in the image — so results persist and nothing sensitive is baked in.
VOLUME ["/data"]

# `docker run … security-forge <args>` passes args straight to the orchestrator.
# For a shell:  docker run --entrypoint bash -it security-forge
ENTRYPOINT ["python", "orchestrate.py"]
CMD ["--help"]
