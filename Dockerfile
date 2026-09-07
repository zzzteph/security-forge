# security-forge — ONE image, run as CLI or UI.
#
#   docker run ... ghcr.io/zzzteph/security-forge ui            # web UI on :8000 (default)
#   docker run ... ghcr.io/zzzteph/security-forge --org OWNER   # CLI orchestrator (static)
#   docker run ... ghcr.io/zzzteph/security-forge --path /data/src --backend litellm --model openai/gpt-5
#   docker run --entrypoint bash -it ghcr.io/zzzteph/security-forge   # a shell
#
# Static analysis only in the container (no `--verify`: that needs a Docker daemon /
# Docker-in-Docker — run it on a host instead). Bundles the agent CLIs so you can
# authorize claude/codex/gemini inside the container; logins persist on /data.
FROM python:3.12-slim-bookworm

ARG INSTALL_AGENTS=true
ARG NODE_MAJOR=20
ARG VUE_VERSION=3.4.21
ARG XTERM_VERSION=5.3.0
ARG XTERM_FIT_VERSION=0.8.0

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    SECFORGE_DATA_DIR=/data \
    HOME=/data/home \
    PORT=8000

# git + ripgrep (scanning) and WeasyPrint's runtime libs (pango/cairo/gdk-pixbuf) for PDF.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ripgrep ca-certificates curl \
      libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2 \
      libjpeg62-turbo libffi8 fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

# Agent CLIs (authorize inside the container; logins persist on /data via $HOME).
RUN if [ "$INSTALL_AGENTS" = "true" ]; then \
      curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
      && apt-get install -y --no-install-recommends nodejs \
      && npm install -g @anthropic-ai/claude-code @openai/codex @google/gemini-cli \
      && npm cache clean --force \
      && rm -rf /var/lib/apt/lists/* ; \
    fi

WORKDIR /app
# Python deps first for layer caching: engine (PyYAML) + UI (fastapi/uvicorn/weasyprint/…/litellm).
COPY requirements.txt ./requirements.txt
COPY webapp/requirements.txt ./webapp/requirements.txt
RUN pip install -r requirements.txt -r webapp/requirements.txt

COPY . /app

# Vendor front-end libs so the UI needs no CDN at runtime.
RUN mkdir -p webapp/static/vendor \
 && curl -fsSL "https://cdn.jsdelivr.net/npm/vue@${VUE_VERSION}/dist/vue.global.prod.js" \
      -o webapp/static/vendor/vue.global.prod.js \
 && curl -fsSL "https://cdn.jsdelivr.net/npm/xterm@${XTERM_VERSION}/lib/xterm.js" \
      -o webapp/static/vendor/xterm.js \
 && curl -fsSL "https://cdn.jsdelivr.net/npm/xterm@${XTERM_VERSION}/css/xterm.css" \
      -o webapp/static/vendor/xterm.css \
 && curl -fsSL "https://cdn.jsdelivr.net/npm/xterm-addon-fit@${XTERM_FIT_VERSION}/lib/xterm-addon-fit.js" \
      -o webapp/static/vendor/xterm-addon-fit.js \
 && chmod +x /app/docker-entrypoint.sh

VOLUME ["/data"]
EXPOSE 8000

# The entrypoint dispatches: first arg `ui` -> web server, anything else -> orchestrator.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["ui"]
