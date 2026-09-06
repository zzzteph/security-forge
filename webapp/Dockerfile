# security-forge UI — web control plane for continuous scanning.
# Build from the REPO ROOT so it can bundle the engine:
#   docker build -f webapp/Dockerfile -t security-forge-ui .
#
# Static analysis only (no verification), so NO Docker socket is needed at runtime.
# Default backend is litellm (CLI-free); build with --build-arg INSTALL_CLAUDE=true
# to also get the Claude Code CLI backend.
FROM python:3.12-slim-bookworm

# Install the agent CLIs so you can AUTHORIZE claude / codex / gemini inside the
# running container (docker exec -it ... claude|codex login). Set false for a lean
# litellm-only image. Package names/versions can be pinned to taste.
ARG INSTALL_AGENTS=true
ARG NODE_MAJOR=20
ARG VUE_VERSION=3.4.21

# HOME points at the mounted /data volume so CLI logins/config (~/.claude, ~/.codex,
# ~/.gemini) PERSIST across restarts. Created at startup (the volume shadows build).
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    SECFORGE_DATA_DIR=/data \
    HOME=/data/home

# git + ripgrep (scanning), and WeasyPrint's runtime libs (pango/cairo/gdk-pixbuf) for PDF.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ripgrep ca-certificates curl \
      libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2 \
      libjpeg62-turbo libffi8 fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

# Agent CLIs (Node-based): Claude Code, OpenAI Codex, Gemini CLI. Authorize them
# inside the container after startup, e.g.:
#   docker exec -it <container> claude        # interactive login (or set ANTHROPIC_API_KEY)
#   docker exec -it <container> codex login   # ChatGPT login (or set OPENAI_API_KEY)
#   docker exec -it <container> gemini        # Google login (or set GEMINI_API_KEY)
RUN if [ "$INSTALL_AGENTS" = "true" ]; then \
      curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
      && apt-get install -y --no-install-recommends nodejs \
      && npm install -g @anthropic-ai/claude-code @openai/codex @google/gemini-cli \
      && npm cache clean --force \
      && rm -rf /var/lib/apt/lists/* ; \
    fi

WORKDIR /app
COPY requirements.txt ./requirements.txt
COPY webapp/requirements.txt ./webapp/requirements.txt
RUN pip install -r requirements.txt -r webapp/requirements.txt

# Engine + UI.
COPY . /app

# Vendor front-end libs (Vue + xterm.js for the in-browser auth terminal) so the
# running container needs no CDN.
ARG XTERM_VERSION=5.3.0
ARG XTERM_FIT_VERSION=0.8.0
RUN mkdir -p webapp/static/vendor \
 && curl -fsSL "https://cdn.jsdelivr.net/npm/vue@${VUE_VERSION}/dist/vue.global.prod.js" \
      -o webapp/static/vendor/vue.global.prod.js \
 && curl -fsSL "https://cdn.jsdelivr.net/npm/xterm@${XTERM_VERSION}/lib/xterm.js" \
      -o webapp/static/vendor/xterm.js \
 && curl -fsSL "https://cdn.jsdelivr.net/npm/xterm@${XTERM_VERSION}/css/xterm.css" \
      -o webapp/static/vendor/xterm.css \
 && curl -fsSL "https://cdn.jsdelivr.net/npm/xterm-addon-fit@${XTERM_FIT_VERSION}/lib/xterm-addon-fit.js" \
      -o webapp/static/vendor/xterm-addon-fit.js

VOLUME ["/data"]
EXPOSE 8000

# --app-dir puts webapp/ on the import path; cwd stays /app so the orchestrator resolves.
CMD ["uvicorn", "app:app", "--app-dir", "webapp", "--host", "0.0.0.0", "--port", "8000"]
