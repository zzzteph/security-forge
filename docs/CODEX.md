# Use your local Codex CLI

The built-in `codex` backend runs the Codex executable on the machine running
security-forge. It reuses the CLI's saved login, configuration and default model.
LiteLLM and a separately configured provider API key are not required for this
backend. Codex uses the model provider configured in your Codex installation.

## Run a scan

The model selects the backend automatically unless you pass `--backend` or
`--agent-cmd`. GPT/ChatGPT/Codex names select local Codex; Claude/Opus/Sonnet/Haiku
names select Claude Code. Unrecognized names use the configured backend.

```bash
python orchestrate.py --model chatgpt --verify --repo https://github.com/zabbix/zabbix --rescan
python orchestrate.py --model opus4.8 --verify --repo https://github.com/zabbix/zabbix --rescan
```

Bare `chatgpt`, `gpt`, or `codex` uses your Codex default model. Formatting aliases
such as `GPT5.4`, `ChatGPT 5.4`, and `gpt_5_4` become `gpt-5.4`; `opus4.8`
becomes `claude-opus-4-8`. These are spelling conversions, not checks that a
version exists or is available to your account. Unknown names are passed through;
the tool does not guess replacement versions. `openai/` is stripped for Codex.

To use a GPT model through your custom API endpoint instead, explicitly pass
`--backend litellm`; its model name is passed through unchanged.

From the security-forge checkout, with Python, Git and Codex on PATH:

```powershell
python -m pip install -r requirements.txt
codex login
codex login status
python orchestrate.py --path C:/path/to/project --backend codex
```

For a remote repository:

```bash
python orchestrate.py --repo https://github.com/OWNER/REPO --backend codex
```

Omit `--model` and leave `agent.model` blank to use your Codex default model.
To override it, pass `--model <codex-model-id>` (a Codex model ID, without a LiteLLM
provider prefix). `--agent-effort low|medium|high` overrides reasoning effort;
`max` maps to `high`. Omit effort, or select `off`, to keep your Codex setting.

If Codex is not on PATH, pass `--codex "C:/path/to/codex.exe"` or set `CODEX_BIN`.
The inherited `CODEX_HOME` is supported. You can also configure the backend:

```yaml
agent:
  backend: codex
  model: ""
  codex:
    binary: ""
    effort: ""
    sandbox: workspace-write
```

The engine grants Codex access to the selected output folders. It sends the
prompt through stdin, so large project instructions do not hit Windows command
line limits. Each repository gets a new `codex exec` session. LiteLLM-specific
turn, temperature, endpoint and specialist controls do not configure Codex;
the orchestrator's `--timeout` still applies.

## Dashboard

In **Settings → AI configuration**, select **codex**, clear the previous LiteLLM
model to use the Codex default, and select **Provider default** effort to use your
local reasoning setting. Both scans and generated AI reports use Codex.

Editing the model selects **auto (from model)**, using the same model-family
routing for scans. GPT/ChatGPT names also route AI reports through Codex.
Choose a specific backend after entering the model to override automatic routing
(for example, **litellm** for your custom API endpoint).

Use **Backends** to check installation and login status. Log in as the same OS
user running security-forge; on Windows, run `codex login` in your terminal and
refresh the page. Browser-based CLI login is available on POSIX hosts.

A dashboard in Docker runs the CLI installed **inside that container**. To use
your host's installation and login, run the orchestrator on the host. To use the
container's Codex, rebuild the image with the default `INSTALL_AGENTS=true`, then:

```bash
docker compose up -d --build
docker compose exec security-forge codex login --device-auth
docker compose exec security-forge codex login status
```

The container's login persists under `/data/home/.codex` on the data volume.

## Token usage

Codex's native JSONL output is saved in the scan log. On completion, security-forge
records input tokens, cached input tokens, output tokens and reasoning output
tokens when supplied by the CLI. The dashboard displays these in scan details.
Cached input and reasoning output are subsets of the corresponding totals.
Codex does not supply a dollar cost here, so it is displayed as **not reported**.
The dashboard's **reported spend** excludes calls with an unknown price.

Usage events arrive at the end of a Codex turn. An interrupted turn may have no
usage event, so these counts are not a substitute for your provider's usage data.

## Integration checks

```bash
python -m unittest discover -s tests -v
```

These checks use local fake subprocesses and temporary databases. They require no
Codex login and make no model requests.

Official references: [non-interactive Codex](https://developers.openai.com/codex/noninteractive/)
and [authentication](https://developers.openai.com/codex/auth/).
