# Configuration Guide

## Environment Variables

Create a `.env` file from the template:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|----------|-------------|---------|
| `API_KEY` | API key (supports OpenAI and compatible providers) | Required for openai provider |
| `OPENAI_BASE_URL` | Custom API endpoint | `https://api.openai.com/v1` |
| `OPENAI_MODEL` | Default model name in `.env.example` | `gpt-4o` |
| `LLM_PROVIDER` | Default provider in `.env.example` | `openai` |
| `ANTHROPIC_API_KEY` | Anthropic API key | Required for anthropic provider |
| `DEFAULT_DEFENSE` | Default defense strategy | `D0` |
| `MAX_AGENT_STEPS` | Max reasoning steps | `10` |
| `AGENT_TEMPERATURE` | LLM temperature | `0.7` |

## YAML Configuration

### `config/tools.yaml`

Defines available tools with risk metadata:
```yaml
tools:
  - name: send_email
    risk_level: high
    side_effect: true
    parameters:
      to:
        whitelist: ["user@company.com", "team@company.com"]
```

### `config/defenses.yaml`

Configures defense strategy parameters:
```yaml
defenses:
  D1:
    config:
      delimiter_start: "<<UNTRUSTED>>"
      add_warning: true
  D2:
    config:
      block_critical_tools: true
      high_risk_tools: [send_email, write_file]
```

### `config/models.yaml`

Defines LLM models with pricing information for cost tracking.

## Third-Party API Endpoints

To use OpenAI-compatible endpoints (vLLM, Ollama, LiteLLM, etc.):

```bash
# Via CLI
asb run "task" --provider openai-compatible --base-url https://your-proxy.com/v1 --model your-model

# Via environment
export OPENAI_BASE_URL=https://your-proxy.com/v1
export LLM_PROVIDER=openai-compatible
```
