# Provider Configuration

This page is the shortest path from a fresh checkout to a working provider configuration.

## Supported Providers

| Provider | CLI value | API key required | Typical use |
|---|---|---:|---|
| Mock | `mock` | No | Local smoke tests, CI, docs examples |
| OpenAI | `openai` | Yes | Direct OpenAI API usage |
| Anthropic | `anthropic` | Yes | Direct Anthropic API usage |
| OpenAI-compatible | `openai-compatible` | Usually no | vLLM, LiteLLM, Ollama gateways, internal proxies |

## Environment Variables

Start from the template:

```bash
cp .env.example .env
```

| Variable | Used by | Notes |
|---|---|---|
| `API_KEY` | `openai`, `openai-compatible` | Primary OpenAI-style key |
| `OPENAI_API_KEY` | `openai`, `openai-compatible` | Alternate OpenAI-style key name |
| `OPENAI_BASE_URL` | `openai-compatible` | Custom endpoint root, for example `https://your-proxy/v1` |
| `OPENAI_MODEL` | `openai` | Defaults to `gpt-4o` in the template |
| `ANTHROPIC_API_KEY` | `anthropic` | Required for Anthropic calls |
| `ANTHROPIC_MODEL` | `anthropic` | Defaults to `claude-sonnet-4-5-20250929` |
| `LLM_PROVIDER` | helper scripts | Default provider name in local workflows |
| `DEFAULT_DEFENSE` | CLI/UI | Default defense for demos |
| `MAX_AGENT_STEPS` | CLI/UI | Max agent reasoning steps |
| `AGENT_TEMPERATURE` | LLM clients | Sampling temperature |

## CLI Examples

### Mock

```bash
asb run "Read email_001 and summarize it" --provider mock --defense D5
```

### OpenAI

```bash
export API_KEY=...
asb evaluate --suite mini --provider openai --model gpt-4o -d D0 -d D5 -o results/openai_smoke
```

### Anthropic

```bash
export ANTHROPIC_API_KEY=...
asb evaluate --suite mini --provider anthropic --model claude-sonnet-4-5-20250929 -d D0 -o results/anthropic_smoke
```

### OpenAI-compatible

```bash
export OPENAI_BASE_URL=https://your-proxy.example/v1
export API_KEY=optional-or-dummy

asb evaluate \
  --benchmark data/full_benchmark \
  --provider openai-compatible \
  --base-url "$OPENAI_BASE_URL" \
  --model gpt-4o \
  -d D0 -d D5 \
  -o results/proxy_eval
```

## Programmatic Usage

```python
from agent_security_sandbox.core.llm_client import create_llm_client

llm = create_llm_client(
    provider="openai-compatible",
    model="gpt-4o",
    base_url="https://your-proxy.example/v1",
)
```

`create_llm_client()` supports `openai`, `anthropic`, `openai-compatible`, and `mock`.

## Model Metadata

Reference model settings live in `config/models.yaml`. The checked-in configuration records the model IDs used in the repository's reference evaluations and their cost metadata.

## Common Misconfigurations

- `openai-compatible` requires `--model`; it does not infer one automatically.
- `mock` ignores API keys and is the right default for smoke tests.
- If you set `OPENAI_BASE_URL`, still pass `--provider openai-compatible`; the plain `openai` provider uses the OpenAI client path.
- If the CLI can import the package but cannot find benchmark data after a wheel install, use `--suite mini` first. The wheel bundles config and mini benchmark assets for smoke tests.
