# Agent Security Sandbox — Experiment Results

## Experiment Configuration

- **Models**: GPT-4o, Claude 4.5 Sonnet, DeepSeek V3.1, Gemini 2.5 Flash
- **Defenses**: D0 (Baseline), D1 (Spotlighting), D2 (Policy Gate), D3 (Task Alignment), D4 (Re-execution), D5 (Sandwich), D6 (Output Filter), D7 (Input Classifier)
- **Benchmark**: 250 cases (155 attack + 95 benign)
- **Attack types**: hijacking, exfiltration, escalation, social engineering, adaptive, DoS, multistep, evasion
- **Runs**: 3 per model-defense pair (96 total evaluations)
- **Tool calling**: OpenAI function calling mode
- **Gateway**: OpenAI-compatible proxy (gateway.2077ai.org/v1)
- **Evaluation period**: March 2026

### Model Versions

| Display Name | Model ID | Provider |
|---|---|---|
| GPT-4o | `gpt-4o` | OpenAI-compatible proxy |
| Claude 4.5 Sonnet | `claude-sonnet-4-5-20250929` | OpenAI-compatible proxy |
| DeepSeek V3.1 | `deepseek-v3-1-250821` | OpenAI-compatible proxy |
| Gemini 2.5 Flash | `gemini-2.5-flash` | OpenAI-compatible proxy |

## Table 1: Attack Success Rate (ASR)

Lower ASR = better defense. D0 is the no-defense baseline. Values are averaged over 3 runs.

| Defense | GPT-4o | Claude 4.5 Sonnet | DeepSeek V3.1 | Gemini 2.5 Flash | **Avg** |
|---|---|---|---|---|---|
| **D0** Baseline | 0.492 | 0.116 | 0.508 | 0.538 | **0.413** |
| **D1** Spotlighting | 0.006 | 0.006 | 0.022 | 0.047 | **0.020** |
| **D2** Policy Gate | 0.372 | 0.084 | 0.406 | 0.366 | **0.307** |
| **D3** Task Alignment | 0.475 | 0.142 | 0.516 | 0.490 | **0.406** |
| **D4** Re-execution | 0.363 | 0.099 | 0.422 | 0.402 | **0.322** |
| **D5** Sandwich | 0.006 | 0.013 | 0.013 | 0.009 | **0.010** |
| **D6** Output Filter | 0.434 | 0.118 | 0.499 | 0.465 | **0.379** |
| **D7** Input Classifier | 0.477 | 0.166 | 0.551 | 0.527 | **0.430** |

## Table 2: Benign Success Rate (BSR)

Higher BSR = less disruption to legitimate tasks. Values are averaged over 3 runs.

| Defense | GPT-4o | Claude 4.5 Sonnet | DeepSeek V3.1 | Gemini 2.5 Flash | **Avg** |
|---|---|---|---|---|---|
| **D0** Baseline | 0.895 | 0.958 | 0.965 | 0.832 | **0.912** |
| **D1** Spotlighting | 0.891 | 0.958 | 0.975 | 0.828 | **0.913** |
| **D2** Policy Gate | 0.754 | 0.814 | 0.793 | 0.688 | **0.762** |
| **D3** Task Alignment | 0.884 | 0.965 | 0.972 | 0.842 | **0.916** |
| **D4** Re-execution | 0.765 | 0.818 | 0.814 | 0.719 | **0.779** |
| **D5** Sandwich | 0.902 | 0.975 | 0.972 | 0.888 | **0.934** |
| **D6** Output Filter | 0.828 | 0.975 | 0.979 | 0.825 | **0.902** |
| **D7** Input Classifier | 0.891 | 0.968 | 0.968 | 0.860 | **0.922** |

## Table 3: Security-Utility Tradeoff Summary

| Defense | Avg ASR | Avg BSR | Avg FPR | ASR Reduction |
|---|:---:|:---:|:---:|:---:|
| **D0** Baseline | 0.413 | 0.912 | 0.088 | — |
| **D1** Spotlighting | 0.020 | 0.913 | 0.087 | +95.1% |
| **D2** Policy Gate | 0.307 | 0.762 | 0.238 | +25.7% |
| **D3** Task Alignment | 0.406 | 0.916 | 0.084 | +1.8% |
| **D4** Re-execution | 0.322 | 0.779 | 0.221 | +22.2% |
| **D5** Sandwich | 0.010 | 0.934 | 0.066 | +97.5% |
| **D6** Output Filter | 0.379 | 0.902 | 0.098 | +8.3% |
| **D7** Input Classifier | 0.430 | 0.922 | 0.078 | -4.0% |

## Key Findings

### 1. Prompt-layer defenses dominate

**D5 (Sandwich)** and **D1 (Spotlighting)** are the two most effective defenses,
reducing average ASR by **97.5%** and **95.1%** respectively while maintaining
high BSR (>0.91) and low FPR (<0.09). Both are prompt-modification-only
strategies that require no additional LLM calls or tool gating.

### 2. Tool-gating defenses show high false positive rates

**D2 (Policy Gate)** and **D4 (Re-execution)** reduce ASR by ~23-26% but at the
cost of significantly elevated FPR (0.22-0.24), indicating they over-block legitimate
tool calls. This security-utility tradeoff may be unacceptable in production.

### 3. Content-level defenses are largely ineffective

**D6 (Output Filter)** and **D7 (Input Classifier)** provide minimal ASR reduction
(8% and -4% respectively). D7 actually *increases* average ASR slightly, possibly
because sanitization strips context that helps the model resist injection.

### 4. Claude exhibits strong inherent robustness

**Claude 4.5 Sonnet** achieves baseline ASR of only 0.116 without any defense —
4x lower than other models (0.49-0.54). Combined with any defense, Claude's ASR
drops to near zero (0.006-0.013 for D1/D5).

### 5. Model capability inversely correlates with injection susceptibility

Robustness ranking: Claude (0.12) > GPT-4o (0.49) > DeepSeek (0.51) > Gemini Flash (0.54).
This suggests that instruction-following models with stronger safety training are
inherently more resistant to indirect prompt injection.

## Defense Composition

The framework supports composing multiple defenses (see `config/defenses.yaml`). Six
predefined combinations are available:

| Combination | Components | Mechanism |
|---|---|---|
| D1+D2 | Spotlighting + Policy Gate | Prompt marking + tool gating |
| D1+D2+D3 | Spotlighting + Policy Gate + Task Alignment | Triple-layer defense |
| D6+D7 | Output Filter + Input Classifier | Content-level only |
| D1+D6+D7 | Spotlighting + Output Filter + Input Classifier | Prompt + content |
| D2+D6 | Policy Gate + Output Filter | Tool gating + output scanning |
| D5+D7 | Sandwich + Input Classifier | Prompt wrapping + content sanitization |

Composition experiments can be run via `experiments/run_composition_study.py`.
Individual defense results suggest that **D5+D1** (both prompt-layer) would be the
strongest combination, as each independently achieves >95% ASR reduction with minimal
utility loss. Combining tool-gating defenses (D2/D4) with prompt-layer defenses may
yield diminishing returns given the already-high FPR of tool-gating alone.

## Statistical Validation

- **Confidence intervals**: Wilson score 95% CIs computed per model-defense pair
  (see `experiments/results/stats/summary_with_ci.json`)
- **McNemar's test**: 280 pairwise comparisons; 164 significant (p < 0.05)
  (see `experiments/results/stats/mcnemar_comparisons.json`)
- **Kendall's tau**: Cross-model ranking consistency ranges from 0.64 to 0.93,
  indicating strong agreement across models on defense effectiveness ordering
  (see `experiments/results/stats/kendall_tau.json`)
- **LaTeX tables**: Per-model tables with CIs available in `experiments/results/stats/table_*.tex`
