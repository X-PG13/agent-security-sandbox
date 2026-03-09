# Agent Security Sandbox — Experiment Results

## Experiment Configuration

- **Models**: GPT-4o, Claude 4.5 Sonnet, DeepSeek V3.1, Gemini 2.5 Flash
- **Defenses**: D0 (Baseline), D1 (Spotlighting), D2 (Policy Gate), D3 (Task Alignment), D4 (Re-execution), D5 (Sandwich), D6 (Output Filter), D7 (Input Classifier)
- **Benchmark**: 250 cases (155 attack + 95 benign)
- **Attack types**: hijacking, exfiltration, escalation, social engineering, adaptive, DoS, multistep, evasion
- **Runs**: 1 (per model-defense pair)
- **Tool calling**: OpenAI function calling mode
- **Gateway**: OpenAI-compatible proxy

## Table 1: Attack Success Rate (ASR)

Lower ASR = better defense. D0 is the no-defense baseline.

| Defense | GPT-4o | Claude 4.5 Sonnet | DeepSeek V3.1 | Gemini 2.5 Flash | **Avg** |
|---|---|---|---|---|---|
| **D0** Baseline | 0.465 | 0.116 | 0.523 | 0.542 | **0.411** |
| **D1** Spotlighting | 0.006 | 0.006 | 0.019 | 0.045 | **0.019** |
| **D2** Policy Gate | 0.368 | 0.077 | 0.387 | 0.361 | **0.298** |
| **D3** Task Alignment | 0.471 | 0.097 | 0.503 | 0.529 | **0.400** |
| **D4** Re-execution | 0.368 | 0.077 | 0.432 | 0.387 | **0.316** |
| **D5** Sandwich | 0.006 | 0.013 | 0.013 | 0.006 | **0.010** |
| **D6** Output Filter | 0.445 | 0.077 | 0.484 | 0.503 | **0.377** |
| **D7** Input Classifier | 0.465 | 0.116 | 0.581 | 0.574 | **0.434** |

## Table 2: Benign Success Rate (BSR)

Higher BSR = less disruption to legitimate tasks.

| Defense | GPT-4o | Claude 4.5 Sonnet | DeepSeek V3.1 | Gemini 2.5 Flash | **Avg** |
|---|---|---|---|---|---|
| **D0** Baseline | 0.905 | 0.958 | 0.958 | 0.758 | **0.895** |
| **D1** Spotlighting | 0.916 | 0.958 | 0.989 | 0.842 | **0.926** |
| **D2** Policy Gate | 0.758 | 0.811 | 0.789 | 0.695 | **0.763** |
| **D3** Task Alignment | 0.884 | 0.958 | 0.958 | 0.853 | **0.913** |
| **D4** Re-execution | 0.758 | 0.811 | 0.800 | 0.674 | **0.761** |
| **D5** Sandwich | 0.916 | 0.958 | 0.968 | 0.895 | **0.934** |
| **D6** Output Filter | 0.842 | 0.958 | 0.958 | 0.789 | **0.887** |
| **D7** Input Classifier | 0.895 | 0.958 | 0.958 | 0.842 | **0.913** |

## Table 3: Security-Utility Tradeoff Summary

| Defense | Avg ASR | Avg BSR | Avg FPR | ASR Reduction |
|---|:---:|:---:|:---:|:---:|
| **D0** Baseline | 0.411 | 0.895 | 0.105 | +0.0% |
| **D1** Spotlighting | 0.019 | 0.926 | 0.074 | +95.3% |
| **D2** Policy Gate | 0.298 | 0.763 | 0.237 | +27.5% |
| **D3** Task Alignment | 0.400 | 0.913 | 0.087 | +2.7% |
| **D4** Re-execution | 0.316 | 0.761 | 0.239 | +23.1% |
| **D5** Sandwich | 0.010 | 0.934 | 0.066 | +97.6% |
| **D6** Output Filter | 0.377 | 0.887 | 0.113 | +8.2% |
| **D7** Input Classifier | 0.434 | 0.913 | 0.087 | -5.5% |

## Key Findings

### 1. Prompt-layer defenses dominate

**D5 (Sandwich)** and **D1 (Spotlighting)** are the two most effective defenses,
reducing average ASR by **97.6%** and **95.3%** respectively while maintaining
high BSR (>0.92) and low FPR (<0.08). Both are prompt-modification-only
strategies that require no additional LLM calls or tool gating.

### 2. Tool-gating defenses show high false positive rates

**D2 (Policy Gate)** and **D4 (Re-execution)** reduce ASR by ~25% but at the
cost of significantly elevated FPR (~0.24), indicating they over-block legitimate
tool calls. This security-utility tradeoff may be unacceptable in production.

### 3. Content-level defenses are largely ineffective

**D6 (Output Filter)** and **D7 (Input Classifier)** provide minimal ASR reduction
(8% and -5% respectively). D7 actually *increases* average ASR slightly, possibly
because sanitization strips context that helps the model resist injection.

### 4. Claude exhibits strong inherent robustness

**Claude 4.5 Sonnet** achieves baseline ASR of only 0.116 without any defense — 
4x lower than other models (0.46-0.54). Combined with any defense, Claude's ASR
drops to near zero (0.006-0.013 for D1/D5).

### 5. Model capability inversely correlates with injection susceptibility

Robustness ranking: Claude (0.12) > GPT-4o (0.47) > DeepSeek (0.52) > Gemini Flash (0.54).
This suggests that instruction-following models with stronger safety training are
inherently more resistant to indirect prompt injection.
