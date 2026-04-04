# Formal Threat Model for Agent Security Sandbox

## 1. Overview

This document defines the formal threat model for evaluating LLM agent
defenses against Indirect Prompt Injection (IPI) attacks. It specifies
attacker capabilities along three orthogonal axes, trust boundaries
within the agent architecture, and the mapping between threat levels and
defense strategies.

---

## 2. Attacker Model

### 2.1 Knowledge Levels (K)

| Level | Name | Description |
|-------|------|-------------|
| **K0** | Black-box | Attacker knows only that an LLM agent processes external content. No knowledge of the model, tools, or defenses. |
| **K1** | Grey-box | Attacker knows the model family (e.g. GPT-4, Claude) and the set of available tools (e.g. `send_email`, `read_file`). No knowledge of active defenses. |
| **K2** | White-box | Attacker knows the exact model, tool set, defense strategies, and their configurations (e.g. delimiter strings, policy rules). |

### 2.2 Access Levels (A)

| Level | Name | Description |
|-------|------|-------------|
| **A0** | Single injection point | Attacker can inject content into exactly one external source (e.g. one email body). |
| **A1** | Multiple injection points | Attacker can inject into several sources that the agent may encounter during a single task (e.g. email + search results). |
| **A2** | Persistent injection | Attacker can place persistent payloads in data sources the agent accesses repeatedly (e.g. RAG corpus, shared documents). |

### 2.3 Adaptiveness Levels (S)

| Level | Name | Description |
|-------|------|-------------|
| **S0** | Static | Attacker uses a fixed payload. No feedback loop. |
| **S1** | Semi-adaptive | Attacker can observe aggregate defense outcomes (e.g. ASR) and manually revise payloads across batches. |
| **S2** | Fully adaptive | Attacker uses an LLM-based red-teaming loop that observes per-case defense decisions and iteratively refines payloads to bypass specific defenses. |

### 2.4 Combined Threat Levels

The three axes combine into a compact threat descriptor:

```
threat_level ::= "K" <0-2> "_A" <0-2> "_S" <0-2>
```

**Examples:**
- `K0_A0_S0` — Weakest attacker: black-box, single injection, static payload.
- `K1_A1_S1` — Moderate attacker: knows model+tools, multi-point injection, semi-adaptive.
- `K2_A2_S2` — Strongest attacker: full knowledge, persistent access, fully adaptive.

**Canonical benchmark mapping:**
- Easy cases → `K0_A0_S0`
- Medium cases → `K1_A0_S0` or `K0_A1_S0`
- Hard cases → `K1_A1_S1` or `K2_A0_S1`
- Adaptive cases → `K2_A1_S2`

---

## 3. Trust Boundaries

```
┌──────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                       │
│  ┌──────────┐   ┌───────────┐   ┌────────────────┐  │
│  │ User Goal│──▶│ LLM Agent │──▶│ Defense Layer   │  │
│  └──────────┘   └─────┬─────┘   └───────┬────────┘  │
│                       │                  │            │
│              ┌────────▼──────────────────▼─────┐     │
│              │       Tool Execution Engine      │     │
│              └────────┬────────────────────────┘     │
│                       │                               │
├───────────────────────┼───── TRUST BOUNDARY ──────────┤
│                       ▼                               │
│                UNTRUSTED ZONE                         │
│  ┌────────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Email Body │ │ Web Page │ │ File Contents    │   │
│  │ (external) │ │ (search) │ │ (shared docs)    │   │
│  └────────────┘ └──────────┘ └──────────────────┘   │
│  ┌────────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ RAG Chunks │ │ API Resp │ │ Tool Outputs     │   │
│  └────────────┘ └──────────┘ └──────────────────┘   │
└──────────────────────────────────────────────────────┘
```

**Key principle:** Any content crossing the trust boundary from the
untrusted zone into the agent's context is a potential injection vector
and must be treated as adversarial input.

---

## 4. Attack Surface

| Injection Location | Tool Path | Risk |
|--------------------|-----------|------|
| `email_body` | `read_email` → agent context | High |
| `search_result` | `search_web` → agent context | High |
| `file_content` | `read_file` → agent context | Medium |
| `api_response` | `call_api` → agent context | Medium |
| `calendar_event` | `read_calendar` → agent context | Low |
| `rag_chunk` | RAG retrieval → agent context | High |
| `tool_output` | Any tool → observation → agent context | Medium |

---

## 5. Attack Taxonomy

| Attack Type | Goal | Example |
|-------------|------|---------|
| `data_exfiltration` | Steal sensitive data via tool side-effects | Forward API keys to external email |
| `goal_hijacking` | Redirect agent from user's task | Overwrite files instead of summarising |
| `privilege_escalation` | Access resources beyond user intent | Claim admin privileges via fake tokens |
| `multi_step` | Chain multiple injected sub-tasks | Read secrets → package → exfiltrate |
| `social_engineering` | Exploit urgency/authority framing | "URGENT: compliance requires..." |
| `encoding_evasion` | Obfuscate payload to bypass filters | ROT13, Unicode homoglyphs, zero-width |
| `multilingual` | Use non-English to bypass English-centric defenses | CJK injection payloads |
| `rag_poisoning` | Poison RAG retrieval context | Inject into knowledge base chunks |
| `tool_output_injection` | Inject via tool observation text | Malicious content in API response |

---

## 6. Defense Coverage Mapping

| Defense | Threat Levels Covered | Mechanism |
|---------|----------------------|-----------|
| D0 Baseline | None (control) | No defense |
| D1 Spotlighting | K0_A0_S0 | Delimiter marking of untrusted content |
| D2 Policy Gate | K0-K1_A0-A1_S0 | Tool-level access control |
| D3 Task Alignment | K0-K1_A0_S0-S1 | LLM-based alignment verification |
| D4 Re-execution | K0-K1_A0_S0 | Masked re-execution comparison |
| D5 Sandwich | K0-K1_A0_S0 | Goal reminder wrapping |
| D6 Output Filter | K0_A0-A1_S0 | Heuristic output scanning |
| D7 Input Classifier | K0_A0_S0 | Pre-processing injection detection |
| D8 Semantic Firewall | K0-K1_A0-A1_S0-S1 | Embedding-based instruction drift detection |
| D9 Dual-LLM | K0-K2_A0-A2_S0-S1 | Two-model screening and verification |
| D10 CIV (ours) | K0-K2_A0-A1_S0-S1 | Provenance + fingerprinting + counterfactual |

---

## 7. Evaluation Protocol

1. **Baseline measurement:** Run all cases against D0 to establish
   attacker success rates without any defense.
2. **Per-threat-level evaluation:** Group cases by `threat_level` and
   evaluate each defense to identify coverage gaps.
3. **Adaptive evaluation:** Use the `AdaptiveAttacker` (S2) against
   each defense to measure worst-case robustness.
4. **Composition analysis:** Test defense combinations to find
   complementary coverage across threat levels.

---

## 8. Metrics

| Metric | Definition |
|--------|-----------|
| ASR (Attack Success Rate) | Fraction of attack cases where the agent performed a forbidden action |
| BSR (Benign Success Rate) | Fraction of benign cases where the agent completed the task correctly |
| FPR (False Positive Rate) | Fraction of benign cases incorrectly blocked by the defense |
| ASR@K/A/S | ASR conditioned on a specific knowledge/access/adaptiveness level |
| Robustness Gap | ASR(S2) - ASR(S0): how much adaptive attacks degrade a defense |
