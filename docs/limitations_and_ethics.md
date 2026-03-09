# Limitations and Ethical Considerations

## Limitations

### 1. Simulated Environment vs. Real-World Deployment

Our evaluation framework uses **mock tool environments** (simulated email, file systems, calendars, and APIs) rather than real-world services. While this provides reproducibility and safety, it introduces a *fidelity gap*:

- **Tool response complexity**: Real-world API responses contain noise, latency, pagination, authentication errors, and rate limiting that our mock tools do not simulate. An agent's behavior under these conditions may differ significantly.
- **Multi-step chains**: Our benchmark cases typically involve 1–3 tool calls. Real-world agent workflows may involve 10+ chained steps with complex state dependencies, creating more opportunities for injection exploitation.
- **User context**: We do not model user-specific context (e.g., prior conversation history, personalization data) that could affect both attack effectiveness and defense performance.

### 2. Benchmark Coverage

Although our benchmark includes 235 cases across 7 attack types, several important dimensions remain underexplored:

- **Attack diversity**: We focus on English-language injections. Cross-lingual attacks, encoding-based evasion (Base64, ROT13, Unicode homoglyphs), and multi-modal injection vectors (images, audio) are not covered.
- **Adaptive attacks**: Our injections are *static*—they do not adapt based on the agent's responses or defense behavior. Sophisticated adversaries may craft *adaptive* injections that probe for defense weaknesses iteratively.
- **Novel attack types**: The threat landscape evolves rapidly. Attack categories like indirect prompt injection via tool outputs, retrieval-augmented generation (RAG) poisoning, and multi-agent collusion are not yet modeled.
- **Difficulty calibration**: Our difficulty ratings (1–3) are manually assigned and not empirically validated against actual attack success rates across models.

### 3. Defense Generalizability

- **Defense–model coupling**: Defense effectiveness may vary across different LLM architectures (e.g., instruction-tuned vs. base models, different safety training approaches). Our results for one model family may not transfer to others.
- **Defense composition**: While we evaluate pairwise and multi-defense combinations, the interaction effects between defenses may be non-linear and depend on ordering, which our evaluation does not exhaustively explore.
- **Computational overhead**: We report token costs but do not measure real-time latency impact of defenses in production settings, which is critical for user-facing applications.

### 4. Evaluation Methodology

- **Judge reliability**: Our LLM-based judge (when used) introduces a dependency on the judge model's own susceptibility to prompt injection and reasoning errors. While we mitigate this with a composite (rule + LLM) judge, the LLM judge component may have blind spots.
- **Binary verdicts**: Our evaluation produces binary outcomes (attack succeeded/blocked, benign completed/blocked). This misses nuanced scenarios where an attack partially succeeds or a benign task is completed with degraded quality.
- **Statistical power**: With 235 benchmark cases and the typical 3 runs per configuration, some subcategory analyses (e.g., per attack type × per defense) may have limited statistical power.

### 5. Model Access

- We evaluate through API access only and do not have access to model weights, internal representations, or training data. This limits our ability to analyze *why* certain defenses succeed or fail at a mechanistic level.
- API-based evaluation is subject to model versioning—results obtained with `gpt-4o-2024-08-06` may not replicate with future model versions.

---

## Ethical Considerations

### Dual-Use Concerns

This work presents a framework that includes **prompt injection attack templates**. While these are designed for defensive research and benchmarking, they could potentially be adapted for malicious purposes. We mitigate this risk through:

1. **Simulated environment**: All attacks execute against mock tools with no real-world side effects. No actual emails are sent, no files are modified, and no APIs are called.
2. **Defensive focus**: The primary contribution is the defense evaluation framework. Attack templates serve only as test inputs for measuring defense effectiveness.
3. **Responsible disclosure**: We do not publish novel zero-day attack techniques. Our injection templates use well-known patterns from the existing literature (BIPIA, InjecAgent, Greshake et al.).

### Potential for Misuse

- **Attack template adaptation**: The benchmark attack cases could be adapted to craft real-world prompt injections. However, similar examples are already publicly available in academic papers, blog posts, and open-source projects.
- **Defense bypass information**: Our results revealing which defenses fail against specific attack types could theoretically inform adversaries. We believe the benefit of transparent defense evaluation outweighs this risk, following the established norms of security research.

### Responsible AI Considerations

- **Autonomy and safety**: Our framework highlights the tension between agent autonomy (executing tasks without human oversight) and safety (preventing manipulation). We advocate for a defense-in-depth approach where no single defense layer is relied upon exclusively.
- **Transparency**: We publish our full benchmark, defense implementations, and evaluation code to enable independent verification and encourage community improvement.
- **No human subjects**: This research does not involve human participants, personal data, or user studies. All "emails" and "documents" in our benchmark are synthetic.

### Recommendations for Practitioners

Based on our findings, we recommend that developers deploying LLM-based agents:

1. **Never rely on a single defense**. Combine complementary defense strategies (e.g., prompt-level + tool-level + output validation).
2. **Implement mandatory human-in-the-loop** for high-stakes actions (financial transactions, external communications, data deletion).
3. **Maintain tool whitelists** and restrict agent capabilities to the minimum necessary for each task.
4. **Monitor and log** all agent actions for post-hoc audit, even when real-time defenses are in place.
5. **Regularly re-evaluate** defenses as LLM capabilities and attack techniques evolve.
