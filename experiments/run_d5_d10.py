#!/usr/bin/env python3
"""Run D5+D10 composition experiment."""
import sys, json, time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from agent_security_sandbox.core.llm_client import create_llm_client
from agent_security_sandbox.defenses.registry import create_composite_defense
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite
from agent_security_sandbox.evaluation.runner import ExperimentRunner
from agent_security_sandbox.tools.registry import ToolRegistry
from enum import Enum

def safe(o):
    if o is None or isinstance(o, (bool, int, float, str)): return o
    if isinstance(o, Enum): return o.value
    if isinstance(o, dict): return {k: safe(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)): return [safe(v) for v in o]
    if hasattr(o, "__dict__"): return {k: safe(v) for k, v in vars(o).items() if not k.startswith("_")}
    return str(o)

suite = BenchmarkSuite.load_from_directory(str(_ROOT / "data" / "full_benchmark"))
print(f"Loaded {len(suite)} cases ({len(suite.attack_cases)} attack, {len(suite.benign_cases)} benign)", flush=True)

outdir = _ROOT / "results" / "full_eval_v2"
outdir.mkdir(parents=True, exist_ok=True)

for run_id in range(1, 4):
    outfile = outdir / f"gpt-4o_D5+D10_run{run_id}.json"
    if outfile.exists():
        print(f"[SKIP] {outfile.name} exists", flush=True)
        continue
    print(f"[{run_id}/3] D5+D10 run{run_id}", flush=True)
    llm = create_llm_client("openai-compatible", "gpt-4o", base_url="https://gateway.2077ai.org/v1")
    defense = create_composite_defense(["D5", "D10"], llm_client=llm)
    runner = ExperimentRunner(llm_client=llm, tool_registry_factory=ToolRegistry, defense_strategy=defense, max_steps=10)
    t0 = time.time()
    def _progress(i, n, c):
        if (i + 1) % 50 == 0 or i == 0:
            print(f"    case {i+1}/{n}  ({time.time()-t0:.0f}s)", flush=True)
    result = runner.run_suite(suite, progress_callback=_progress)
    elapsed = time.time() - t0
    m = result.metrics
    print(f"  ASR={m.asr:.4f}  BSR={m.bsr:.4f}  FPR={m.fpr:.4f}  time={elapsed:.1f}s", flush=True)
    data = safe(result)
    data["_meta"] = {"model": "gpt-4o", "defense": "D5+D10", "run_id": run_id, "elapsed": round(elapsed, 2)}
    with open(outfile, "w") as f:
        json.dump(data, f, indent=2)
print("Done!", flush=True)
