#!/usr/bin/env python3
"""Audit benchmark data quality for Route A paper."""

import json
from collections import Counter
from pathlib import Path

BENCHMARK_DIR = Path(__file__).parent.parent / "data" / "full_benchmark"

REQUIRED_FIELDS = {"id", "type", "goal", "untrusted_content", "expected_tools", "forbidden_actions"}
OPTIONAL_FIELDS = {
    "injection_location", "attack_type", "injection_technique",
    "tags", "difficulty", "threat_level",
}
ALL_FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS

KNOWN_TOOLS = {
    "search_web", "read_email", "send_email", "read_file", "write_file",
    "create_document", "read_calendar", "create_calendar_event",
    "call_api", "post_api", "execute_code", "list_emails",
}

KNOWN_ATTACK_TYPES = {
    "goal_hijacking", "data_exfiltration", "privilege_escalation",
    "social_engineering", "adaptive", "denial_of_service",
    "multistep", "evasion", "encoding", "tool_output_manipulation",
    "rag_poisoning", "multilingual",
}


def load_all_cases():
    """Load all JSONL files from the benchmark directory."""
    cases = []
    file_stats = {}
    for fpath in sorted(BENCHMARK_DIR.glob("*.jsonl")):
        file_cases = []
        with open(fpath) as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    case = json.loads(line)
                    case["_source_file"] = fpath.name
                    case["_line_number"] = i
                    file_cases.append(case)
                except json.JSONDecodeError as e:
                    print(f"  ERROR: {fpath.name} line {i}: JSON parse error: {e}")
        cases.extend(file_cases)
        file_stats[fpath.name] = len(file_cases)
    return cases, file_stats


def audit_fields(cases):
    """Check field presence and types."""
    issues = []
    for c in cases:
        cid = c.get("id", f"unknown@{c['_source_file']}:{c['_line_number']}")
        # Required fields
        for field in REQUIRED_FIELDS:
            if field not in c:
                issues.append(f"{cid}: missing required field '{field}'")
        # Type checks
        if c.get("type") not in ("attack", "benign"):
            issues.append(f"{cid}: invalid type '{c.get('type')}'")
        if not isinstance(c.get("goal", ""), str) or not c.get("goal", "").strip():
            issues.append(f"{cid}: empty or invalid goal")
        if not isinstance(c.get("expected_tools", []), list):
            issues.append(f"{cid}: expected_tools is not a list")
        if not isinstance(c.get("forbidden_actions", []), list):
            issues.append(f"{cid}: forbidden_actions is not a list")
        # Attack-specific checks
        if c.get("type") == "attack":
            if not c.get("untrusted_content"):
                issues.append(f"{cid}: attack case has no untrusted_content")
            if not c.get("forbidden_actions"):
                issues.append(f"{cid}: attack case has no forbidden_actions")
            if not c.get("attack_type"):
                issues.append(f"{cid}: attack case has no attack_type")
        # Benign-specific checks
        if c.get("type") == "benign":
            if not c.get("expected_tools"):
                issues.append(f"{cid}: benign case has no expected_tools")
        # Unknown fields
        extra = set(c.keys()) - ALL_FIELDS - {"_source_file", "_line_number"}
        if extra:
            issues.append(f"{cid}: unknown fields: {extra}")
    return issues


def audit_ids(cases):
    """Check for duplicate IDs."""
    ids = Counter(c.get("id") for c in cases)
    duplicates = {k: v for k, v in ids.items() if v > 1}
    return duplicates


def audit_tools(cases):
    """Check tool references."""
    unknown_tools = set()
    tool_usage = Counter()
    for c in cases:
        for t in c.get("expected_tools", []):
            tool_usage[t] += 1
            if t not in KNOWN_TOOLS:
                unknown_tools.add(t)
        for fa in c.get("forbidden_actions", []):
            tool = fa.get("tool", "")
            tool_usage[tool] += 1
            if tool not in KNOWN_TOOLS:
                unknown_tools.add(tool)
    return unknown_tools, tool_usage


def audit_attack_types(cases):
    """Check attack type distribution."""
    attack_types = Counter()
    unknown_types = set()
    for c in cases:
        if c.get("type") == "attack":
            at = c.get("attack_type", "MISSING")
            attack_types[at] += 1
            if at not in KNOWN_ATTACK_TYPES and at != "MISSING":
                unknown_types.add(at)
    return attack_types, unknown_types


def audit_difficulty(cases):
    """Check difficulty distribution."""
    difficulty = Counter()
    for c in cases:
        d = c.get("difficulty", "MISSING")
        difficulty[d] += 1
    return difficulty


def audit_injection_locations(cases):
    """Check injection location distribution."""
    locations = Counter()
    for c in cases:
        if c.get("type") == "attack":
            loc = c.get("injection_location", "MISSING")
            locations[loc] += 1
    return locations


def audit_injection_techniques(cases):
    """Check injection technique distribution."""
    techniques = Counter()
    for c in cases:
        if c.get("type") == "attack":
            tech = c.get("injection_technique", "MISSING")
            techniques[tech] += 1
    return techniques


def audit_content_quality(cases):
    """Check content length and quality."""
    issues = []
    goal_lengths = []
    content_lengths = []
    for c in cases:
        goal = c.get("goal", "")
        goal_lengths.append(len(goal))
        if len(goal) < 10:
            issues.append(f"{c.get('id')}: very short goal ({len(goal)} chars): '{goal}'")
        if len(goal) > 500:
            issues.append(f"{c.get('id')}: very long goal ({len(goal)} chars)")
        uc = c.get("untrusted_content") or ""
        if uc:
            content_lengths.append(len(uc))
            if len(uc) < 10 and c.get("type") == "attack":
                issues.append(f"{c.get('id')}: very short untrusted_content ({len(uc)} chars)")
    return issues, goal_lengths, content_lengths


def audit_benign_categories(cases):
    """Check benign case categories by source file."""
    categories = Counter()
    for c in cases:
        if c.get("type") == "benign":
            src = c.get("_source_file", "unknown")
            categories[src] += 1
    return categories


def main():
    print("=" * 70)
    print("ASB Benchmark Data Quality Audit")
    print("=" * 70)

    cases, file_stats = load_all_cases()
    attack_cases = [c for c in cases if c.get("type") == "attack"]
    benign_cases = [c for c in cases if c.get("type") == "benign"]

    print("\n### 1. 总体统计")
    print(f"总 case 数: {len(cases)}")
    print(f"攻击 case: {len(attack_cases)}")
    print(f"良性 case: {len(benign_cases)}")
    print("\n文件分布:")
    for fname, count in sorted(file_stats.items()):
        print(f"  {fname}: {count}")

    print("\n### 2. 字段完整性检查")
    field_issues = audit_fields(cases)
    if field_issues:
        print(f"发现 {len(field_issues)} 个问题:")
        for issue in field_issues[:20]:
            print(f"  - {issue}")
        if len(field_issues) > 20:
            print(f"  ... 还有 {len(field_issues) - 20} 个问题")
    else:
        print("  所有字段完整性检查通过 ✓")

    print("\n### 3. ID 唯一性检查")
    duplicates = audit_ids(cases)
    if duplicates:
        print(f"发现 {len(duplicates)} 个重复 ID:")
        for did, count in duplicates.items():
            print(f"  - {did}: 出现 {count} 次")
    else:
        print("  所有 ID 唯一 ✓")

    print("\n### 4. 工具引用检查")
    unknown_tools, tool_usage = audit_tools(cases)
    if unknown_tools:
        print(f"未知工具: {unknown_tools}")
    else:
        print("  所有工具引用有效 ✓")
    print("  工具使用频率:")
    for tool, count in tool_usage.most_common():
        marker = "" if tool in KNOWN_TOOLS else " ⚠ UNKNOWN"
        print(f"    {tool}: {count}{marker}")

    print("\n### 5. 攻击类型分布")
    attack_types, unknown_at = audit_attack_types(cases)
    if unknown_at:
        print(f"  未知攻击类型: {unknown_at}")
    for at, count in attack_types.most_common():
        pct = count / len(attack_cases) * 100
        print(f"  {at}: {count} ({pct:.1f}%)")

    print("\n### 6. 难度分布")
    difficulty = audit_difficulty(cases)
    for d, count in difficulty.most_common():
        pct = count / len(cases) * 100
        print(f"  {d}: {count} ({pct:.1f}%)")

    print("\n### 7. 注入位置分布")
    locations = audit_injection_locations(cases)
    for loc, count in locations.most_common():
        pct = count / len(attack_cases) * 100
        print(f"  {loc}: {count} ({pct:.1f}%)")

    print("\n### 8. 注入技术分布")
    techniques = audit_injection_techniques(cases)
    for tech, count in techniques.most_common():
        pct = count / len(attack_cases) * 100
        print(f"  {tech}: {count} ({pct:.1f}%)")

    print("\n### 9. 内容质量检查")
    content_issues, goal_lengths, content_lengths = audit_content_quality(cases)
    if content_issues:
        print(f"  发现 {len(content_issues)} 个问题:")
        for issue in content_issues[:10]:
            print(f"    - {issue}")
        if len(content_issues) > 10:
            print(f"    ... 还有 {len(content_issues) - 10} 个问题")
    else:
        print("  内容质量检查通过 ✓")
    print(f"  Goal 长度: min={min(goal_lengths)}, max={max(goal_lengths)}, "
          f"avg={sum(goal_lengths)/len(goal_lengths):.0f}")
    if content_lengths:
        print(f"  Untrusted content 长度: min={min(content_lengths)}, max={max(content_lengths)}, "
              f"avg={sum(content_lengths)/len(content_lengths):.0f}")

    print("\n### 10. 良性 case 分类")
    benign_cats = audit_benign_categories(cases)
    for cat, count in benign_cats.most_common():
        pct = count / len(benign_cases) * 100
        print(f"  {cat}: {count} ({pct:.1f}%)")

    # Summary
    total_issues = len(field_issues) + len(duplicates) + len(unknown_tools) + len(content_issues)
    print(f"\n{'=' * 70}")
    print(f"审计总结: {total_issues} 个问题")
    if total_issues == 0:
        print("数据质量良好，可以进入下一阶段 ✓")
    else:
        print("需要修复上述问题后再进行实验")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
