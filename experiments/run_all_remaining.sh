#!/bin/bash
# 自动运行所有 D8/D9/D10 实验
# 使用 --resume 自动跳过已完成的评估
# 用法: cd project_root && bash experiments/run_all_remaining.sh

set -e
cd "$(dirname "$0")/.."

# 加载 .env
export $(grep -v '^#' .env | grep -v '^$' | xargs)

BASE_URL="https://gateway.2077ai.org/v1"
BENCHMARK="data/full_benchmark"
OUTPUT="results/full_eval"

echo "============================================"
echo "  ASB D8/D9/D10 全量实验"
echo "  开始时间: $(date)"
echo "============================================"

for DEFENSE in D8 D9 D10; do
    echo ""
    echo ">>> 运行 $DEFENSE 实验..."
    PYTHONUNBUFFERED=1 python experiments/run_full_evaluation.py \
        --models gpt-4o claude-sonnet-4-5-20250929 deepseek-v3-1-250821 gemini-2.5-flash \
        --defenses "$DEFENSE" \
        --runs 3 \
        --benchmark-dir "$BENCHMARK" \
        --output-dir "$OUTPUT" \
        --provider openai-compatible \
        --base-url "$BASE_URL" \
        --resume
    echo ">>> $DEFENSE 完成: $(date)"
done

echo ""
echo "============================================"
echo "  所有实验完成!"
echo "  结束时间: $(date)"
echo "============================================"

echo ""
echo "D8/D9/D10 结果文件数:"
ls results/full_eval/*D8* results/full_eval/*D9* results/full_eval/*D10* 2>/dev/null | wc -l
