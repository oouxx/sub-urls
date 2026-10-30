#!/usr/bin/env bash
# 一键检测 gitraw.txt / jichang.txt 里的订阅链接质量
#   ./checker/run.sh              # 完整跑：抓取 -> 汇总 -> 实测 -> 报表
#   SUBCHECK_PROXY=http://127.0.0.1:1082 ./checker/run.sh   # 抓取走代理（探测仍然裸连）
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONUNBUFFERED=1

PY=${PYTHON:-python3}
if ! "$PY" -c "import yaml" 2>/dev/null; then
    echo "缺少 PyYAML，正在创建虚拟环境 .venv ..."
    "$PY" -m venv .venv
    ./.venv/bin/pip install -q -r checker/requirements.txt
    PY=./.venv/bin/python
fi

PREFIX=${PREFIX:-run}
"$PY" checker/fetch.py
"$PY" checker/build.py
"$PY" checker/pipeline.py .check-work/config.yaml "$PREFIX" "${CONC1:-250}" "${CONC2:-40}"
"$PY" checker/report.py "$PREFIX"
echo "完成，报表见 .check-work/${PREFIX}_report.md"
