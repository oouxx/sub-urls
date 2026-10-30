#!/usr/bin/env python3
"""四阶段报表：按订阅源统计质量，输出终端表格 + Markdown。

用法: python checker/report.py [prefix]
产物: .check-work/<prefix>_report.json、.check-work/<prefix>_report.md
"""
import json
import os
import statistics
import sys
from collections import defaultdict

import common as C


def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else "run"
    data = json.load(open(os.path.join(C.WORK, "nodes.json")))
    delay = json.load(open(os.path.join(C.WORK, f"{prefix}_delay.json")))
    verify = json.load(open(os.path.join(C.WORK, f"{prefix}_verify.json")))

    per = defaultdict(lambda: {"n": 0, "a1": 0, "v": 0, "lat": [], "uniq": 0, "uniq_v": 0})
    for nd in data["nodes"]:
        d = delay.get(nd["id"], {}).get("delay")
        ok = bool(verify.get(nd["id"], {}).get("ok"))
        for s in nd["srcs"]:
            p = per[s]
            p["n"] += 1
            p["a1"] += bool(d)
            p["v"] += ok
            if ok:
                p["lat"].append(d)
            if len(nd["srcs"]) == 1:
                p["uniq"] += 1
                p["uniq_v"] += ok

    rows = []
    for s in data["sources"]:
        p = per[s["idx"]]
        n = p["n"] or s["count"]
        rows.append({**s, "nodes": n, "alive1": p["a1"], "verified": p["v"],
                     "vrate": round(p["v"] / n * 100, 1) if n else 0.0,
                     "med_delay": int(statistics.median(p["lat"])) if p["lat"] else 0,
                     "uniq": p["uniq"], "uniq_v": p["uniq_v"]})
    rows.sort(key=lambda r: (-r["verified"], -r["vrate"]))

    print(f"{'#':>2} {'文件':<11} {'HTTP':>4} {'节点':>6} {'一阶段':>6} "
          f"{'真实可用':>7} {'可用率':>6} {'中位ms':>6}  链接")
    for r in rows:
        print(f"{r['idx']:>2} {r['file']:<11} {r['http']:>4} {r['nodes']:>6} "
              f"{r['alive1']:>6} {r['verified']:>7} {r['vrate']:>5}% "
              f"{r['med_delay']:>6}  {r['url']}")
        if r.get("error"):
            print(f"   !! {r['error']}")

    uniq = len(data["nodes"])
    a1 = sum(1 for v in delay.values() if v.get("delay"))
    vv = sum(1 for v in verify.values() if v.get("ok"))
    print(f"\n合计：订阅 {len(rows)} 条，去重节点 {uniq}，直连存活 {a1}，真实可用 {vv}")

    md = ["# 订阅链接质量报告", "",
          f"检测方式：mihomo 内核裸连（不经本机/系统代理），一阶段 delay 直连探测 + "
          f"二阶段 socks 入口真实访问 cloudflare trace 验证落地。", "",
          "| 真实可用 | 可用率 | 节点数 | 中位延迟 | 链接 |", "|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['verified']} | {r['vrate']}% | {r['nodes']} | "
                  f"{r['med_delay']}ms | {r['url']} |")
    md += ["", f"合计：去重节点 {uniq}，直连存活 {a1}，真实可用 {vv}。"]

    json.dump(rows, open(os.path.join(C.WORK, f"{prefix}_report.json"), "w"),
              ensure_ascii=False, indent=1)
    with open(os.path.join(C.WORK, f"{prefix}_report.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("报表:", os.path.join(C.WORK, f"{prefix}_report.md"))


if __name__ == "__main__":
    main()
