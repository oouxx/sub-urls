#!/usr/bin/env python3
"""二阶段汇总：解析各订阅内容 -> 去重 -> 生成 mihomo 配置。

产物：.check-work/config.yaml（全部唯一节点）、.check-work/nodes.json（节点来源表）
"""
import json
import os

import yaml

import common as C
from parse import parse_file

KEY_FIELDS = ("uuid", "password")


def key_of(proxy):
    cred = next((proxy[f] for f in KEY_FIELDS if proxy.get(f)), "")
    return (proxy.get("type"), str(proxy.get("server")).lower(),
            proxy.get("port"), str(cred))


def main():
    meta_path = os.path.join(C.WORK, "fetch_meta.json")
    if not os.path.exists(meta_path):
        raise SystemExit("没有抓取结果，请先运行: python checker/fetch.py")
    meta = json.load(open(meta_path))

    sources, nodes, seen = [], [], {}
    for rec in meta:
        entry = {"idx": rec["idx"], "file": rec["file"], "url": rec["raw"],
                 "http": rec.get("http"), "size": rec.get("size", 0),
                 "fmt": "-", "count": 0, "error": rec.get("error", "")}
        if rec.get("path") and rec.get("size"):
            try:
                fmt, ns = parse_file(rec["path"])
                entry["fmt"], entry["count"] = fmt, len(ns)
                for pr in ns:
                    k = key_of(pr)
                    if k in seen:
                        seen[k]["srcs"].append(rec["idx"])
                        continue
                    item = {"src": rec["idx"], "orig": pr.get("name", ""),
                            "proxy": pr, "srcs": [rec["idx"]]}
                    seen[k] = item
                    nodes.append(item)
            except Exception as e:
                entry["error"] = f"parse:{e}"[:150]
        sources.append(entry)

    total = sum(s["count"] for s in sources)
    print(f"订阅 {len(sources)} 条，解析出节点 {total} 个，去重后 {len(nodes)} 个")

    for n, item in enumerate(nodes):
        item["proxy"]["name"] = f"n{n:05d}"

    cfg = {
        "mixed-port": C.MIXED_PORT,
        "external-controller": C.API_HOST,
        "secret": C.SECRET,
        "mode": "direct",
        "log-level": "warning",
        "proxies": [it["proxy"] for it in nodes],
        "rules": ["MATCH,DIRECT"],
    }
    with open(os.path.join(C.WORK, "config.yaml"), "w") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False, width=4096)

    json.dump({"sources": sources,
               "nodes": [{"id": it["proxy"]["name"], "src": it["src"],
                          "srcs": it["srcs"], "orig": it["orig"],
                          "type": it["proxy"].get("type"),
                          "server": it["proxy"].get("server"),
                          "port": it["proxy"].get("port")} for it in nodes]},
              open(os.path.join(C.WORK, "nodes.json"), "w"),
              ensure_ascii=False, indent=0)
    print("配置已生成:", os.path.join(C.WORK, "config.yaml"))


if __name__ == "__main__":
    main()
