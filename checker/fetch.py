#!/usr/bin/env python3
"""一阶段抓取：把 gitraw.txt / jichang.txt 里的订阅地址全部拉下来。

- 默认直连抓取；设置了 SUBCHECK_PROXY 时，直连失败会再用代理重试
- {Ymd} {Y} {m} {d} 这类日期占位符会自动展开成今天
产物：.check-work/raw/NN.bin 与 .check-work/fetch_meta.json
"""
import datetime
import json
import os
import sys

import common as C


def expand(url):
    d = datetime.date.today()
    return (url.replace("{Ymd}", f"{d.year}{d.month:02d}{d.day:02d}")
               .replace("{Y}", str(d.year))
               .replace("{m}", f"{d.month:02d}")
               .replace("{d}", f"{d.day:02d}"))


def main():
    C.ensure_dirs()
    proxies = [C.PROXY, None] if C.PROXY else [None]
    subs = C.load_sub_urls()
    meta = []
    for i, (src_file, raw) in enumerate(subs):
        url = expand(raw)
        rec = {"idx": i, "file": src_file, "raw": raw, "url": url}
        ok, code, body, secs, via, err = C.try_get(url, timeout=40, proxies=proxies)
        if ok:
            path = os.path.join(C.RAW, f"{i:02d}.bin")
            with open(path, "wb") as f:
                f.write(body)
            rec.update({"http": code, "size": len(body), "secs": round(secs, 2),
                        "via": via, "path": path})
        else:
            rec.update({"http": 0, "size": 0, "error": err})
        meta.append(rec)
        print(f"[{i:02d}] {rec['http'] or 'ERR':>4} {rec['size']:>8} "
              f"{(rec.get('via') or '-'):<6} {raw}", flush=True)

    with open(os.path.join(C.WORK, "fetch_meta.json"), "w") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)
    okn = sum(1 for r in meta if r.get('size'))
    print(f"抓取完成：{okn}/{len(meta)} 成功")


if __name__ == "__main__":
    sys.exit(main())
