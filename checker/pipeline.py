#!/usr/bin/env python3
"""三阶段实测：mihomo 内核**裸连**探测（不经任何本机/系统代理）。

1. 启动内核；配置文件里无法初始化的坏节点自动剔除（内核会逐个报错）
2. 一阶段：/proxies/{name}/delay 直连每个节点访问 gstatic 204
3. 二阶段：给每个存活节点开一个独立 socks 入口（mihomo listeners），
   真实访问 https://www.cloudflare.com/cdn-cgi/trace
   要求 HTTPS 成功且拿到真实出口 IP —— 才算「真实可用」

用法: python checker/pipeline.py [config.yaml] [prefix] [阶段1并发] [阶段2并发]
产物: .check-work/<prefix>_delay.json、.check-work/<prefix>_verify.json
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import yaml

import common as C


def stop_core():
    subprocess.run(["pkill", "-f", C.MIHOMO])
    time.sleep(1)


def start_core(cfg_path, prefix, drop_bad=True):
    """启动内核，返回 (proc, 剔除列表)。"""
    dropped, log_path = [], os.path.join(C.WORK, f"{prefix}_core.log")
    for _ in range(500):
        log = open(log_path, "w")
        proc = subprocess.Popen([C.MIHOMO, "-d", C.RUN_DIR, "-f", cfg_path],
                                stdout=log, stderr=subprocess.STDOUT,
                                env=C.clean_env())
        for _ in range(60):
            if proc.poll() is not None:
                break
            try:
                urllib.request.urlopen(
                    urllib.request.Request(C.API + "/version", headers=C.HDR),
                    timeout=3).read()
                return proc, dropped
            except Exception:
                time.sleep(0.25)
        text = open(log_path).read()
        m = re.search(r'fatal msg="Parse config error: proxy (\d+): (.{0,150})', text)
        if not (m and drop_bad):
            raise SystemExit("内核启动失败:\n" + text[:1500])
        cfg = yaml.safe_load(open(cfg_path))
        bad = cfg["proxies"].pop(int(m.group(1)))
        dropped.append({"name": bad.get("name"), "type": bad.get("type"),
                        "server": bad.get("server"), "reason": m.group(2)})
        yaml.safe_dump(cfg, open(cfg_path, "w"), allow_unicode=True,
                       sort_keys=False, width=4096)
    raise SystemExit("坏节点过多，放弃")


def delay_one(name):
    url = (f"{C.API}/proxies/{urllib.parse.quote(name)}/delay"
           f"?timeout={C.DELAY_TIMEOUT}&url={urllib.parse.quote(C.TEST_URL, safe='')}")
    try:
        body = urllib.request.urlopen(
            urllib.request.Request(url, headers=C.HDR),
            timeout=C.DELAY_TIMEOUT / 1000 + 5).read()
        return json.loads(body).get("delay")
    except Exception:
        return None


def stage1(names, conc, prefix):
    res, t0 = {}, time.time()
    with ThreadPoolExecutor(max_workers=conc) as ex:
        for k, (name, d) in enumerate(zip(names, ex.map(delay_one, names))):
            res[name] = {"delay": d}
            if (k + 1) % 1000 == 0:
                alive = sum(1 for v in res.values() if v["delay"])
                print(f"  一阶段 {k+1}/{len(names)} 存活={alive} "
                      f"{time.time()-t0:.0f}s", flush=True)
    return res


def probe(name, port, url):
    cmd = ["curl", "-s", "--socks5-hostname", f"127.0.0.1:{port}", "--noproxy", "",
           "-m", str(C.TRACE_TIMEOUT), "-w", "\n__META__%{http_code} %{time_total}", url]
    out = {"ok": False, "ip": "", "loc": "", "code": "", "t": 0.0}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=C.TRACE_TIMEOUT + 8, env=C.clean_env())
        body, _, meta = r.stdout.rpartition("__META__")
        code, t = (meta.split() + ["", ""])[:2]
        out["code"], out["t"] = code, float(t or 0)
        for line in body.splitlines():
            if line.startswith("ip="):
                out["ip"] = line[3:].strip()
            elif line.startswith("loc="):
                out["loc"] = line[4:].strip()
        out["ok"] = code == "200" and bool(out["ip"])
    except Exception:
        pass
    return out


def stage2(cfg_path, alive, conc, prefix):
    cfg = yaml.safe_load(open(cfg_path))
    alive_set = set(alive)
    keep = [p for p in cfg["proxies"] if p["name"] in alive_set]
    listeners, port_of = [], {}
    for i, p in enumerate(keep):
        port = C.VERIFY_PORT0 + i
        port_of[p["name"]] = port
        listeners.append({"name": f"in{i}", "type": "socks", "port": port,
                          "listen": "127.0.0.1", "proxy": p["name"]})
    vcfg = {"mixed-port": C.VERIFY_MIXED_PORT, "external-controller": C.API_HOST,
            "secret": C.SECRET, "mode": "direct", "log-level": "warning",
            "proxies": keep, "listeners": listeners, "rules": ["MATCH,DIRECT"]}
    vpath = os.path.join(C.WORK, f"{prefix}_verify.yaml")
    yaml.safe_dump(vcfg, open(vpath, "w"), allow_unicode=True,
                   sort_keys=False, width=4096)
    stop_core()
    start_core(vpath, prefix, drop_bad=False)
    res, t0 = {}, time.time()
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = {n: ex.submit(probe, n, port_of[n], C.TRACE_URL) for n in port_of}
        for k, (n, fut) in enumerate(futs.items()):
            res[n] = fut.result()
            if (k + 1) % 200 == 0:
                ok = sum(1 for v in res.values() if v["ok"])
                print(f"  二阶段 {k+1}/{len(futs)} 真实可用={ok} "
                      f"{time.time()-t0:.0f}s", flush=True)
    return res


def main():
    C.ensure_dirs()
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(C.WORK, "config.yaml")
    prefix = sys.argv[2] if len(sys.argv) > 2 else "run"
    conc1 = int(sys.argv[3]) if len(sys.argv) > 3 else 250
    conc2 = int(sys.argv[4]) if len(sys.argv) > 4 else 40

    C.ensure_mihomo()
    print("内核:", C.mihomo_version())
    stop_core()
    _, dropped = start_core(cfg_path, prefix)
    cfg = yaml.safe_load(open(cfg_path))
    names = [p["name"] for p in cfg["proxies"]]
    print(f"加载节点 {len(names)} 个，剔除无法初始化节点 {len(dropped)} 个")

    d = stage1(names, conc1, prefix)
    json.dump(d, open(os.path.join(C.WORK, f"{prefix}_delay.json"), "w"))
    alive = [n for n, v in d.items() if v["delay"]]
    print(f"一阶段完成：直连存活 {len(alive)}/{len(d)}")

    v = stage2(cfg_path, alive, conc2, prefix)
    json.dump(v, open(os.path.join(C.WORK, f"{prefix}_verify.json"), "w"))
    print(f"二阶段完成：真实可用 {sum(1 for x in v.values() if x['ok'])}/{len(v)}")
    stop_core()


if __name__ == "__main__":
    main()
