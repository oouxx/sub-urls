#!/usr/bin/env python3
"""公共定义：路径、HTTP 抓取、mihomo 内核管理。

可用环境变量：
  SUBCHECK_WORKDIR  工作目录（默认 <repo>/.check-work）
  SUBCHECK_PROXY    抓取订阅/下载内核时使用的代理，例如 http://127.0.0.1:1082
                    （默认空 = 直连。注意：节点探测始终裸连，与它无关）
"""
import gzip
import json
import os
import platform
import ssl
import stat
import subprocess
import time
import urllib.request

CHECKER_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(CHECKER_DIR)
WORK = os.environ.get("SUBCHECK_WORKDIR") or os.path.join(REPO_DIR, ".check-work")
RAW = os.path.join(WORK, "raw")
BIN_DIR = os.path.join(WORK, "bin")
RUN_DIR = os.path.join(WORK, "mihomo-run")
MIHOMO = os.path.join(BIN_DIR, "mihomo")

API_HOST = "127.0.0.1:19093"
API = f"http://{API_HOST}"
SECRET = "chk"
HDR = {"Authorization": f"Bearer {SECRET}"}
MIXED_PORT = 17990
VERIFY_MIXED_PORT = 17991
VERIFY_PORT0 = 22000          # 二阶段每个节点一个 socks 入口的起始端口

TEST_URL = "http://www.gstatic.com/generate_204"
DELAY_TIMEOUT = 5000
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
TRACE_TIMEOUT = 12

MIHOMO_VERSION = "v1.19.33"
PROXY = os.environ.get("SUBCHECK_PROXY", "").strip()
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

# 订阅清单文件（相对 repo 根目录）
SUB_FILES = ("gitraw.txt", "jichang.txt")

# 探测时剔除干净的环境变量，保证「裸连」
def clean_env():
    env = {k: v for k, v in os.environ.items()
           if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env["SAFE_PATHS"] = WORK
    return env


def ensure_dirs():
    for d in (WORK, RAW, BIN_DIR, RUN_DIR):
        os.makedirs(d, exist_ok=True)


def opener(proxy=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    handlers.append(urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}))
    return urllib.request.build_opener(*handlers)


def http_get(url, timeout=30, proxy=None, headers=None):
    """返回 (status, body:bytes)。"""
    req = urllib.request.Request(url, headers={**(headers or {"User-Agent": UA})})
    with opener(proxy).open(req, timeout=timeout) as r:
        return r.status, r.read()


def try_get(url, timeout=30, proxies=(None,)):
    """按顺序尝试直连/代理，返回 (ok, status, body, 用时, 方式, 错误)。"""
    last = ""
    for proxy in proxies:
        t0 = time.time()
        try:
            code, body = http_get(url, timeout=timeout, proxy=proxy)
            return True, code, body, time.time() - t0, ("proxy" if proxy else "direct"), ""
        except Exception as e:
            last = f"{'proxy' if proxy else 'direct'}:{type(e).__name__}:{e}"[:200]
    return False, 0, b"", 0.0, "", last


def load_sub_urls():
    """读出两个 txt 里的订阅链接（# 开头为注释）。"""
    urls = []
    for name in SUB_FILES:
        path = os.path.join(REPO_DIR, name)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append((name, line))
    return urls


def ensure_mihomo(version=MIHOMO_VERSION):
    """确保本地有 mihomo 内核，没有则从 GitHub Releases 下载。"""
    if os.path.exists(MIHOMO):
        return MIHOMO
    system = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64",
            "x86_64": "amd64", "AMD64": "amd64"}.get(platform.machine())
    if not system or not arch:
        raise SystemExit(f"不支持自动下载内核的平台: {platform.system()} {platform.machine()}，"
                         f"请手动放置到 {MIHOMO}")
    ensure_dirs()
    proxies = [p for p in (PROXY, None) if p is not None] or [None]
    if PROXY:
        proxies = [PROXY, None]
    assets = []
    try:
        _, body = http_get(f"https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/{version}",
                           timeout=30, proxy=PROXY or None,
                           headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
        assets = [a["browser_download_url"] for a in json.loads(body).get("assets", [])]
    except Exception:
        pass
    want = f"mihomo-{system}-{arch}-{version}.gz"
    url = next((a for a in assets if a.rsplit("/", 1)[-1] == want), None)
    if not url:
        url = (f"https://github.com/MetaCubeX/mihomo/releases/download/{version}/{want}")
    print(f"下载 mihomo 内核: {url}")
    ok, code, body, _, via, err = try_get(url, timeout=180, proxies=proxies)
    if not ok:
        raise SystemExit(f"内核下载失败: {err}\n可设置 SUBCHECK_PROXY 走代理后重试")
    with open(MIHOMO, "wb") as f:
        f.write(gzip.decompress(body))
    os.chmod(MIHOMO, os.stat(MIHOMO).st_mode | stat.S_IEXEC)
    print("内核就绪:", MIHOMO)
    return MIHOMO


def mihomo_version():
    if not os.path.exists(MIHOMO):
        return ""
    r = subprocess.run([MIHOMO, "-v"], capture_output=True, text=True)
    return (r.stdout or r.stderr).strip()
