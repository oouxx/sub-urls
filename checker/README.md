# checker —— 订阅链接质量实测

对本仓库 `gitraw.txt` / `jichang.txt` 里的每条订阅链接做**真实可用性**检测，
用于决定保留哪些链接。

## 快速开始

```bash
./checker/run.sh          # 抓取 -> 汇总去重 -> 两阶段实测 -> 出报表
```

首次运行会自动建 `.venv` 装 PyYAML，并把 mihomo 内核下载到 `.check-work/bin/`。
产物全部在 `.check-work/`（已 gitignore），核心结论看 `.check-work/run_report.md`。

分步执行：

```bash
python checker/fetch.py                       # 1. 抓取订阅内容
python checker/build.py                       # 2. 解析 + 去重 + 生成内核配置
python checker/pipeline.py .check-work/config.yaml run 250 40   # 3. 实测
python checker/report.py run                  # 4. 按订阅源出质量报表
```

## 检测原理

**全程裸连**：剔除 `*_proxy` 环境变量，由 mihomo 内核直接向节点拨号，
不经过本机/系统代理，因此结果反映的就是本机网络下的真实体验。

| 阶段 | 做法 | 通过标准 |
|---|---|---|
| 一阶段 直连探测 | mihomo `/proxies/{name}/delay` 直连节点访问 `gstatic.com/generate_204` | 5s 内返回延迟 |
| 二阶段 真实落地 | 给每个存活节点开一个独立 socks 入口（mihomo `listeners` 的 `proxy` 绑定），curl 真实访问 `https://www.cloudflare.com/cdn-cgi/trace` | HTTPS 成功 + 拿到真实出口 IP |

只有两阶段都通过才算「真实可用」。这样可以排除：端口通但代理协议不通、
能握手但出不了网、DNS 劫持/假节点等。

## 支持解析的订阅格式

- Clash / mihomo YAML（`proxies:` 列表）
- base64 包裹的 v2ray 链接
- 明文 v2ray 链接（vmess / vless / trojan / ss / ssr / hysteria2 / tuic）
- sing-box JSON（`outbounds`）

统计口径里一条链接的「节点数」是它自己的节点数（与其他链接重复的也算），
「可用率」= 真实可用 / 节点数，跨链接完全相同的节点会自动去重后再实测一次。

## 环境变量

| 变量 | 说明 |
|---|---|
| `SUBCHECK_PROXY` | 抓取订阅/下载内核时使用的代理，如 `http://127.0.0.1:1082`。**探测始终裸连，不受影响** |
| `SUBCHECK_WORKDIR` | 工作目录，默认 `.check-work` |
| `CONC1` / `CONC2` | 一阶段/二阶段并发，默认 250 / 40 |
| `PREFIX` | 本次运行的产物前缀，默认 `run` |
| `PYTHON` | 指定解释器（已装 pyyaml 的） |

## 端口与进程

- 内核 API：`127.0.0.1:19093`（secret `chk`）
- 二阶段 socks 入口：从 `22000` 起每节点一个，跑完自动释放
- 脚本只 `pkill` 自己下载的那个内核（`.check-work/bin/mihomo`），不影响系统里其他 mihomo/clash

## 文件

| 文件 | 作用 |
|---|---|
| `common.py` | 路径/环境变量、HTTP 抓取、mihomo 下载与启动环境 |
| `parse.py` | 订阅内容 → Clash 代理字典（各协议链接、base64、sing-box JSON） |
| `fetch.py` | 抓取两个 txt 里的链接（含 `{Ymd}` 等日期占位符展开） |
| `build.py` | 解析 + 去重 + 生成 `config.yaml` / `nodes.json` |
| `pipeline.py` | 启动内核（自动剔除无法初始化的坏节点）→ 一阶段 → 二阶段 |
| `report.py` | 按订阅源统计，输出终端表格 + Markdown 报表 |
| `run.sh` | 一键串联以上步骤 |

## 注意

- 免费节点波动很大，同一批链接两次检测结果会有差异（本次实测中两次验证集的
  交集只有约六成），所以「可用率」只适合同批次横向比较，别当绝对值。
- 单次全量检测（约 1.3 万节点）耗时 3~6 分钟，取决于网络。
- 结果只代表**本机网络环境**下的可用性；换个网络（尤其境外）结论会变。
