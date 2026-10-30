# sub-urls

远程订阅链接。

- `gitraw.txt`：GitHub raw 订阅源
- `jichang.txt`：机场 / 聚合订阅

## 链接实测

`checker/` 里有一套检测脚本，用 mihomo 内核**裸连**实测每条链接节点的真实可用性
（直连探测 + 真实 HTTPS 落地验证），并按链接输出可用数与可用率报表：

```bash
./checker/run.sh     # 报表输出到 .check-work/run_report.md
```

详见 [checker/README.md](checker/README.md)。
