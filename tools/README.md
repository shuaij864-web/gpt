# Offline Security Audit Tools

本目录提供**离线可运行**的防守型工具，不包含漏洞利用功能。

## 1) `offline_sec_audit.py`

用途：对 Web 访问日志做离线检测，标记疑似 SQL 注入 / SSRF 探测痕迹。

### 运行示例

```bash
python tools/offline_sec_audit.py --log /path/to/access.log --out report.json --top 20
```

### 输入要求

- Nginx/Apache 常见 access log（combined/common 变体均可尝试）

### 输出内容

- 终端摘要（Top IP、分类统计）
- JSON 详细报告（可用于演练报告附录）

### 注意

- 该工具仅做规则匹配，不发起任何网络攻击请求。
- 命中结果是“可疑行为”，需要结合上下文进行人工复核。
