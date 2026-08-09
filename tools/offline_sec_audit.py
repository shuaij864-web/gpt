#!/usr/bin/env python3
"""
离线安全审计工具（防守用途）

功能：
1) 解析 Web 访问日志，发现可疑 SQL 注入 / SSRF 探测痕迹（仅规则检测，不发起攻击流量）
2) 输出 JSON 报告与终端摘要

用法：
  python offline_sec_audit.py --log access.log --out report.json
  python offline_sec_audit.py --log access.log --top 20
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable


SQLI_PATTERNS = [
    r"\bunion\b",
    r"\bselect\b",
    r"\bsleep\s*\(",
    r"\bbenchmark\s*\(",
    r"\bor\b\s+1\s*=\s*1",
    r"\bload_file\s*\(",
    r"\binto\s+outfile\b",
    r"\binformation_schema\b",
]

SSRF_PATTERNS = [
    r"https?://",
    r"file://",
    r"gopher://",
    r"dict://",
    r"ftp://",
    r"@",  # 可疑 URL 认证信息
    r"169\.254\.169\.254",
    r"127\.0\.0\.1",
    r"localhost",
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b",
]

COMMON_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>[^\s"]+)\s*[^\"]*"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s*"?(?P<referer>[^"]*)"?\s*"?(?P<ua>[^"]*)"?'
)


@dataclass
class Finding:
    line_no: int
    category: str
    risk: str
    ip: str
    method: str
    path: str
    status: str
    matched_rules: list[str]
    raw: str


def compile_rules(patterns: Iterable[str]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


def parse_log_line(line: str) -> dict | None:
    m = COMMON_LOG_RE.match(line.strip())
    if not m:
        return None
    return m.groupdict()


def detect(path: str, sql_rules: list[re.Pattern[str]], ssrf_rules: list[re.Pattern[str]]) -> tuple[list[str], list[str]]:
    sql_hits = [r.pattern for r in sql_rules if r.search(path)]
    ssrf_hits = [r.pattern for r in ssrf_rules if r.search(path)]
    return sql_hits, ssrf_hits


def scan_log(log_path: Path) -> dict:
    sql_rules = compile_rules(SQLI_PATTERNS)
    ssrf_rules = compile_rules(SSRF_PATTERNS)

    findings: list[Finding] = []
    ip_counter = Counter()
    path_counter = Counter()
    status_counter = Counter()
    parse_failures = 0

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for idx, raw in enumerate(f, start=1):
            line = raw.rstrip("\n")
            parsed = parse_log_line(line)
            if not parsed:
                parse_failures += 1
                continue

            ip = parsed["ip"]
            method = parsed["method"]
            path = parsed["path"]
            status = parsed["status"]

            ip_counter[ip] += 1
            path_counter[path] += 1
            status_counter[status] += 1

            sql_hits, ssrf_hits = detect(path, sql_rules, ssrf_rules)
            if sql_hits:
                findings.append(
                    Finding(
                        line_no=idx,
                        category="SQLi-Probing",
                        risk="high",
                        ip=ip,
                        method=method,
                        path=path,
                        status=status,
                        matched_rules=sql_hits,
                        raw=line,
                    )
                )
            if ssrf_hits:
                findings.append(
                    Finding(
                        line_no=idx,
                        category="SSRF-Probing",
                        risk="high",
                        ip=ip,
                        method=method,
                        path=path,
                        status=status,
                        matched_rules=ssrf_hits,
                        raw=line,
                    )
                )

    findings_by_ip = defaultdict(int)
    findings_by_category = defaultdict(int)
    for item in findings:
        findings_by_ip[item.ip] += 1
        findings_by_category[item.category] += 1

    report = {
        "meta": {
            "tool": "offline_sec_audit",
            "version": "1.0.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "log_file": str(log_path),
        },
        "stats": {
            "total_lines": sum(ip_counter.values()) + parse_failures,
            "parsed_lines": sum(ip_counter.values()),
            "parse_failures": parse_failures,
            "unique_ips": len(ip_counter),
            "unique_paths": len(path_counter),
            "status_distribution": status_counter,
        },
        "top_talkers": ip_counter.most_common(20),
        "top_paths": path_counter.most_common(20),
        "finding_summary": {
            "total_findings": len(findings),
            "by_category": dict(findings_by_category),
            "by_ip": dict(sorted(findings_by_ip.items(), key=lambda x: x[1], reverse=True)[:20]),
        },
        "findings": [asdict(x) for x in findings],
    }
    return report


def print_summary(report: dict, top: int) -> None:
    print("=" * 72)
    print("离线安全审计摘要")
    print("=" * 72)
    s = report["stats"]
    print(f"日志文件: {report['meta']['log_file']}")
    print(f"总行数: {s['total_lines']} | 成功解析: {s['parsed_lines']} | 解析失败: {s['parse_failures']}")
    print(f"唯一IP: {s['unique_ips']} | 唯一路径: {s['unique_paths']}")
    print(f"发现总数: {report['finding_summary']['total_findings']}")
    print()

    print(f"Top {top} 请求源 IP:")
    for ip, count in report["top_talkers"][:top]:
        print(f"  {ip:<18} {count}")

    print()
    print("发现分类:")
    for cat, count in report["finding_summary"]["by_category"].items():
        print(f"  {cat:<16} {count}")


def main() -> None:
    parser = argparse.ArgumentParser(description="离线日志安全审计工具（防守用途）")
    parser.add_argument("--log", required=True, help="访问日志路径（Nginx/Apache common combined 格式）")
    parser.add_argument("--out", default="audit_report.json", help="报告输出路径（JSON）")
    parser.add_argument("--top", type=int, default=10, help="终端展示 top 条目")
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        raise SystemExit(f"日志文件不存在: {log_path}")

    report = scan_log(log_path)
    out_path = Path(args.out)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print_summary(report, top=args.top)
    print()
    print(f"JSON 报告已写入: {out_path.resolve()}")


if __name__ == "__main__":
    main()
