#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web 中间件信息识别工具 v1.0

用途：输入站点地址，根据公开的 HTTP 响应头和页面特征，
      识别 Nginx / Apache / IIS / Tomcat 等主流中间件及版本信息，
      用于资产梳理（搞清楚一台服务器上跑的是什么 Web 服务）。

用法：
    python scanner.py -u https://example.com          # 扫描单个站点
    python scanner.py -f urls.txt -o result.csv       # 扫描列表文件，导出 CSV 报表
    python scanner.py -u https://example.com -t 20    # 指定并发线程数

依赖：pip install requests
"""

import argparse
import csv
import re
import sys
from concurrent.futures import ThreadPoolExecutor

import requests

# 关闭 SSL 证书告警（很多站点证书不标准，不影响中间件识别）
requests.packages.urllib3.disable_warnings()

# ============================================================
# 中间件特征库（fingerprint）
# 每条特征 = (检查位置, 关键字, 分值)
#   - 检查位置："server" 表示匹配响应头 Server 字段
#                "x-powered-by" 表示匹配响应头 X-Powered-By 字段
#                "html" 表示匹配网页内容
#   - 命中关键字就加对应分值，最后分数最高的中间件胜出
# 想扩展中间件（如 Jetty、Caddy、LiteSpeed 等）就在下面加一条
# ============================================================
FEATURE_LIB = {
    "Nginx": [
        ("server", "nginx", 5),
    ],
    "Apache": [
        ("server", "apache", 5),
    ],
    "IIS": [
        ("server", "microsoft-iis", 5),
        ("server", "iis", 3),
    ],
    "Tomcat": [
        ("server", "coyote", 5),          # Tomcat 的 Server 头通常是 "Apache-Coyote/1.1"
        ("x-powered-by", "tomcat", 5),
        ("html", "apache tomcat", 3),     # 默认错误页会出现 "Apache Tomcat" 字样
    ],
}

# 请求时伪装成浏览器，避免被简单的 WAF / 防护规则拦截
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

# 采集网页内容时只保留前 N 个字符，够匹配特征就行，节省时间
HTML_SAMPLE_LEN = 5000


def fetch_one(url, timeout=10):
    """采集单个站点的响应头与页面内容。

    返回: (url, headers字典, 页面文本, 错误信息)
    出错时 headers 为空、页面为空，错误信息里带原因。
    """
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": UA},
            verify=False,          # 不校验证书，识别阶段够用
            allow_redirects=True,  # 跟随跳转（http -> https 等）
        )
        # 键统一转小写，方便后面用 "server" / "x-powered-by" 查找
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return url, headers, resp.text[:HTML_SAMPLE_LEN], None
    except Exception as exc:
        return url, {}, "", str(exc)


def extract_version(server_header):
    """从 Server 头里提取版本号，如 'nginx/1.18.0' -> '1.18.0'"""
    match = re.search(r"([\d.]+)", server_header or "")
    return match.group(1) if match else ""


def identify(headers, html):
    """打分匹配：遍历特征库，统计每个中间件的命中总分。

    返回: 按分数从高到低排序的 [(中间件名, 分数), ...]
    """
    html_lower = html.lower()
    scores = {}
    for middleware, features in FEATURE_LIB.items():
        total = 0
        for field, keyword, points in features:
            if field == "html":
                if keyword in html_lower:
                    total += points
            else:
                if keyword in headers.get(field, "").lower():
                    total += points
        if total > 0:
            scores[middleware] = total
    return sorted(scores.items(), key=lambda item: item[1], reverse=True)


def scan(url):
    """扫描一个站点，返回一行结果字典。"""
    url, headers, html, error = fetch_one(url)
    server = headers.get("server", "")  # 键已统一为小写

    if error:
        return {"url": url, "middleware": "采集失败", "version": "", "score": 0,
                "detail": error}

    ranked = identify(headers, html)
    if ranked:
        name, score = ranked[0]
        # Nginx/Apache 的版本通常能从 Server 头直接读到
        version = extract_version(server) if name in ("Nginx", "Apache") else ""
        return {"url": url, "middleware": name, "version": version, "score": score,
                "detail": f"Server: {server}"}

    return {"url": url, "middleware": "未识别", "version": "", "score": 0,
            "detail": f"Server: {server}"}


def main():
    parser = argparse.ArgumentParser(description="Web 中间件信息识别工具")
    parser.add_argument("-u", "--url", help="要扫描的单个站点地址，如 https://example.com")
    parser.add_argument("-f", "--file", help="站点列表文件，每行一个地址")
    parser.add_argument("-o", "--output", default="result.csv", help="结果导出的 CSV 文件名")
    parser.add_argument("-t", "--threads", type=int, default=10, help="并发线程数（默认 10）")
    args = parser.parse_args()

    # 确定要扫描的 URL 列表
    urls = []
    if args.url:
        urls = [args.url]
    elif args.file:
        with open(args.file, encoding="utf-8") as fp:
            urls = [line.strip() for line in fp if line.strip()]
    else:
        print("请用 -u 指定单个地址，或用 -f 指定站点列表文件")
        sys.exit(1)

    print(f"共 {len(urls)} 个站点，开始扫描（线程数 {args.threads}）...")
    results = []
    # ThreadPoolExecutor 实现并发采集：多个站点同时请求，速度更快
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for row in pool.map(scan, urls):
            results.append(row)
            print(f"[{row['middleware']}] {row['url']}  {row['detail']}")

    # 导出结构化 CSV 报表（utf-8-sig 编码，Excel 打开不乱码）
    with open(args.output, "w", newline="", encoding="utf-8-sig") as fp:
        writer = csv.DictWriter(fp, fieldnames=["url", "middleware", "version", "score", "detail"])
        writer.writeheader()
        writer.writerows(results)
    print(f"完成，结果已导出到 {args.output}")


if __name__ == "__main__":
    main()
