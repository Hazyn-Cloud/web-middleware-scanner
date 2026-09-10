# Web 中间件信息识别工具

基于 Python 开发的 Web 中间件信息采集识别工具。输入站点地址，根据站点公开的 HTTP 响应头与页面特征，识别 **Nginx / Apache / IIS / Tomcat** 等主流中间件产品及版本信息，用于资产梳理。

本工具由 AI 辅助开发（Claude Code），结合日常渗透测试对资产梳理的需求完成代码框架搭建与迭代。

## 功能特性

- 采集站点公开的 HTTP 响应头与页面特征
- 内置中间件特征库（指纹库），可自行扩展
- 打分匹配算法：多条特征按分值累计，识别更准
- 并发采集：多线程同时扫描多个站点
- 结构化报表导出：结果保存为 CSV，Excel 可直接打开

## 环境要求

- Python 3.8+
- 安装依赖：`pip install -r requirements.txt`

## 使用方法

```bash
# 1. 扫描单个站点
python scanner.py -u https://example.com

# 2. 扫描列表文件（每行一个地址）
python scanner.py -f urls.txt -o result.csv

# 3. 指定并发线程数（默认 10）
python scanner.py -u https://example.com -t 20
```

运行示例：

```
$ python scanner.py -u https://example.com
共 1 个站点，开始扫描（线程数 10）...
[Nginx] https://example.com  Server: nginx/1.18.0
完成，结果已导出到 result.csv
```

输出 CSV 字段：`url`（站点地址）、`middleware`（中间件）、`version`（版本）、`score`（匹配分）、`detail`（原始 Server 头信息）。

## 特征库扩展

特征定义在 `scanner.py` 的 `FEATURE_LIB` 中，格式为：

```python
"中间件名": [
    ("检查位置", "关键字", 分值),
]
```

- `server`：匹配响应头 Server 字段
- `x-powered-by`：匹配响应头 X-Powered-By 字段
- `html`：匹配网页内容

想新增中间件（如 Jetty、Caddy、LiteSpeed），照着加一条即可：

```python
"Caddy": [
    ("server", "caddy", 5),
],
```

## 识别原理（面试常问）

1. **特征采集**：发起 HTTP 请求，读取响应头（重点看 `Server`、`X-Powered-By` 字段）和页面内容。
2. **指纹匹配**：把采集到的内容拿去和特征库逐条比对。
3. **打分判定**：每个中间件有多条特征，命中一条加对应分值，累计得分最高者判定为该中间件。
4. **版本提取**：从 Server 头中用正则提取版本号，如 `nginx/1.18.0` -> `1.18.0`。

## 已知限制

- 部分站点会隐藏或修改 Server 头（安全加固），此时只能靠页面特征，识别率下降
- 仅做被动采集识别，不做主动漏洞扫描

## 免责声明

本工具仅用于授权范围内的安全测试与学习研究，请勿用于未授权的站点扫描。
