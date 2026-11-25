# CVE 漏洞研究记录

用于归档原创漏洞研究成果。每个 CVE 独立目录，报告、披露材料、概念验证（PoC）和逆向分析文件分类保存。

## 漏洞索引

| CVE | 厂商 / 产品 | 漏洞类型 | 受影响版本 | 披露日期 | 报告 |
|---|---|---|---|---|---|
| [CVE-2026-133680](https://www.cve.org/CVERecord?id=CVE-2026-133680) | D-Link DCS-935L | OS 命令注入（CWE-78） | 1.10.01 | 2026-11-20 | [中文](CVE-2026-133680/reports/CVE-2026-133680_report.zh-CN.md) / [English](CVE-2026-133680/reports/CVE-2026-133680_report.en.md) |

## CVE-2026-133680

D-Link DCS-935L 1.10.01 的 `setconf.cgi` 中，`loginRouter` 未安全处理 POST 参数 `account` / `password`，导致 OS 命令注入。

- **官方记录**：[CVE](https://www.cve.org/CVERecord?id=CVE-2026-133680) · [VulDB VDB-441406](https://vuldb.com/vuln/441406)
- **官方评分**：CVSS 4.0 **9.4 / Critical**；CVSS 3.1 **9.9 / Critical**（由 VulDB CNA 提供）
- **报告**：[中文 Markdown](CVE-2026-133680/reports/CVE-2026-133680_report.zh-CN.md) · [中文 PDF](CVE-2026-133680/reports/CVE-2026-133680_report.zh-CN.pdf) · [English Markdown](CVE-2026-133680/reports/CVE-2026-133680_report.en.md) · [English PDF](CVE-2026-133680/reports/CVE-2026-133680_report.en.pdf)
- **披露材料**：[中文](CVE-2026-133680/disclosure/vuldb-submission.zh-CN.md) · [English](CVE-2026-133680/disclosure/vuldb-submission.en.md)
- **PoC**：[exploit_setconf.py](CVE-2026-133680/poc/exploit_setconf.py)
- **逆向分析**：[setconf.cgi](CVE-2026-133680/analysis/setconf.cgi) · [IDA 数据库](CVE-2026-133680/analysis/setconf.cgi.i64)

> 验证基于静态 MIPS 分析和 qemu-user 仿真，未在物理设备上复现；真实设备上前置 `httpd` 的认证可达性仍需补验。VulDB 提交稿中的评分是提交时估算，当前评分以官方 CVE 记录为准。

## 目录规范

```text
CVE-<年份>-<编号>/
├── reports/       # 中英文报告、PDF 和报告截图
│   └── assets/
├── disclosure/    # CVE / VulDB 等披露提交材料
├── poc/           # 概念验证脚本
└── analysis/      # 目标二进制与逆向工程数据库
```

新增条目时按同一结构归档，并更新上方索引。仓库不收录完整固件；`analysis/` 中保存的是报告涉及的 CGI 文件及其 IDA 分析数据库。

## 使用说明

PoC 仅用于自有设备或明确授权的安全研究。脚本中的 `ROOTFS` 是原作者的 WSL 本地路径，复现前需按实际解包目录修改，并自行准备 pwntools 与 qemu-user 环境。请勿对未授权设备使用。
