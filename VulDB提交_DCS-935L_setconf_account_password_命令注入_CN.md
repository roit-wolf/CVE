# VulDB 提交材料 — D-Link DCS-935L setconf.cgi 命令注入（account / password）

> 逐字段提交文本。**A** 为表单字段；**B** 为描述正文（粘进 Description 框）；**C** 为引用。
> 下文所有地址均已对照实测固件 `setconf.cgi`（DCS-935L 1.10.01）的反汇编核验。

---

## A. 表单字段

| 字段 | 填写值 |
|---|---|
| Vendor | D-Link |
| Product | DCS-935L |
| Version | 1.10.01 |
| Firmware / Build | 固件 1.10.01 (A1)，build r4156 |
| 固件 SHA-256 | `eb1abd5af3f8b31db85b2f742a5e17bf62544625e2a60854fd8c6bc0a5d2fbc1` |
| 设备类型 | IP 摄像机 / 网络摄像机 |
| Vulnerability | **os command injection**（操作系统命令注入） |
| CWE | **CWE-78**（主），CWE-77（次） |
| 受影响组件 | Web 服务（`web/httpd`）→ CGI |
| 受影响文件 | `web/cgi-bin/localrecording/setconf.cgi` |
| 受影响函数 | `loginRouter`（0x401088） |
| 危险汇聚点 | `snprintf` 调用 @ 0x40117c（格式串 @ 0x403844）→ `popen` 调用 @ 0x401194 |
| 受影响参数 | `account`、`password`（HTTP POST，`application/x-www-form-urlencoded`） |
| 攻击向量 | 网络（HTTP POST） |
| 认证要求 | 需要（由前端 `httpd` 实施管理员认证） |
| 所需权限 | 低（已认证管理员） |
| 影响 | 远程代码执行——以 CGI 进程权限执行任意命令 |
| CVSS v3.1（估算） | 8.8 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| 利用代码 | 概念验证（qemu-user 仿真下复现） |
| 产品状态 | 已停产（EOL/EOS）——最后支持日 2020-03-31（D-Link SAP10461）；预期无修复 |
| 关联 CVE | CVE-2026-13545——同一 CGI 二进制，**不同参数、不同汇聚点** |
| 发现日期 | 2026-10-20 |

> **分类说明**：本漏洞**不属于**内存破坏类（CWE-119 族）。`snprintf` 目标为 256 字节栈缓冲、
> 写入上限 255 字节，危害来自 shell 命令替换而非越界访问。（同一 CGI 中 `account`/`password`
> 另存在 `strcpy` @ 0x402B98 / 0x402C04 的栈溢出，那属于**另一类**漏洞，需单独提报。）

---

## B. 描述正文

### 摘要

D-Link DCS-935L IP 摄像机（固件 1.10.01）的 CGI 程序
`web/cgi-bin/localrecording/setconf.cgi` 存在操作系统命令注入漏洞。HTTP POST 参数
`account` 与 `password` 在**没有任何值校验**的情况下被存放，随后拼接进 shell 命令字符串，
并经 `popen()` 交由 `/bin/sh -c` 执行。由于 shell **在双引号内仍会做命令替换**，参数中的
`$(...)` 或反引号会被求值，已认证攻击者可以 CGI 进程权限执行任意命令。

### 受影响组件

- 路径：`web/cgi-bin/localrecording/setconf.cgi`——ELF 32 位大端、MIPS-I、动态链接
  （uClibc）、已 strip
- 函数：`loginRouter` @ `0x401088`
- 汇聚点：`snprintf` 调用 @ `0x40117c`（格式串 @ `0x403844`），结果传给
  `popen` 调用 @ `0x401194`
- 调用者：`0x401c78`（`jal 0x401088`），位于 `fcn.00402608` 内
- 入口：经 `web/httpd` 在 `/localrecording/` 前缀下可达

### 根因

```c
/* loginRouter，依据 0x401130 - 0x401194 的 MIPS 反汇编还原 */
snprintf(buf, 0xff,                       /* a1 = 255 @ 0x401130；buf = sp+0x28 @ 0x401168 */
  "/bin/curl https://%s:%d/localrecording/form_login -k --connect-timeout 10 "
  "--data-urlencode \"login_n=%s\" --data-urlencode \"login_pass=%s\" 2>/dev/null",
  host,                                   /* a2 */
  port,                                   /* a3 */
  account,                                /* 栈上 sp+0x10 */
  password);                              /* sp+0x14 */
                                          /* 格式串 @ 0x403844 */
popen(buf, "r");                          /* @ 0x401194 */
```

拼接后的字符串交给 `popen()`，从而交给 `/bin/sh -c`。shell 在**双引号参数内部**依然执行
命令替换（`$(...)`、反引号），因此用 `--data-urlencode "login_n=%s"` 包裹参数**并不能**消除
注入——只有转义/引号隔离才能。

请求体解析函数（`fcn.00402098`）用 `strncmp` 将每个 POST 键与固定名称表比对
（名称表 `0x403d24`–`0x403d68`：`enable`、`policy`、`day`、`period`、`UID`、`overwrite`、
`account`、`password`、`no`、`mac`）。命中 `account`（`0x402a98`）或 `password`
（`0x402acc`）时，**仅把值指针存入栈槽**（分别为 `0x47c($sp)` 与 `0x480($sp)`），
**对取值不做任何字符或长度校验**。仅 `overwrite`、`no` 等数字字段会调用 `atoi`。

### 触发条件

`loginRouter` 仅在全部入参非空/非零时才会进入（`0x4010ec`–`0x40111c` 处的守卫判断）。
因此 POST 体必须同时携带 `account`、`password`、`UID` 与 `overwrite`，其中 `overwrite`
取 `{0,1}`，且 `no` 为非零整数，以便走 curl 分支而非 `localrec` 分支。

### 概念验证

```
POST /cgi-bin/localrecording/setconf.cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded

account=$(id>/tmp/id_out)&password=B&UID=1&overwrite=1&no=1
```

已在解包固件的 qemu-user 仿真环境中复现：`/bin/sh -c` 收到含 `login_n=$(id>...)` 的拼接
命令并执行了命令替换，注入的命令随即运行。

### 与 CVE-2026-13545 的区别

同一个 CGI 二进制，不同注入链：

| | CVE-2026-13545 | 本报告 |
|---|---|---|
| 参数 | `UID` | `account`、`password` |
| 执行的命令 | `/mydlink/localrec` | `/bin/curl` |
| 拼装函数 | `fcn.00400e40` | `loginRouter`（0x401088） |
| 格式化调用 | `sprintf` @ 0x400edc，格式串 @ 0x403730 | `snprintf` @ 0x40117c，格式串 @ 0x403844 |
| `popen` 调用 | 0x400f14 | 0x401194 |
| 输入存放 | `dest_3` @ sp+0x360（`strcpy` @ 0x402C48） | `account` → sp+0x47c（`strcpy` @ 0x402B98）；`password` → sp+0x480（`strcpy` @ 0x402C04） |

参数不同、存放位置不同、调用点不同、命令模板不同：消除其中一条链并不能消除另一条。

### 局限说明

- 结论基于静态 MIPS 分析与 qemu-user 仿真，未在物理硬件上复现。
- 本工作**未验证** CGI 前端 `httpd` 的认证实施；CGI 二进制本身不含认证逻辑。

### 产品状态

D-Link 已宣布 DCS-935L 生命周期终止 / 服务终止（最后支持日 2020-03-31，见 SAP10461）。
预期不会发布固件修复。

### 修复建议

不要用请求数据拼接 shell 命令，改用 `execve`/`execv` 传参数数组。对 `account`、`password`、
`UID` 实施严格的字母数字白名单。对 `localrecording` 端点强制认证与授权。

---

## C. 引用

- CVE-2026-13545（同一二进制，`UID` → `localrec` 链）：https://www.cve.org/CVERecord?id=CVE-2026-13545
- D-Link SAP10461（EOL/EOS 公告，含第三方报告清单）：https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10461
- D-Link legacy 产品页：https://legacy.us.dlink.com/pages/product.aspx?id=81ca12c07ec242af93d8e0290708b5dd
