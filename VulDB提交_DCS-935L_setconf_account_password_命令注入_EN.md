# VulDB Submission — D-Link DCS-935L setconf.cgi OS Command Injection (account / password)

> Field-by-field submission text for VulDB. Section **A** = form fields; section **B** = Description body (paste into the description box); section **C** = references.
> Every address below was verified against the disassembly of the shipped binary (`setconf.cgi`, DCS-935L firmware 1.10.01).

---

## A. Form fields

| Field | Value |
|---|---|
| Vendor | D-Link |
| Product | DCS-935L |
| Version | 1.10.01 |
| Firmware / Build | Firmware 1.10.01 (A1), build r4156 |
| Firmware SHA-256 | `eb1abd5af3f8b31db85b2f742a5e17bf62544625e2a60854fd8c6bc0a5d2fbc1` |
| Device type | IP Camera / Network Camera |
| Vulnerability | **os command injection** |
| CWE | **CWE-78** (primary), CWE-77 (secondary) |
| Affected component | Web interface (`web/httpd`) → CGI |
| Affected file | `web/cgi-bin/localrecording/setconf.cgi` |
| Affected function | `loginRouter` (0x401088) |
| Vulnerable sink | `snprintf` call @ 0x40117c (format string @ 0x403844) → `popen` call @ 0x401194 |
| Vulnerable parameters | `account`, `password` (HTTP POST, `application/x-www-form-urlencoded`) |
| Attack vector | Network (HTTP POST) |
| Authentication | Required (admin authentication enforced by the front-end `httpd`) |
| Privileges required | Low (authenticated administrator) |
| Impact | Remote Code Execution — arbitrary commands with the privileges of the CGI process |
| CVSS v3.1 (estimate) | 8.8 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| Exploit availability | Proof of Concept (reproduced under qemu-user emulation) |
| Product status | EOL / EOS — last day of support 2020-03-31 (D-Link SAP10461); no fix expected |
| Related CVE | CVE-2026-13545 — same CGI binary, **different parameter and different sink** |
| Discovery date | 2026-10-20 |

> **Classification note:** this is *not* a memory-corruption issue (CWE-119 family). The
> `snprintf` destination is a 256-byte stack buffer written with a 255-byte limit, and the
> impact comes from shell command substitution, not from out-of-bounds access. (The same
> CGI does hold `account`/`password` with `strcpy` at 0x402B98 / 0x402C04; that is a
> separate buffer-overflow class and would require a separate record.)

---

## B. Description

### Summary

The D-Link DCS-935L IP camera (firmware 1.10.01) contains an OS command injection in the
CGI program `web/cgi-bin/localrecording/setconf.cgi`. The HTTP POST parameters `account`
and `password` are stored without any value validation and are then interpolated into a
shell command string that is executed through `popen()`, i.e. `/bin/sh -c`. Shell
metacharacters such as `$(...)` or backticks in either parameter are evaluated by the
shell, allowing an authenticated attacker to execute arbitrary commands with the
privileges of the CGI process.

### Affected component

- Path: `web/cgi-bin/localrecording/setconf.cgi` — ELF 32-bit MSB, MIPS-I, dynamically
  linked (uClibc), stripped
- Function: `loginRouter` @ `0x401088`
- Sink: `snprintf` call @ `0x40117c` (format string @ `0x403844`), result passed to
  `popen` call @ `0x401194`
- Caller: `0x401c78` (`jal 0x401088`) inside `fcn.00402608`
- Endpoint: reachable through `web/httpd` under the `/localrecording/` prefix

### Root cause

```c
/* loginRouter, reconstructed from MIPS at 0x401130 - 0x401194 */
snprintf(buf, 0xff,                       /* a1 = 255 @ 0x401130, buf = sp+0x28 @ 0x401168 */
  "/bin/curl https://%s:%d/localrecording/form_login -k --connect-timeout 10 "
  "--data-urlencode \"login_n=%s\" --data-urlencode \"login_pass=%s\" 2>/dev/null",
  host,                                   /* a2 */
  port,                                   /* a3 */
  account,                                /* a3 on stack: sp+0x10 */
  password);                              /* sp+0x14 */
                                          /* format string @ 0x403844 */
popen(buf, "r");                          /* @ 0x401194 */
```

The assembled string is handed to `popen()`, therefore to `/bin/sh -c`. Command
substitution (`$(...)`, backticks) is still performed by the shell **inside double-quoted
arguments**, so wrapping the values in `--data-urlencode "login_n=%s"` does not neutralise
the injection; only quoting would.

The request-body parser (`fcn.00402098`) compares each POST key against a fixed name list
with `strncmp` (name table at `0x403d24`–`0x403d68`: `enable`, `policy`, `day`, `period`,
`UID`, `overwrite`, `account`, `password`, `no`, `mac`). On a match for `account`
(`0x402a98`) or `password` (`0x402acc`) it only stores the value pointer into a stack slot
(`0x47c($sp)` and `0x480($sp)` respectively). **No character or length validation is
applied to either value.** Only numeric fields such as `overwrite`/`no` call `atoi`.

### Trigger

`loginRouter` is entered only when every one of its arguments is non-NULL / non-zero
(guards at `0x4010ec`–`0x40111c`). The POST body must therefore carry `account`,
`password`, `UID` and `overwrite`, with `overwrite` in `{0,1}`, and `no` set to a
non-zero integer so that the curl branch is taken instead of the `localrec` branch.

### Proof of Concept

```
POST /cgi-bin/localrecording/setconf.cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded

account=$(id>/tmp/id_out)&password=B&UID=1&overwrite=1&no=1
```

Reproduced under qemu-user emulation of the extracted firmware: `/bin/sh -c` receives the
assembled command containing `login_n=$(id>...)` and performs the command substitution, so
the injected command executes.

### Distinction from CVE-2026-13545

Same CGI binary, different injection chain:

| | CVE-2026-13545 | This report |
|---|---|---|
| Parameter | `UID` | `account`, `password` |
| Command executed | `/mydlink/localrec` | `/bin/curl` |
| Emitting function | `fcn.00400e40` | `loginRouter` (0x401088) |
| Format call | `sprintf` @ 0x400edc, format @ 0x403730 | `snprintf` @ 0x40117c, format @ 0x403844 |
| `popen` call | 0x400f14 | 0x401194 |
| Input storage | `dest_3` @ sp+0x360 (`strcpy` @ 0x402C48) | `account` → sp+0x47c (`strcpy` @ 0x402B98); `password` → sp+0x480 (`strcpy` @ 0x402C04) |

Different parameters, different storage locations, different call sites and different
command templates: neutralising one chain does not remove the other.

### Limitations

- Established by static MIPS analysis plus qemu-user emulation; not reproduced on physical
  hardware.
- Authentication enforcement in front of this CGI (performed by `httpd`) was not verified
  in this work; the CGI binary itself contains no authentication logic.

### Product status

D-Link has declared the DCS-935L end-of-life / end-of-service (last day of support
2020-03-31, SAP10461). No firmware fix is expected.

### Remediation

Do not build shell command strings from request data; use `execve`/`execv` with an
argument vector. Enforce a strict alphanumeric whitelist on `account`, `password` and
`UID`. Require authentication and authorisation on the `localrecording` endpoint.

---

## C. References

- CVE-2026-13545 (same binary, `UID` → `localrec` chain): https://www.cve.org/CVERecord?id=CVE-2026-13545
- D-Link SAP10461 (EOL/EOS notice listing third-party reports): https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10461
- D-Link legacy product page: https://legacy.us.dlink.com/pages/product.aspx?id=81ca12c07ec242af93d8e0290708b5dd
