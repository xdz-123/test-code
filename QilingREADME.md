Qiling Firmware Security Framework (QFSF)

一个基于 Qiling 框架的自动化嵌入式固件安全分析工具集，专为在容器化环境中进行用户态二进制分析、漏洞验证和模糊测试而设计。

概述

本框架提供了一套完整的脚本和钩子，用于对从路由器/物联网设备提取的固件文件系统进行自动化分析。核心能力包括：

批量二进制扫描：对固件根文件系统中的所有 ELF 可执行文件执行指定命令，监控崩溃、超时和错误。

系统调用追踪：记录目标程序的关键系统调用，用于行为分析和崩溃根因定位。

内存异常监控：捕获非法内存访问、非法指令等异常，辅助漏洞发现。

轻量级模糊测试：纯 Python 变异引擎，无需外部依赖（如 AFL++），即可对二进制进行输入模糊测试并捕获崩溃。

定向漏洞验证：结合 IDA Pro 逆向分析，通过精确控制目标函数的参数和依赖，实现栈缓冲区溢出等漏洞的自动化验证。

可扩展钩子系统：所有监控功能以插件形式实现，易于定制和扩展。

该框架最初在 Docker 容器环境（无 loop 设备、非特权模式）中构建，非常适用于云服务器或受限环境。它证明了用户态仿真在无需完整系统模拟的情况下，依然能有效检测固件中的内存损坏漏洞。

环境要求

Python：3.8 - 3.10

Qiling 框架：1.4.8 或更高版本（推荐 pip install qiling）

操作系统：Linux (推荐 Ubuntu 20.04/22.04)，已在容器内测试

可选工具：

binwalk：用于提取固件文件系统

capstone：用于静态地址提取（pip install capstone）

pyelftools：用于 ELF 解析

IDA Pro（本机）：用于逆向分析，生成漏洞目标描述文件


目录结构

/root/

├── qiling/            # Qiling 仿真根文件系统

│   ├── rootfs/                   # D-Link DIR-868L 根文件系统

│   └── rootfs_tenda/             # Tenda AX-3 根文件系统

│       └── rootfs_ubifs/         # 实际根文件系统（binwalk 提取的）

├── qiling-framework/             # 本框架主目录

│   ├── config.yaml               # 扫描配置

│   ├── scanner.py                # 批量扫描引擎

│   ├── hooks/                    # 插件目录

│   │   ├── crash_monitor.py      # 崩溃监控插件

│   │   ├── syscall_tracer.py     # 系统调用追踪插件

│   │   ├── memory_guard.py       # 内存访问异常插件（可选）

│   │   └── fuzz_engine.py        # 模糊测试引擎（模块）

│   ├── results/                  # 扫描结果输出目录（JSON）

│   ├── fuzz_targets/             # 模糊测试脚本和种子

│   ├── extract_addrs_capstone.py # 利用 capstone 从二进制提取函数地址

│   ├── extract_addrs_elf.py      # 利用 pyelftools 提取地址

│   ├── batch_verify_vulns.py     # 批量定向漏洞验证脚本

│   └── verify_formSetFirewallCfg.py # 单函数验证示例

├── fuzzing/                      # 模糊测试工作目录

│   ├── smart_fuzz.py             # 精准模糊测试器

│   ├── manual_fuzz.py            # 简单模糊测试器

│   ├── seeds/                    # 种子文件

│   └── crashes/                  # 崩溃输出

└── firmware_lab/                 # 原始固件存放目录



安装与配置

1.安装 Qiling 框架

如果网络受限，可以先下载 Qiling 压缩包，然后离线安装：

unzip qiling-master.zip

cd qiling-master

pip3 install --user .

正常情况下在线安装：

pip3 install --user qiling

2.获取固件根文件系统

使用 binwalk 从固件镜像中提取：

cd /root/firmware_lab/firmwares

binwalk -Me --run-as=root firmware.bin

提取完成后，将根文件系统（通常为 squashfs-root 或类似名称）移动到 /root/qiling/rootfs_XXX 目录下，并在框架配置中指定路径。

例如，对于 Tenda AX-3：

mv _firmware.bin.extracted/ubifs-root/xxxx/rootfs_ubifs /root/qiling/rootfs_tenda/rootfs_ubifs

3.安装框架所需 Python 库

 pip3 install --user pyyaml  # 解析配置文件

可选（用于地址提取）：

 pip3 install --user capstone pyelftools

4.配置扫描目标

编辑 config.yaml，示例：

global:

  rootfs: "/root/qiling/rootfs_tenda/rootfs_ubifs"
	
  timeout: 10
	
  verbose: false
	

targets:

  - pattern: "/bin/*"
    
  - args: ["--help"]
    
  - binary: "/sbin/httpd"
  - 
    args: []


hooks:
  enabled:
    - "crash_monitor"
output:

  format: "json"
	
  path: "./results"
使用指南

批量扫描二进制文件

cd /root/qiling-framework

python3 scanner.py -c config.yaml

扫描结果保存在 results/ 目录下的 summary_<timestamp>.json 文件中。可以使用以下命令快速查看统计：

cat results/summary_*.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['total'], d['success'], d['timeout'], d['error'], d['crash'])"

模糊测试

内置两种模糊测试方式：

精准模糊测试（适用于简单命令行程序）

cd /root/fuzzing

python3 smart_fuzz.py

输出崩溃将保存在 crashes/ 目录，并被 CrashMonitor 严格鉴定（只记录 UcError）。

集成 AFL++（实验性）

由于容器环境限制，AFL++ 集成较复杂，通常不推荐。框架已实现了不依赖 AFL++ 的覆盖率引导模糊引擎（fuzz_engine.py），可在 scanner.py 中调用。

定向漏洞验证

这是本框架最强大的功能，用于验证从逆向分析中发现的疑似漏洞。

步骤 1：用 IDA Pro 提取漏洞函数信息

在 IDA 中运行 extract_vulns.py 脚本（保存在 Windows 本机），生成 vuln_targets.json。该脚本会遍历目标函数列表，收集：

函数入口地址

websGetVar 调用点（指令地址及下一条指令地址）

所有外部 BL 调用目标函数及地址

步骤 2：上传至服务器并运行验证

scp -P 42799 vuln_targets.json root@server_ip:/root/qiling-framework/

cd /root/qiling-framework

python3 batch_verify_vulns.py

该脚本会：

·为每个目标函数设置模拟的 websGetVar，使其返回超长字符串（500 字节）

·挂钩所有非 libc 的外部函数，直接返回成功

·调用漏洞函数并观察是否触发内存违规

·检查寄存器中是否出现 payload 特征（0x42424242）

运行示例输出：

[*] Testing formSetFirewallCfg (0x50048) ... [!] CRASH at 0x1272f74

  -> Payload detected in registers, overflow confirmed!
	
  -> formSetFirewallCfg: VULNERABLE
	
系统调用追踪

在 config.yaml 中启用 syscall_tracer 插件：

hooks:

  enabled:
	
- "crash_monitor"
  
- "syscall_tracer"
  
然后运行扫描，结果 JSON 中会包含 syscalls 字段，记录每个系统调用的名称和参数

插件开发

所有监控功能通过钩子（hook）实现，位于 hooks/ 目录。每个插件都是一个类，在 scanner.py 的 _init_hooks 方法中被实例化。

示例：开发一个记录所有 execve 调用的插件：

from qiling import Qiling

from qiling.const import QL_INTERCEPT

class ExecveMonitor:

    def __init__(self, ql, result_dict):
        self.ql = ql
        self.result = result_dict
        def execve_hook(ql, *args):
            print(f"[!] execve called: {args}")
            return None  # 不修改执行
        ql.os.set_syscall('execve', execve_hook, QL_INTERCEPT.ENTER)
				
然后在 config.yaml 的 hooks.enabled 列表中添加插件类名（需在 scanner.py 中注册）。

已验证的漏洞案例

Tenda AX-3 httpd 缓冲区溢出 (formSetFirewallCfg)

·漏洞类型：栈缓冲区溢出 (strcpy)

·触发参数：firewallEn 长度超过 7 字节

·Qiling 验证结果：PAYLOAD 注入后，寄存器 r2, r3 被覆盖为 0x42424242，程序跳转到非法地址 0x1272f74，触发内存违规。

·验证脚本：verify_formSetFirewallCfg.py 和 batch_verify_vulns.py

其他 21 个函数同样触发了内存违规（环境依赖型），表明框架可有效识别异常行为，但需要进一步的环境模拟才能确证为可被利用的溢出。

常见问题与技巧

Qiling 版本兼容性

·本框架基于 Qiling 1.4.8 开发。新版 Qiling (2.x) API 变动较大，如需升级请相应调整脚本。

·系统调用钩子必须返回元组 (retval, ()) 才能绕过执行，否则可能引发参数错误。

根文件系统路径问题

·Qiling 将 rootfs 目录作为虚拟根 /。确保所有文件（包括动态库）都在该目录下正确放置。

·如果程序报告 can't open /tmp/xxx: No such file or directory，请检查虚拟 tmp 目录是否存在（可能是符号链接），手动创建即可：

rm /path/to/rootfs/tmp

mkdir -p /path/to/rootfs/tmp

抑制输出

由于 Qiling 1.4.8 不支持 stdout 参数，可通过在 ql.run() 前重定向 sys.stdout 来抑制仿真输出：

import sys

old_stdout = sys.stdout

sys.stdout = open(os.devnull, 'w')

try:
    ql.run()
finally:

sys.stdout = old_stdout

绕过守护进程初始化循环

许多嵌入式 Web 服务器在启动时会执行无限循环的 close() 调用（如 D-Link/Tenda httpd）。框架内提供了 close、sysconf、getrlimit 等钩子模板，可直接复用。

def close_hook(ql, fd, retval):
    if retval == -9 and fd > 1024:
        return 0
    return retval
ql.os.set_syscall('close', close_hook, QL_INTERCEPT.EXIT)。
