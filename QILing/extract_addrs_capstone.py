#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
from capstone import *
import struct

BINARY = "/root/qiling/rootfs_tenda/rootfs_ubifs/bin/httpd"
TARGETS = [
    "formSetFirewallCfg",
    "formAddMacfilterRule",
    "R7WebsSecurityHandler",
    "SetMacFilterCfg",
]

with open(BINARY, 'rb') as f:
    elf = ELFFile(f)
    text = elf.get_section_by_name('.text')
    if not text:
        print("[-] .text section not found")
        exit(1)
    text_data = text.data()
    text_vaddr = text['sh_addr']

    # 第一步：在所有只读段中查找目标字符串的虚拟地址
    str_vaddrs = {}
    for name in TARGETS:
        raw = name.encode('utf-8')
        for section in elf.iter_sections():
            if section.name in ('.rodata', '.data', '.rel.ro', '.ARM.exidx', '.strtab', '.dynstr'):
                try:
                    data = section.data()
                except Exception:
                    continue
                pos = data.find(raw)
                if pos != -1:
                    str_vaddr = section['sh_addr'] + pos
                    str_vaddrs[name] = str_vaddr
                    break
        if name not in str_vaddrs:
            print(f"[-] String '{name}' not found")

    if not str_vaddrs:
        print("[-] No target strings found, exiting.")
        exit(1)

    # 第二步：使用 capstone 反汇编 .text，查找 PC-relative LDR 指令引用的地址是否匹配
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True

    for name, target_addr in str_vaddrs.items():
        for insn in md.disasm(text_data, text_vaddr):
            if insn.mnemonic == 'ldr' and len(insn.operands) >= 2:
                src = insn.operands[1]
                if src.type == CS_OP_MEM and src.mem.base == ARM_REG_PC and src.mem.disp is not None:
                    actual_addr = insn.address + 8 + src.mem.disp
                    if actual_addr == target_addr:
                        print(f"[+] '{name}' referenced at instruction 0x{insn.address:x} (PC rel)")
                        break

print("Done.")
