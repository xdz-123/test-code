#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
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
    # 获取代码段
    text = elf.get_section_by_name('.text')
    if not text:
        print("[-] .text section not found")
        exit(1)
    text_data = text.data()
    text_vaddr = text['sh_addr']
    
    # 查找每个目标字符串的引用地址
    for name in TARGETS:
        raw = name.encode('utf-8')
        found = False
        # 在所有可读段中搜索字符串
        for section in elf.iter_sections():
            if section.name in ('.rodata', '.data', '.ARM.exidx', '.strtab', '.shstrtab'):
                data = section.data()
                pos = data.find(raw)
                if pos != -1:
                    str_vaddr = section['sh_addr'] + pos
                    print(f"[+] Found '{name}' string at 0x{str_vaddr:x}")
                    # 在 .text 中查找对该地址的引用
                    for i in range(0, len(text_data) - 4, 4):
                        word = struct.unpack('<I', text_data[i:i+4])[0]
                        if word == str_vaddr:
                            ref_vaddr = text_vaddr + i
                            print(f"    -> referenced at 0x{ref_vaddr:x}")
                            found = True
                            break
                    break
        if not found:
            print(f"[-] '{name}' reference not found")
