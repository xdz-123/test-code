import idc
import idaapi
import json

# 你的漏洞函数名列表
FUNC_NAMES = [
    "formSetFirewallCfg",
    "formAddMacfilterRule",
    "R7WebsSecurityHandler",
    "formWifiBasicSet_2G",
    "formWifiBasicSet_5G",
    "saveParentControlInfo",
    "set_device_name",
    "fromAdvSetMacMtuWan",
    "fromSetIpMacBind",
    "fromSetRouteStatic",
    "fromSetSysTime",
    "fromSetWifiGusetBasic",
    "wlSetExternParameter",
    "setSchedWifi",
    "form_fast_setting_wifi_set",
    "formSetRebootTimer",
    "formSetVirtualSer",
    "formSetQosBand",
    "formSetPPTPServer",
    "GetParentControlInfo",
    "compare_parentcontrol_time",
]

# libc / 基础函数黑名单：这些函数不会被挂钩，必须真实执行
LIBC_BLACKLIST = {
    "memset", "strlen", "strcpy", "strncpy", "sprintf", "snprintf",
    "memcpy", "memmove", "malloc", "free", "realloc", "calloc",
    "sscanf", "__isoc99_sscanf", "printf", "puts", "atoi", "strcmp",
    "strncmp", "strchr", "strrchr", "strstr", "memcmp",
    "open", "close", "read", "write", "lseek", "stat", "fstat",
    "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "ioctl", "fcntl", "select", "poll",
}

output = []

for fname in FUNC_NAMES:
    func_ea = idc.get_name_ea_simple(fname)
    if func_ea == idc.BADADDR:
        print(f"WARNING: {fname} not found")
        continue

    # 收集 websGetVar 调用点 (BL 指令地址) 及其下一条指令
    websgetvar_calls = []   # [(call_addr, next_addr)]
    # 收集所有 BL 调用的目标信息
    external_calls = []

    # 遍历函数下所有指令
    func = idaapi.get_func(func_ea)
    if not func:
        print(f"WARNING: {fname} has no function")
        continue

    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            mnem = idc.print_insn_mnem(head)
            if mnem.upper() in ("BL", "BLX"):
                target = idc.get_operand_value(head, 0)
                target_name = idc.get_name(target) or ""
                # 记录所有调用
                external_calls.append({
                    "call_addr": head,
                    "target_addr": target,
                    "target_name": target_name
                })
                # 检查是否是 websGetVar
                if target_name == "websGetVar" or "websGetVar" in target_name:
                    next_addr = head + 4   # ARM 模式
                    websgetvar_calls.append((head, next_addr))

    print(f"{fname}: {func_ea:#x}, websGetVar calls: {websgetvar_calls}")
    output.append({
        "func_name": fname,
        "func_addr": func_ea,
        "websGetVar_calls": websgetvar_calls,
        "external_calls": external_calls
    })

# 保存为 JSON
with open("vuln_targets.json", "w") as f:
    json.dump(output, f, indent=2)

print("Saved to vuln_targets.json")
