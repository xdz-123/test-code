# qilingfw/hooks/bypass.py
from qiling import Qiling
from qiling.const import QL_INTERCEPT

def enable_bypass_hooks(ql: Qiling):
    """启用一组通用绕过钩子（close 循环、资源限制、网络/进程调用）"""

    # 1. 跳过 close 循环（嵌入式常见初始化行为）
    def close_hook(ql: Qiling, fd: int, retval: int) -> int:
        if retval == -9 and fd > 1024:
            return 0
        return retval
    ql.os.set_syscall('close', close_hook, QL_INTERCEPT.EXIT)

    # 2. 限制 _SC_OPEN_MAX 返回值
    def sysconf_hook(ql: Qiling, name: int):
        if name == 4:  # _SC_OPEN_MAX
            return (1024, ())
        return None
    ql.os.set_syscall('sysconf', sysconf_hook, QL_INTERCEPT.ENTER)

    # 3. 限制 getrlimit(RLIMIT_NOFILE)
    def getrlimit_hook(ql: Qiling, resource: int, rlim_ptr: int):
        if resource == 7:  # RLIMIT_NOFILE
            ql.mem.write(rlim_ptr, (1024).to_bytes(4, 'little'))
            ql.mem.write(rlim_ptr + 4, (4096).to_bytes(4, 'little'))
            return (0, ())
        return None
    ql.os.set_syscall('getrlimit', getrlimit_hook, QL_INTERCEPT.ENTER)

    # 4. 拦截所有 socketcall (ARM 网络总入口) 并返回成功
    def socketcall_hook(ql: Qiling, *args):
        return (0, ())
    ql.os.set_syscall('socketcall', socketcall_hook, QL_INTERCEPT.ENTER)

    # 5. 拦截 clone/fork 并返回假子进程 ID
    def clone_hook(ql: Qiling, *args):
        return (42, ())
    ql.os.set_syscall('clone', clone_hook, QL_INTERCEPT.ENTER)
    ql.os.set_syscall('fork', clone_hook, QL_INTERCEPT.ENTER)