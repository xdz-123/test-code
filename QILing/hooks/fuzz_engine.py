#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
from qiling import Qiling
from qiling.const import QL_VERBOSE
from hooks.crash_monitor import CrashMonitor

class FuzzEngine:
    """轻量级纯 Python 模糊测试引擎，使用随机变异和崩溃监控"""

    def __init__(self, binary, rootfs, output_dir, seeds=None, max_iter=500, payload_size=500):
        """
        初始化模糊测试引擎

        Args:
            binary: 目标二进制文件的宿主机绝对路径
            rootfs: Qiling 仿真根目录
            output_dir: 崩溃样本输出目录
            seeds: 初始种子列表 (bytes 列表)
            max_iter: 最大测试次数
            payload_size: 变异输入的大致长度上限
        """
        self.binary = binary
        self.rootfs = rootfs
        self.output_dir = output_dir
        self.max_iter = max_iter
        self.payload_size = payload_size
        self.seeds = seeds or [b"test\n", b"hello\n", b"1234\n"]
        self.crash_count = 0

        # 确保虚拟临时目录存在（修复符号链接问题）
        self.tmp_in_rootfs = os.path.join(rootfs, 'tmp')
        if os.path.islink(self.tmp_in_rootfs) or not os.path.isdir(self.tmp_in_rootfs):
            if os.path.exists(self.tmp_in_rootfs):
                os.remove(self.tmp_in_rootfs)
            os.makedirs(self.tmp_in_rootfs, exist_ok=True)

        # 创建输出目录
        os.makedirs(self.output_dir, exist_ok=True)

    def _mutate(self, data: bytes) -> bytes:
        """对数据进行随机变异"""
        data = bytearray(data)
        # 随机插入
        if random.random() < 0.1 and len(data) < self.payload_size * 2:
            data.insert(random.randint(0, len(data)), random.randrange(0, 256))
        # 随机删除
        if random.random() < 0.1 and len(data) > 1:
            del data[random.randint(0, len(data)-1)]
        # 随机翻转位
        for _ in range(random.randint(1, 3)):
            if len(data) > 0:
                data[random.randint(0, len(data)-1)] = random.randrange(0, 256)
        return bytes(data)

    def _save_crash(self, iteration: int, input_bytes: bytes):
        """保存崩溃样本"""
        self.crash_count += 1
        path = os.path.join(self.output_dir, f"crash_{self.crash_count:04d}_iter{iteration}.bin")
        with open(path, 'wb') as f:
            f.write(input_bytes)
        return path

    def run(self) -> int:
        """执行模糊测试，返回发现的总崩溃次数"""
        seeds_pool = list(self.seeds)
        for i in range(self.max_iter):
            parent = random.choice(seeds_pool)
            inp = self._mutate(parent)

            # 将输入写入虚拟文件系统
            fname = f'fuzz_{i}.bin'
            host_path = os.path.join(self.tmp_in_rootfs, fname)
            with open(host_path, 'wb') as f:
                f.write(inp)

            result = {'crash': None}
            try:
                ql = Qiling([self.binary, "cat", f"/tmp/{fname}"], self.rootfs,
                            stdout=None, stderr=None, verbose=QL_VERBOSE.OFF)
                CrashMonitor(ql, result)
                ql.run()
            except Exception:
                pass
            finally:
                try:
                    os.remove(host_path)
                except:
                    pass

            if result.get('crash'):
                path = self._save_crash(i, inp)
                print(f"[!] Real crash #{self.crash_count} at iteration {i}: {result['crash']}")
                # 可选：保留新路径样本作为种子（覆盖率引导简化版）
                # 这里仅简单加入种子池
                seeds_pool.append(inp)

            if (i+1) % 50 == 0:
                print(f"[*] Iteration {i+1}, crashes so far: {self.crash_count}")

        return self.crash_count


# 简单使用示例
if __name__ == "__main__":
    # 针对 busybox cat 进行模糊测试
    engine = FuzzEngine(
        binary="/root/qiling/rootfs/bin/busybox",
        rootfs="/root/qiling/rootfs",
        output_dir="./fuzz_results",
        max_iter=200
    )
    crashes = engine.run()
    print(f"Fuzzing finished, total crashes: {crashes}")
