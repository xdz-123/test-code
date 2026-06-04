#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from qilingfw import FirmwareAnalyzer

def test_scan():
    print("=" * 50)
    print("测试1：批量扫描稳定二进制")
    print("=" * 50)
    analyzer = FirmwareAnalyzer(rootfs="/root/qiling/rootfs_tenda/rootfs_ubifs")
    result = analyzer.scan(
        targets=["/bin/busybox", "/bin/ls", "/bin/echo", "/bin/sh", "/bin/cat"],
        hooks=["crash"],
        timeout=5,
        output_dir="./results"
    )
    s = result.summary()
    print(f"总文件数: {s['total']}, 成功: {s['success']}, 超时: {s['timeout']}, 错误: {s['error']}, 崩溃: {s['crash']}")
    for r in result.results:
        print(f"  {'✓' if r['status']=='success' else '✗'} {r['binary']} ({r['status']})")

def test_fuzz():
    print("\n" + "=" * 50)
    print("测试2：模糊测试 busybox (快速)")
    print("=" * 50)
    analyzer = FirmwareAnalyzer(rootfs="/root/qiling/rootfs_tenda/rootfs_ubifs")
    crashes = analyzer.fuzz(binary="/root/qiling/rootfs_tenda/rootfs_ubifs/bin/busybox",
                            args=["cat", "@@"], seeds=[b"test\n"], max_iter=50,
                            output_dir="./fuzz_results")
    print(f"模糊测试完成，发现崩溃: {crashes}")

def test_verify():
    print("\n" + "=" * 50)
    print("测试3：定向漏洞验证")
    print("=" * 50)
    json_file = "vuln_targets.json"
    if not os.path.exists(json_file):
        print("vuln_targets.json 未找到，跳过。")
        return
    analyzer = FirmwareAnalyzer(rootfs="/root/qiling/rootfs_tenda/rootfs_ubifs")
    targets = analyzer.load_vuln_targets(json_file)
    if targets:
        t = targets[0]
        print(f"验证 {t['func_name']} (0x{t['func_addr']:x}) ...")
        overflow = analyzer.verify_overflow(t['func_name'], t['func_addr'],
                                            t.get('websGetVar_calls', []),
                                            t.get('external_calls', []))
        print(f"结果: {'存在溢出漏洞' if overflow else '未触发溢出'}")

if __name__ == "__main__":
    test_scan()
    test_fuzz()
    test_verify()
    print("\n所有测试完成。")
