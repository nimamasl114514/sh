# -*- coding: utf-8 -*-
"""
elf_sim_demo.py — ElfSim v2 使用示例
演示：加载 ELF → 符号寻址 → libc 桩 → 调用解密函数 → hook 捕获 → dump
"""
import sys
sys.path.insert(0, r'.')  # 同目录
from elf_sim import ElfSim


def demo(elf_path):
    # 1) 加载
    sim = ElfSim(elf_path)
    print(f'entry = {hex(sim.entry)}')

    # 2) 导入/符号
    if 'memcpy' in sim.imports:
        print(f'memcpy @ {hex(sim.imports["memcpy"])}')

    # 3) libc 桩（strlen/strcmp/memcpy/memset/... Python 实现，call 到 PLT stub 时自动 intercept）
    sim.install_libc_stubs()

    # 4) 内存写入追踪
    writes = sim.hook_mem_write()

    # 5) 调用函数（地址或符号名）
    sim.call(0x1F2B70, [], until=0, max_steps=10**6)

    # 6) dump 解密后数据
    raw = sim.dump(0x5F0000, 0x1000)
    print('writes:', len(writes))
    print('first bytes:', raw[:32])
    return raw


if __name__ == '__main__':
    demo(sys.argv[1])
