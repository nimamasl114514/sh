# -*- coding: utf-8 -*-
"""
elf_sim.py — 自研 ELF 模拟动态执行框架（MiniDBI 思路）
核心：加载 ELF → 映射段 → 直接调用任意函数（绕过 linker）→ hook 控制流 → dump 解密数据
基于 Unicorn 2.1.4
"""
import struct
import sys
from unicorn import *
from unicorn.x86_const import *


class ElfSim:
    """ELF x86_64 模拟执行框架（Android bionic 也可：无 linker 依赖）"""

    def __init__(self, elf_path):
        self.data = open(elf_path, 'rb').read()
        self._parse_elf()
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self._map_all()
        self._setup_stack()
        self.symbols = {}

    # ---------- ELF 解析 ----------
    def _parse_elf(self):
        d = self.data
        assert d[:4] == b'\x7fELF'
        self.entry = struct.unpack_from('<Q', d, 24)[0]  # e_entry
        e_shoff = struct.unpack_from('<Q', d, 40)[0]
        e_shentsize = struct.unpack_from('<H', d, 58)[0]
        e_shnum = struct.unpack_from('<H', d, 60)[0]
        e_shstrndx = struct.unpack_from('<H', d, 62)[0]
        # 节名表
        shstr_off = struct.unpack_from('<Q', d, e_shoff + e_shstrndx*e_shentsize + 24)[0]
        def cstr(o):
            e = d.index(b'\0', o)
            return d[o:e].decode('latin1')
        self.sections = {}
        for i in range(e_shnum):
            off = e_shoff + i*e_shentsize
            raw = struct.unpack_from('<IIQQQQIIQQ', d, off)
            n = raw[0]
            stype, flags, addr, offset, size = raw[1], raw[2], raw[3], raw[4], raw[5]
            self.sections[cstr(shstr_off+n)] = (addr, offset, size, stype)

    # ---------- 内存映射 ----------
    def _map_all(self):
        self.mu.mem_map(0x0, 0x08000000)  # 大映射覆盖
        text = self.sections.get('.text')
        if text:
            addr, off, size, _ = text
            self.mu.mem_write(addr, self.data[off:off+size])
        for name in ('.rodata', '.data', '.eh_frame', '.gcc_except_table',
                     '.eh_frame_hdr', '.plt', '.data.rel.ro', '.got',
                     '.got.plt', '.init_array', '.fini_array', '.preinit_array'):
            if name in self.sections:
                addr, off, size, _ = self.sections[name]
                self.mu.mem_write(addr, self.data[off:off+size])
        if '.bss' in self.sections:
            addr, off, size, _ = self.sections['.bss']
            print(f'[sim] bss addr=0x{addr:X} off=0x{off:X} size={size}')
            try:
                zsize = min(size, 0x20000)
                self.mu.mem_write(addr, b'\x00' * zsize)
                print(f'[sim] bss zeroed {zsize}')
            except UcError as e:
                print(f'[sim] bss skip: {e}')

    def _setup_stack(self):
        self.STACK = 0x70000000
        self.mu.mem_map(self.STACK, 0x200000)
        self.mu.reg_write(UC_X86_REG_RSP, self.STACK + 0x100000)
        self.mu.reg_write(UC_X86_REG_RBP, self.STACK + 0x100000)

    # ---------- 执行 ----------
    def run(self, entry, timeout=10**9):
        """从 entry 执行到自然退出/超时（hook 控制）"""
        self.mu.emu_start(entry, 0, count=0, timeout=timeout)
        return self.pc()

    def call(self, func, args=None, until=None, max_steps=10**7, timeout=10**9):
        """调用 ELF 函数（sysv: rdi,rsi,rdx,rcx,r8,r9）
        args: [a1,a2,...]，直到 until（函数地址）或超步
        """
        args = args or []
        regs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
        for i, v in enumerate(args[:6]):
            self.mu.reg_write(regs[i], v)
        # 返回地址放栈（模拟 ret）
        ret_addr = self.STACK + 0x9000
        self.mu.mem_write(self.mu.reg_read(UC_X86_REG_RSP) - 8,
                          struct.pack('<Q', ret_addr))
        self.mu.reg_write(UC_X86_REG_RSP, self.mu.reg_read(UC_X86_REG_RSP) - 8)
        if until:
            self.mu.emu_start(func, until, count=max_steps, timeout=timeout)
        else:
            self.mu.emu_start(func, 0, count=max_steps, timeout=timeout)
        return self.pc()

    # ---------- 寄存器/内存 ----------
    def reg(self, name):
        regs = {'rax': UC_X86_REG_RAX, 'rbx': UC_X86_REG_RBX, 'rcx': UC_X86_REG_RCX,
                'rdx': UC_X86_REG_RDX, 'rsi': UC_X86_REG_RSI, 'rdi': UC_X86_REG_RDI,
                'rsp': UC_X86_REG_RSP, 'rbp': UC_X86_REG_RBP, 'rip': UC_X86_REG_RIP,
                'r8': UC_X86_REG_R8, 'r9': UC_X86_REG_R9, 'r10': UC_X86_REG_R10,
                'r11': UC_X86_REG_R11, 'r12': UC_X86_REG_R12, 'r13': UC_X86_REG_R13,
                'r14': UC_X86_REG_R14, 'r15': UC_X86_REG_R15}
        return self.mu.reg_read(regs[name])

    def pc(self):
        return self.reg('rip')

    def write_mem(self, addr, data):
        if isinstance(data, str):
            data = data.encode()
        self.mu.mem_write(addr, data)

    def read(self, addr, size):
        r = self.mu.mem_read(addr, size)
        return bytes(r) if isinstance(r, list) else r

    def read_str(self, addr, maxlen=256):
        b = self.read(addr, maxlen)
        i = b.find(b'\x00')
        return (b[:i] if i != -1 else b).decode('utf-8', 'replace')

    def dump(self, addr, size):
        return self.read(addr, size)

    # ---------- Hook ----------
    def hook_code(self, cb):
        """cb(uc, addr, size)"""
        self.mu.hook_add(UC_HOOK_CODE, cb)
