# -*- coding: utf-8 -*-
"""
elf_sim.py — 自研 ELF 模拟动态执行框架 v2（MiniDBI 思路）
强化：
  1. 完整节表解析 + .dynsym 符号寻址（from_symbol）
  2. .rela.plt 导入解析（导入函数列表 + PLT/GOT 地址）
  3. libc 桩系统：install_libc_stubs() 自动 hook 导入的常用 libc 函数（Python 实现）
  4. syscall 拦截（UC_HOOK_INSN）：exit/write/read/mmap/brk 等简单模拟
  5. 内存写入/读取追踪 hook（hook_mem_write/hook_mem_read）
  6. 现场快照/恢复（snapshot/restore：寄存器 + 追踪内存）
  7. 调用约定句柄 call() 保持兼容

基于 Unicorn 2.x；适用于 Android/linux x86_64 ELF。
"""
import struct
import sys
import time
from unicorn import *
from unicorn.x86_const import *


class ElfSim:
    """ELF x86_64 模拟执行框架（无 linker 依赖，直接函数级模拟）"""

    def __init__(self, elf_path):
        self.data = open(elf_path, 'rb').read()
        self._parse_elf()
        self.symbols = {}      # name -> VA（dynsym 定义符号）
        self.imports = {}      # name -> PLT stub 地址（导入函数）
        self._libc_handlers = {}  # PLT addr -> python callable
        self._mem_write_log = []  # [(addr, value)]
        self._mem_read_log = []
        self._snap_regs = None
        self._snap_mem = {}    # addr -> byte
        self._parse_symbols()
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self._map_all()
        self._setup_stack()
        self._install_syscall_hook()

    # ---------------- ELF 解析 ----------------
    def _parse_elf(self):
        d = self.data
        assert d[:4] == b'\x7fELF'
        self.entry = struct.unpack_from('<Q', d, 24)[0]
        e_shoff = struct.unpack_from('<Q', d, 40)[0]
        e_shentsize = struct.unpack_from('<H', d, 58)[0]
        e_shnum = struct.unpack_from('<H', d, 60)[0]
        e_shstrndx = struct.unpack_from('<H', d, 62)[0]
        shstr_off = struct.unpack_from('<Q', d, e_shoff + e_shstrndx * e_shentsize + 24)[0]

        def cstr(o):
            e = d.index(b'\0', o)
            return d[o:e].decode('latin1')

        self.sections = {}
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            raw = struct.unpack_from('<IIQQQQIIQQ', d, off)
            name = cstr(shstr_off + raw[0])
            self.sections[name] = (raw[3], raw[4], raw[5], raw[1])  # addr, offset, size, type

    def _parse_symbols(self):
        """解析 .dynsym：定义 -> symbols；UND 导入 -> 通过 .rela.plt 得 PLT 地址"""
        d = self.data
        if '.dynsym' not in self.sections or '.dynstr' not in self.sections:
            return
        ds, dynstr = self.sections['.dynsym'], self.sections['.dynstr']
        dsa, dso, dssz, _ = ds
        dsta, dsto, dstsz, _ = dynstr
        import re

        def cstr(off):
            e = d.index(b'\0', dsto + off)
            return d[dsto + off:e].decode('latin1')

        # 先存所有 dynsym 的 (name, info, shndx)
        syms = []
        for j in range(0, dssz, 24):
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', d, dso + j)
            if st_name:
                syms.append((cstr(st_name), st_info, st_shndx, st_value))
        for name, info, shndx, value in syms:
            if shndx != 0:  # 定义符号
                self.symbols[name] = value
        # .rela.plt -> 导入表（GOT 地址）
        self._rela_plt = {}
        if '.rela.plt' in self.sections:
            rp = self.sections['.rela.plt']
            rpa, rpo, rpsz, _ = rp
            for j in range(0, rpsz, 24):
                r_offset, r_info, r_addend = struct.unpack_from('<QQq', d, rpo + j)
                sym_idx = r_info >> 32
                if sym_idx < len(syms):
                    self._rela_plt[syms[sym_idx][0]] = r_offset
                    self.imports[syms[sym_idx][0]] = r_offset

        # 扫描 .plt 的 jmp [rip+disp32] 找到 PLT stub 地址（匹配 .got.plt 区间）
        try:
            if '.plt' in self.sections and '.got.plt' in self.sections:
                plt = self.sections['.plt']
                got_addr = self.sections['.got.plt'][0]
                pa, po, psz, _ = plt
                blob = self.data[po:po + psz]
                for j in range(0, len(blob) - 6):
                    if blob[j] == 0xFF and (blob[j + 1] & 0x3F) == 0x25:  # jmp qword [rip+disp32]
                        disp = struct.unpack_from('<i', blob, j + 2)[0]
                        target = pa + j + 6 + disp
                        if got_addr <= target < got_addr + 0x300:
                            for name, goff in list(self._rela_plt.items()):
                                if goff == target:
                                    self.imports[name] = pa + j
        except Exception:
            pass

    def from_symbol(self, name):
        """符号名 -> VA（定义符号）或 PLT stub（导入）"""
        if name in self.symbols:
            return self.symbols[name]
        if name in self.imports:
            return self.imports[name]
        raise KeyError(name)

    # ---------------- 内存映射 ----------------
    def _map_all(self):
        self.mu.mem_map(0x0, 0x08000000)
        for name in ('.text', '.rodata', '.data', '.eh_frame', '.gcc_except_table',
                     '.eh_frame_hdr', '.plt', '.data.rel.ro', '.got', '.got.plt',
                     '.init_array', '.fini_array', '.preinit_array', '.note.android.ident'):
            if name in self.sections:
                addr, off, size, _ = self.sections[name]
                if size:
                    self.mu.mem_write(addr, self.data[off:off + size])
        if '.bss' in self.sections:
            addr, off, size, _ = self.sections['.bss']
            try:
                self.mu.mem_write(addr, b'\x00' * min(size, 0x20000))
            except UcError:
                pass

    def _setup_stack(self):
        self.STACK = 0x70000000
        self.mu.mem_map(self.STACK, 0x200000)
        self.mu.reg_write(UC_X86_REG_RSP, self.STACK + 0x100000)
        self.mu.reg_write(UC_X86_REG_RBP, self.STACK + 0x100000)

    # ---------------- 执行 ----------------
    def run(self, entry, until=0, timeout=10**9, max_steps=10**7):
        self.mu.emu_start(entry, until, count=max_steps, timeout=timeout)
        return self.pc()

    def call(self, func, args=None, until=0, max_steps=10**7, timeout=10**9):
        """SySV 调用：rdi/rsi/rdx/rcx/r8/r9；func 可为地址或符号名"""
        if isinstance(func, str):
            func = self.from_symbol(func)
        args = args or []
        regs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
        for i, v in enumerate(args[:6]):
            self.mu.reg_write(regs[i], v)
        ret = self.STACK + 0x9000
        rsp = self.mu.reg_read(UC_X86_REG_RSP)
        self.mu.mem_write(rsp - 8, struct.pack('<Q', ret))
        self.mu.reg_write(UC_X86_REG_RSP, rsp - 8)
        self.mu.emu_start(func, until, count=max_steps, timeout=timeout)
        return self.reg('rax')

    # ---------------- 寄存/内存 ----------------
    _REG = {'rax': UC_X86_REG_RAX, 'rbx': UC_X86_REG_RBX, 'rcx': UC_X86_REG_RCX,
            'rdx': UC_X86_REG_RDX, 'rsi': UC_X86_REG_RSI, 'rdi': UC_X86_REG_RDI,
            'rsp': UC_X86_REG_RSP, 'rbp': UC_X86_REG_RBP, 'rip': UC_X86_REG_RIP,
            'r8': UC_X86_REG_R8, 'r9': UC_X86_REG_R9, 'r10': UC_X86_REG_R10,
            'r11': UC_X86_REG_R11, 'r12': UC_X86_REG_R12, 'r13': UC_X86_REG_R13,
            'r14': UC_X86_REG_R14, 'r15': UC_X86_REG_R15}

    def reg(self, name):
        return self.mu.reg_read(self._REG[name])

    def set_reg(self, name, value):
        self.mu.reg_write(self._REG[name], value)

    def pc(self):
        return self.reg('rip')

    def read(self, addr, size):
        r = self.mu.mem_read(addr, size)
        return bytes(r) if isinstance(r, list) else r

    def read_str(self, addr, maxlen=256):
        b = self.read(addr, maxlen)
        i = b.find(b'\x00')
        return (b[:i] if i != -1 else b).decode('utf-8', 'replace')

    def read_cstr(self, addr, maxlen=256):
        return self.read_str(addr, maxlen)

    def write_mem(self, addr, data):
        if isinstance(data, str):
            data = data.encode()
        self.mu.mem_write(addr, data)

    def write_ptr(self, addr, value):
        self.mu.mem_write(addr, struct.pack('<Q', value))

    def read_ptr(self, addr):
        return struct.unpack('<Q', self.read(addr, 8))[0]

    def dump(self, addr, size):
        return self.read(addr, size)

    # ---------------- Snapshot / Restore ----------------
    def snapshot(self):
        """快照全部寄存器 + 栈区（简单实现：记录栈 64KB）"""
        regs = {n: self.reg(n) for n in self._REG}
        stack_lo = self.STACK + 0x100000 - 0x10000
        stack_hi = self.STACK + 0x100000
        stack = self.read(stack_lo, stack_hi - stack_lo)
        return {'regs': regs, 'stack_lo': stack_lo, 'stack': stack}

    def restore(self, snap):
        for n, v in snap['regs'].items():
            self.set_reg(n, v)
        stack = bytes(snap['stack']) if not isinstance(snap['stack'], bytes) else snap['stack']
        self.write_mem(snap['stack_lo'], stack)

    # ---------------- Hooks ----------------
    def hook_code(self, cb):
        """cb(uc, addr, size)；返回 False 可停止"""
        self.mu.hook_add(UC_HOOK_CODE, cb)

    def hook_mem_write(self, cb=None):
        """cb(addr, value) for mem writes；返回记录列表"""
        log = self._mem_write_log

        def h(uc, access, address, size, value, user):
            if cb:
                cb(address, value, size)
            log.append((address, value, size))
        self.mu.hook_add(UC_HOOK_MEM_WRITE, h)
        return log

    def hook_mem_read(self, cb=None):
        log = self._mem_read_log

        def h(uc, access, address, size, value, user):
            if cb:
                cb(address, size)
        self.mu.hook_add(UC_HOOK_MEM_READ, h)
        return log

    # ---------------- syscall 拦截 ----------------
    def _install_syscall_hook(self):
        def h(uc, user):
            n = uc.reg_read(UC_X86_REG_RAX)
            # 简单模拟若干 syscall
            if n == 60:  # exit
                uc.emu_stop()
            elif n == 231:  # exit_group
                uc.emu_stop()
            elif n == 1:  # write
                fd = uc.reg_read(UC_X86_REG_RDI)
                buf = uc.reg_read(UC_X86_REG_RSI)
                cnt = uc.reg_read(UC_X86_REG_RDX)
                try:
                    data = self.read(buf, min(cnt, 4096))
                    if fd == 1 or fd == 2:
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
                except Exception:
                    pass
                uc.reg_write(UC_X86_REG_RAX, cnt)
            elif n == 0:  # read
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif n == 9:  # mmap
                uc.reg_write(UC_X86_REG_RAX, 0x74000000)
            elif n == 12:  # brk
                uc.reg_write(UC_X86_REG_RAX, 0x76000000)
            elif n == 228:  # clock_gettime
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif n == 35:  # nanosleep
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif n == 7:  # poll
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif n == 35 or n == 130:  # nanodelay
                uc.reg_write(UC_X86_REG_RAX, 0)
            else:
                uc.reg_write(UC_X86_REG_RAX, 0)  # 默认返回成功
            # syscall 返回地址 = 下一条 rip（syscall 指令后自动）
        self.mu.hook_add(UC_HOOK_INSN, h, None, 1, 0, UC_X86_INS_SYSCALL)

    # ---------------- libc 桩系统 ----------------
    def install_libc_stub(self, name, handler):
        """注册 libc 函数桩：挂钩 .rela.plt 的 GOT 解析跳转前（call 到 PLT stub 时拦截）
        更稳：hook_code 检测 call 到 GOT entry-6 的 PLT stub → 直接执行 handler"""
        if name not in self._rela_plt:
            raise KeyError(f'import not found: {name}')
        got = self._rela_plt[name]
        stub = got - 6
        self._libc_handlers[stub] = handler

    def hook_import_function(self, name, handler):
        """别名（与 install_libc_stub 一致）：在 call 到该导入的 PLT stub 时调用 handler(uc, args)
        返回 handler 的 rax 值，跳过原 PLT"""
        self.install_libc_stub(name, handler)

    def install_libc_stubs(self, stubs=None):
        """自动安装常用 libc 桩（Python 实现）"""
        defaults = {
            'strlen': lambda uc: self._s_strlen(uc),
            'strcmp': lambda uc: self._s_strcmp(uc),
            'strncmp': lambda uc: self._s_strncmp(uc),
            'strcpy': lambda uc: self._s_strcpy(uc),
            'memcpy': lambda uc: self._s_memcpy(uc),
            'memmove': lambda uc: self._s_memcpy(uc),
            'memset': lambda uc: self._s_memset(uc),
            'putchar': lambda uc: self._s_putchar(uc),
            'puts': lambda uc: self._s_puts(uc),
            'time': lambda uc: self._s_time(uc),
            'usleep': lambda uc: self._s_usleep(uc),
            'dlopen': lambda uc: 0,
            'dlsym': lambda uc: 0,
            '__android_log_print': lambda uc: 0,
        }
        for name, h in (stubs or defaults).items():
            try:
                self.install_libc_stub(name, h)
            except KeyError:
                pass
        # 核心机制：hook_code 检测 call 到 stub
        stubs_map = dict(self._libc_handlers)

        def code_hook(uc, addr, size, user):
            # 检测 call rel32 到 stub
            try:
                if size >= 5:
                    insn = self.read(addr, 5)
                    if insn[0] == 0xE8:  # call rel32
                        disp = struct.unpack('<i', insn[1:5])[0]
                        target = addr + 5 + disp
                        if target in stubs_map:
                            handler = stubs_map[target]
                            rax = handler(uc)
                            uc.reg_write(UC_X86_REG_RAX, rax)
                            # 跳过 call（rip 已指向下一条——Unicorn 会在这条 call 执行完；直接改 rip 跳过）
                            uc.reg_write(UC_X86_REG_RIP, addr + 5)
            except Exception:
                pass
        self.mu.hook_add(UC_HOOK_CODE, code_hook)

    # ---------- libc 桩实现 ----------
    def _arg(self, uc, idx):
        regs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
        return uc.reg_read(regs[idx])

    def _s_strlen(self, uc):
        p = self._arg(uc, 0)
        s = self.read_str(p, 4096)
        return len(s)

    def _s_strcmp(self, uc):
        a = self.read_str(self._arg(uc, 0), 4096)
        b = self.read_str(self._arg(uc, 1), 4096)
        return (a > b) - (a < b)

    def _s_strncmp(self, uc):
        a = self.read_str(self._arg(uc, 0), 4096)[:self._arg(uc, 2)]
        b = self.read_str(self._arg(uc, 1), 4096)[:self._arg(uc, 2)]
        return (a > b) - (a < b)

    def _s_strcpy(self, uc):
        dst, src = self._arg(uc, 0), self._arg(uc, 1)
        s = self.read_str(src, 4096)
        self.write_mem(dst, s.encode() + b'\x00')
        return dst

    def _s_memcpy(self, uc):
        dst, src, n = self._arg(uc, 0), self._arg(uc, 1), self._arg(uc, 2)
        self.write_mem(dst, self.read(src, n))
        return dst

    def _s_memset(self, uc):
        dst, c, n = self._arg(uc, 0), self._arg(uc, 1) & 0xFF, self._arg(uc, 2)
        self.write_mem(dst, bytes([c]) * n)
        return dst

    def _s_putchar(self, uc):
        return self._arg(uc, 0) & 0xFF

    def _s_puts(self, uc):
        s = self.read_str(self._arg(uc, 0), 4096)
        print(s)
        return 0

    def _s_time(self, uc):
        return int(time.time())

    def _s_usleep(self, uc):
        return 0


# ---------------- 便捷 CLI ----------------
if __name__ == '__main__':
    print('ElfSim v2: from elf_sim import ElfSim')
    print('  sim = ElfSim("x.elf")')
    print('  sim.install_libc_stubs()')
    print('  sim.call(sim.from_symbol("main"))')
