# -*- coding: utf-8 -*-
"""
elf_sim.py — 自研 ELF 模拟动态执行框架 v4（MiniDBI 思路）

v4 新增：
  13. 断点 API：breakpoints（设/删/命中回调/停止）
  14. 指令追踪：trace_instructions() 记录执行路径（capstone 反汇编）
  15. 字符串自动收集：collect_strings() 抓取 .rodata/.data 被访问的字符串常量
  16. 状态持久化：save_state/load_state（JSON，寄存器+数据区）
  17. 越界检测：watch_range(addr, size) 记录对该区间的读/写
  18. 架构检测：ELF e_machine 校验（非 x86_64 明确报错）

依赖：unicorn 2.x（capstone 可选：无则 trace 仅地址）
"""
import struct
import sys
import time
import json
from unicorn import *
from unicorn.x86_const import *

try:
    from capstone import *
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


class ElfSim:
    """ELF x86_64 模拟执行框架（无 linker 依赖，直接函数级模拟）"""

    def __init__(self, elf_path):
        self.data = open(elf_path, 'rb').read()
        self._parse_elf()
        self.symbols = {}
        self.imports = {}
        self._libc_handlers = {}
        self._mem_write_log = []
        self._mem_read_log = []
        self._call_trace = []
        self._auto_stubs = True
        # v4 新增状态
        self._breakpoints = {}       # addr -> callback 或 None
        self._instr_trace = []       # [(addr, asm)]
        self._trace_on = False
        self._strings = set()        # v4: 自动收集的字符串
        self._watches = {}           # (addr,size) -> {'r': n, 'w': n}
        self._parse_symbols()
        self.symbols_name_rev = {v: k for k, v in self.symbols.items()}
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self._map_all()
        self._setup_stack()
        self._setup_heap()
        self._install_syscall_hook()
        self.install_libc_stubs(full=True)

    # ---------------- ELF 解析 ----------------
    def _parse_elf(self):
        d = self.data
        assert d[:4] == b'\x7fELF'
        self.elf_machine = struct.unpack_from('<H', d, 18)[0]
        if self.elf_machine != 62:  # EM_X86_64
            names = {3: 'x86(32)', 62: 'x86_64', 183: 'ARM64', 40: 'ARM', 243: 'RISC-V'}
            raise NotImplementedError(f'仅支持 x86_64 ELF (machine={self.elf_machine}, {names.get(self.elf_machine)})')
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
            self.sections[cstr(shstr_off + raw[0])] = (raw[3], raw[4], raw[5], raw[1])

    def _parse_symbols(self):
        d = self.data
        if '.dynsym' not in self.sections or '.dynstr' not in self.sections:
            return
        _, dso, dssz, _ = self.sections['.dynsym']
        _, dsto, _, _ = self.sections['.dynstr']

        def cstr(off):
            e = d.index(b'\0', dsto + off)
            return d[dsto + off:e].decode('latin1')

        syms = []
        for j in range(0, dssz, 24):
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', d, dso + j)
            if st_name:
                syms.append((cstr(st_name), st_info, st_shndx, st_value))
        for name, info, shndx, value in syms:
            if shndx != 0:
                self.symbols[name] = value
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
        try:
            if '.plt' in self.sections and '.got.plt' in self.sections:
                plt = self.sections['.plt']
                got_addr = self.sections['.got.plt'][0]
                pa, po, psz, _ = plt
                blob = self.data[po:po + psz]
                for j in range(0, len(blob) - 6):
                    if blob[j] == 0xFF and (blob[j + 1] & 0x3F) == 0x25:
                        disp = struct.unpack_from('<i', blob, j + 2)[0]
                        target = pa + j + 6 + disp
                        if got_addr <= target < got_addr + 0x300:
                            for name, goff in list(self._rela_plt.items()):
                                if goff == target:
                                    self.imports[name] = pa + j
        except Exception:
            pass

    def from_symbol(self, name):
        if name in self.symbols:
            return self.symbols[name]
        if name in self.imports:
            return self.imports[name]
        raise KeyError(name)

    def where(self, addr):
        """地址描述：符号名 / 根符号 + 偏移"""
        if addr in self.symbols_name_rev:
            return self.symbols_name_rev[addr]
        best = None
        for name, va in self.symbols.items():
            if va <= addr < va + 0x1000 and (best is None or addr - va < addr - best[1]):
                best = (name, va)
        if best:
            return f'{best[0]}+0x{addr - best[1]:X}'
        return hex(addr)

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

    def _setup_heap(self):
        self.HEAP = 0x72000000
        self.mu.mem_map(self.HEAP, 0x800000)
        self._heap_cur = self.HEAP

    # ---------------- 执行 ----------------
    def run(self, entry, until=0, timeout=10**9, max_steps=10**7):
        self.mu.emu_start(entry, until, count=max_steps, timeout=timeout)
        return self.pc()

    def call(self, func, args=None, until=0, max_steps=10**7, timeout=10**9):
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

    def setup_argv(self, args):
        rsp = self.mu.reg_read(UC_X86_REG_RSP)
        cur = rsp - 0x1000
        ptrs = []
        for s in args:
            if isinstance(s, str):
                s = s.encode()
            self.write_mem(cur, s + b'\x00')
            ptrs.append(cur)
            cur += len(s) + 1
        table = rsp - 0x2000
        for i, p in enumerate(ptrs):
            self.write_ptr(table + i * 8, p)
        self.write_ptr(table + len(ptrs) * 8, 0)
        return table

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

    # ---------------- 快照/恢复 ----------------
    def snapshot(self):
        regs = {n: self.reg(n) for n in self._REG}
        stack_lo = self.STACK + 0x100000 - 0x10000
        stack = self.read(stack_lo, 0x10000)
        return {'regs': regs, 'stack_lo': stack_lo, 'stack': stack}

    def restore(self, snap):
        for n, v in snap['regs'].items():
            self.set_reg(n, v)
        stack = bytes(snap['stack']) if not isinstance(snap['stack'], bytes) else snap['stack']
        self.write_mem(snap['stack_lo'], stack)

    # ---------------- v4: 断点 ----------------
    def add_breakpoint(self, addr, cb=None):
        """设置执行断点。cb(addr, insn_size) 返回 False 停止；无 cb 默认停止"""
        self._breakpoints[addr] = cb

    def remove_breakpoint(self, addr):
        self._breakpoints.pop(addr, None)

    def list_breakpoints(self):
        return list(self._breakpoints)

    def _ensure_hooks_installed(self):
        """安装统一的 code hook（断点/trace/watch 复用，幂等）"""
        if getattr(self, '_hooks_installed', False):
            return
        stubs_map = dict(self._libc_handlers)
        bp = self._breakpoints
        self._hooks_installed = True

        def code_hook(uc, addr, size, user):
            # 1) 断点
            if addr in bp:
                cb = bp[addr]
                hit = (cb(addr, size) if cb else None)
                if hit is False or cb is None:
                    uc.emu_stop()
                    return
            # 2) 指令追踪
            if self._trace_on:
                self._instr_trace.append((addr, self._disasm(addr, size)))
            # 3) libc 桩拦截
            try:
                if size >= 5:
                    insn = self.read(addr, 5)
                    if insn[0] == 0xE8:
                        disp = struct.unpack('<i', insn[1:5])[0]
                        target = addr + 5 + disp
                        if target in stubs_map:
                            rax = stubs_map[target](uc)
                            uc.reg_write(UC_X86_REG_RAX, rax)
                            uc.reg_write(UC_X86_REG_RIP, addr + 5)
            except Exception:
                pass
        self.mu.hook_add(UC_HOOK_CODE, code_hook)

    def _disasm(self, addr, size):
        if not _HAS_CAPSTONE:
            return f'0x{addr:X}'
        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64) if not hasattr(self, '_md') else self._md
            if not hasattr(self, '_md'):
                self._md = md
            for i in md.disasm(self.read(addr, min(size, 15)), addr, count=1):
                return f'0x{addr:X}: {i.mnemonic} {i.op_str}'
        except Exception:
            pass
        return f'0x{addr:X}'

    # ---------------- v4: 指令追踪 ----------------
    def trace_instructions(self, on=True):
        """开始/停止记录执行路径（addr + 反汇编）"""
        self._trace_on = on
        if on:
            self._instr_trace = []
        self._ensure_hooks_installed()
        return self._instr_trace

    @property
    def instr_trace(self):
        return self._instr_trace

    # ---------------- v4: 字符串自动收集 ----------------
    def collect_strings(self):
        """收集执行中被引用（读 .rodata/.data）的字符串常量"""
        self._strings = set()
        self._ensure_hooks_installed()

        def h(uc, access, address, size, value, user):
            # 只记录读 .rodata/.data 区可打印字符串
            try:
                if access == UC_MEM_READ:
                    for sec in ('.rodata', '.data'):
                        if sec in self.sections:
                            sa, _, ss, _ = self.sections[sec]
                            if sa <= address < sa + ss and size >= 2:
                                b = self.read(address, min(128, 4096))
                                if b and all(32 <= c < 127 or c in (9, 10, 13) for c in b[:32]):
                                    i = b.find(b'\x00')
                                    s = (b[:i] if i != -1 else b[:32]).decode('ascii', 'replace')
                                    if len(s) >= 4 and s.isprintable():
                                        self._strings.add(s)
            except Exception:
                pass
        self.mu.hook_add(UC_HOOK_MEM_READ, h)
        return self._strings

    @property
    def strings(self):
        return self._strings

    # ---------------- v4: 区间监视 ----------------
    def watch_range(self, addr, size):
        """监视区间读写（记录次数）"""
        self._watches[(addr, addr + size)] = {'r': 0, 'w': 0}
        self._ensure_hooks_installed()

        def h(uc, access, address, size2, value, user):
            for (lo, hi), st in self._watches.items():
                if lo <= address < hi:
                    if access == UC_MEM_READ:
                        st['r'] += 1
                    elif access in (UC_MEM_WRITE, UC_MEM_WRITE_UNMAPPED):
                        st['w'] += 1
        self.mu.hook_add(UC_HOOK_MEM_READ, h)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, h)

    @property
    def watches(self):
        return self._watches

    # ---------------- v4: 状态持久化 ----------------
    def save_state(self, path):
        """保存寄存器 + 数据区差异（JSON）"""
        regs = {n: self.reg(n) for n in self._REG}
        # 保存 .data 区（可能被解密修改）
        data_sec = self.sections.get('.data')
        data_blob = None
        if data_sec:
            data_blob = self.read(data_sec[0], data_sec[2]).hex()
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'machine': self.elf_machine, 'regs': regs, 'data': data_blob}, f)
        return path

    def load_state(self, path):
        with open(path, encoding='utf-8') as f:
            st = json.load(f)
        for n, v in st['regs'].items():
            self.set_reg(n, v)
        if st.get('data') and '.data' in self.sections:
            blob = bytes.fromhex(st['data'])
            self.write_mem(self.sections['.data'][0], blob)
        return True

    # ---------------- Hooks（原 API 保留） ----------------
    def hook_code(self, cb):
        self.mu.hook_add(UC_HOOK_CODE, cb)

    def hook_mem_write(self, cb=None):
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

    def trace_calls(self):
        self._call_trace = []
        name_by_addr = {}
        for name, addr in self.imports.items():
            name_by_addr[addr] = name
        for addr, handler in self._libc_handlers.items():
            name_by_addr[addr] = name_by_addr.get(addr, f'stub_{addr:X}')

        def h(uc, addr, size, user):
            try:
                if size >= 5:
                    insn = self.read(addr, 5)
                    if insn[0] == 0xE8:
                        disp = struct.unpack('<i', insn[1:5])[0]
                        target = addr + 5 + disp
                        if target in name_by_addr:
                            self._call_trace.append(name_by_addr[target])
            except Exception:
                pass
        self.mu.hook_add(UC_HOOK_CODE, h)
        return self._call_trace

    # ---------------- syscall 拦截 ----------------
    def _install_syscall_hook(self):
        def h(uc, user):
            n = uc.reg_read(UC_X86_REG_RAX)
            if n in (60, 231):
                uc.emu_stop()
            elif n == 1:
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
            elif n == 0:
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif n == 9:
                uc.reg_write(UC_X86_REG_RAX, 0x74000000)
            elif n == 12:
                uc.reg_write(UC_X86_REG_RAX, self._heap_cur + 0x1000)
            elif n == 228:
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif n in (35, 130):
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif n == 7:
                uc.reg_write(UC_X86_REG_RAX, 0)
            else:
                uc.reg_write(UC_X86_REG_RAX, 0)
        self.mu.hook_add(UC_HOOK_INSN, h, None, 1, 0, UC_X86_INS_SYSCALL)

    # ---------------- libc 桩系统 ----------------
    def install_libc_stub(self, name, handler):
        if name not in self._rela_plt:
            raise KeyError(name)
        stub = self.imports.get(name, self._rela_plt[name])
        self._libc_handlers[stub] = handler

    def install_libc_stubs(self, full=False, stubs=None):
        defaults = {
            'strlen': lambda uc: self._s_strlen(uc),
            'strcmp': lambda uc: self._s_strcmp(uc),
            'strncmp': lambda uc: self._s_strncmp(uc),
            'memcmp': lambda uc: self._s_memcmp(uc),
            'strcpy': lambda uc: self._s_strcpy(uc),
            'strncpy': lambda uc: self._s_strncpy(uc),
            'strcat': lambda uc: self._s_strcat(uc),
            'strchr': lambda uc: 0,
            'strstr': lambda uc: 0,
            'memcpy': lambda uc: self._s_memcpy(uc),
            'memmove': lambda uc: self._s_memcpy(uc),
            'memset': lambda uc: self._s_memset(uc),
            'putchar': lambda uc: self._s_putchar(uc),
            'puts': lambda uc: self._s_puts(uc),
            'printf': lambda uc: self._s_printf(uc),
            'sprintf': lambda uc: self._s_sprintf(uc),
            'atoi': lambda uc: self._s_atoi(uc),
            'strtol': lambda uc: self._s_atoi(uc),
            'time': lambda uc: self._s_time(uc),
            'usleep': lambda uc: 0,
            'malloc': lambda uc: self._s_malloc(uc),
            'calloc': lambda uc: self._s_calloc(uc),
            'free': lambda uc: 0,
            'dlopen': lambda uc: 0,
            'dlsym': lambda uc: 0,
            'getenv': lambda uc: 0,
            'abort': lambda uc: (uc.emu_stop(), 0)[1],
            'exit': lambda uc: (uc.emu_stop(), 0)[1],
            '__android_log_print': lambda uc: 0,
            'clock_gettime': lambda uc: 0,
            'gettimeofday': lambda uc: 0,
        }
        for name, h in (stubs or defaults).items():
            try:
                self.install_libc_stub(name, h)
            except KeyError:
                pass
        self._ensure_hooks_installed()

    def enable_auto_stubs(self, on=True):
        self._auto_stubs = on

    # ---------- libc 桩实现 ----------
    def _arg(self, uc, idx):
        regs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
        return uc.reg_read(regs[idx])

    def _s_strlen(self, uc):
        return len(self.read_str(self._arg(uc, 0), 4096))

    def _s_strcmp(self, uc):
        a = self.read_str(self._arg(uc, 0), 4096)
        b = self.read_str(self._arg(uc, 1), 4096)
        return (a > b) - (a < b)

    def _s_strncmp(self, uc):
        n = self._arg(uc, 2)
        a = self.read_str(self._arg(uc, 0), 4096)[:n]
        b = self.read_str(self._arg(uc, 1), 4096)[:n]
        return (a > b) - (a < b)

    def _s_memcmp(self, uc):
        n = self._arg(uc, 2)
        a = self.read(self._arg(uc, 0), n)
        b = self.read(self._arg(uc, 1), n)
        return (a > b) - (a < b)

    def _s_strcpy(self, uc):
        dst = self._arg(uc, 0)
        self.write_mem(dst, self.read_str(self._arg(uc, 1), 4096).encode() + b'\x00')
        return dst

    def _s_strncpy(self, uc):
        dst, n = self._arg(uc, 0), self._arg(uc, 2)
        s = self.read_str(self._arg(uc, 1), n + 1) if n else ''
        data = s.encode()[:n]
        if n > len(data):
            data += b'\x00' * (n - len(data))
        self.write_mem(dst, data)
        return dst

    def _s_strcat(self, uc):
        dst, src = self._arg(uc, 0), self._arg(uc, 1)
        cur = dst + len(self.read_str(dst, 4096))
        s = self.read_str(src, 4096)
        self.write_mem(cur, s.encode() + b'\x00')
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

    def _fmt_args(self, uc):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        args = []
        for i in range(8):
            args.append(self.read_ptr(rsp + 8 + (7 - i) * 8))
        return args

    def _parse_fmt(self, fmt, args):
        out = []
        ai = 0
        i = 0
        while i < len(fmt):
            if fmt[i] == '%' and i + 1 < len(fmt):
                spec = fmt[i:i+2]
                if spec in ('%s', '%d', '%i', '%x', '%X', '%u', '%f', '%p', '%c', '%ld', '%.s'):
                    if spec == '%s':
                        try:
                            out.append(self.read_str(args[ai], 4096))
                        except Exception:
                            out.append(f'<ptr:{args[ai]}>')
                        ai += 1
                    elif spec in ('%d', '%i', '%u', '%x', '%X', '%ld'):
                        out.append(str(args[ai]))
                        ai += 1
                    elif spec == '%c':
                        out.append(chr(args[ai] & 0xFF))
                        ai += 1
                    elif spec == '%p':
                        out.append(hex(args[ai]))
                        ai += 1
                    elif spec == '%f':
                        out.append(str(args[ai]))
                        ai += 1
                    else:
                        out.append(spec)
                    i += 2
                elif fmt[i+1] == '%':
                    out.append('%')
                    i += 2
                else:
                    out.append(fmt[i])
                    i += 1
            else:
                out.append(fmt[i])
                i += 1
        return ''.join(out)

    def _s_printf(self, uc):
        fmt = self.read_str(self._arg(uc, 0), 2048)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        vals = []
        for i in range(1, 9):
            try:
                vals.append(self.read_ptr(rsp + i * 8))
            except Exception:
                break
        txt = self._parse_fmt(fmt, vals)
        try:
            sys.stdout.write(txt)
            sys.stdout.flush()
        except Exception:
            pass
        return len(txt)

    def _s_sprintf(self, uc):
        dst = self._arg(uc, 0)
        fmt = self.read_str(self._arg(uc, 1), 2048)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        vals = []
        for i in range(2, 9):
            try:
                vals.append(self.read_ptr(rsp + i * 8))
            except Exception:
                break
        txt = self._parse_fmt(fmt, vals)
        self.write_mem(dst, txt.encode() + b'\x00')
        return len(txt)

    def _s_atoi(self, uc):
        s = self.read_str(self._arg(uc, 0), 256)
        try:
            import re
            m = re.search(r'[-+]?\d+', s)
            return int(m.group(0)) if m else 0
        except Exception:
            return 0

    def _s_time(self, uc):
        return int(time.time())

    def _s_malloc(self, uc):
        size = self._arg(uc, 0)
        if size == 0:
            size = 1
        size = (size + 15) & ~15
        if self._heap_cur + size > self.HEAP + 0x800000:
            return 0
        ptr = self._heap_cur
        self._heap_cur += size
        return ptr

    def _s_calloc(self, uc):
        nmemb, size = self._arg(uc, 0), self._arg(uc, 1)
        ptr = self._s_malloc(uc)
        if ptr:
            self.write_mem(ptr, b'\x00' * min(nmemb * size, 4096))
        return ptr


# ---------------- 便捷 CLI ----------------
if __name__ == '__main__':
    print('ElfSim v4: from elf_sim import ElfSim')
    print('  sim = ElfSim("x.elf")')
    print('  sim.add_breakpoint(addr, cb)        # 断点')
    print('  sim.trace_instructions()            # 指令追踪')
    print('  sim.collect_strings()               # 字符串收集')
    print('  sim.save_state("s.json")            # 状态持久化')
