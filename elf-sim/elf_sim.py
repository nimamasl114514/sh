# -*- coding: utf-8 -*-
"""
elf_sim.py — 自研 ELF 模拟动态执行框架 v7（双架构：x86_64 + ARM64）
v7 新增：ARM64 后端（Unicorn 原生支持，第三方引擎）
  - 架构自动检测（ELF machine: 62=x86_64 / 183=ARM64）
  - ARM64: 参数 x0-x7 / bl 调用识别 / ret 检测 / svc 拦截 / AArch64 PLT 解析（标准 16B entry）
  - 双架构共用全部观察能力（断点/追踪/调用树/桩/差分/持久化）

依赖：unicorn 2.x（capstone 可选）
"""
import struct
import sys
import time
import json
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm64_const import *

try:
    from capstone import *
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


class ElfSim:
    """ELF 模拟执行框架（双架构）"""

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
        self._breakpoints = {}
        self._instr_trace = []
        self._trace_on = False
        self._strings = set()
        self._watches = {}
        self._parse_symbols()
        if not hasattr(self, '_rela_plt'):
            self._rela_plt = {}
        self.symbols_name_rev = {v: k for k, v in self.symbols.items()}
        # 架构选择（在 _parse_elf 后确定）
        self._init_arch()
        self._resolve_plt()
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
        if self.elf_machine == 62:
            self.arch_name = 'x86_64'
        elif self.elf_machine == 183:
            self.arch_name = 'aarch64'
        else:
            names = {3: 'x86(32)', 40: 'ARM', 243: 'RISC-V'}
            raise NotImplementedError(f'不支持的架构 machine={self.elf_machine} ({names.get(self.elf_machine)})')
        self.entry = struct.unpack_from('<Q', d, 24)[0]
        e_shoff = struct.unpack_from('<Q', d, 40)[0]
        e_shentsize = struct.unpack_from('<H', d, 58)[0]
        e_shnum = struct.unpack_from('<H', d, 60)[0]
        e_shstrndx = struct.unpack_from('<H', d, 62)[0]
        self.sections = {}
        if e_shnum and e_shoff:
            shstr_off = struct.unpack_from('<Q', d, e_shoff + e_shstrndx * e_shentsize + 24)[0]

            def cstr(o):
                e = d.index(b'\0', o)
                return d[o:e].decode('latin1')

            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                raw = struct.unpack_from('<IIQQQQIIQQ', d, off)
                self.sections[cstr(shstr_off + raw[0])] = (raw[3], raw[4], raw[5], raw[1])

    # ---------------- 架构初始化 ----------------
    def _init_arch(self):
        """按架构设置寄存器/指令识别常量"""
        if self.arch_name == 'x86_64':
            self.uc = UC_ARCH_X86
            self.mode = UC_MODE_64
            self._REG = {n: v for n, v in {
                'rax': UC_X86_REG_RAX, 'rbx': UC_X86_REG_RBX, 'rcx': UC_X86_REG_RCX,
                'rdx': UC_X86_REG_RDX, 'rsi': UC_X86_REG_RSI, 'rdi': UC_X86_REG_RDI,
                'rsp': UC_X86_REG_RSP, 'rbp': UC_X86_REG_RBP, 'rip': UC_X86_REG_RIP,
                'r8': UC_X86_REG_R8, 'r9': UC_X86_REG_R9, 'r10': UC_X86_REG_R10,
                'r11': UC_X86_REG_R11, 'r12': UC_X86_REG_R12, 'r13': UC_X86_REG_R13,
                'r14': UC_X86_REG_R14, 'r15': UC_X86_REG_R15}.items()}
            self.PARAM_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
            self.SP = 'rsp'; self.FP = 'rbp'; self.PC = 'rip'
        else:  # aarch64
            self.uc = UC_ARCH_ARM64
            self.mode = UC_MODE_ARM
            self._REG = {n: globals().get(f'UC_ARM64_REG_{n.upper()}') for n in []}  # 通过统一填充
            regvals = {
                'x0': UC_ARM64_REG_X0, 'x1': UC_ARM64_REG_X1, 'x2': UC_ARM64_REG_X2,
                'x3': UC_ARM64_REG_X3, 'x4': UC_ARM64_REG_X4, 'x5': UC_ARM64_REG_X5,
                'x6': UC_ARM64_REG_X6, 'x7': UC_ARM64_REG_X7, 'x8': UC_ARM64_REG_X8,
                'x9': UC_ARM64_REG_X9, 'x10': UC_ARM64_REG_X10, 'x11': UC_ARM64_REG_X11,
                'x12': UC_ARM64_REG_X12, 'x13': UC_ARM64_REG_X13, 'x14': UC_ARM64_REG_X14,
                'x15': UC_ARM64_REG_X15, 'x16': UC_ARM64_REG_X16, 'x17': UC_ARM64_REG_X17,
                'x18': UC_ARM64_REG_X18, 'x19': UC_ARM64_REG_X19, 'x20': UC_ARM64_REG_X20,
                'x21': UC_ARM64_REG_X21, 'x22': UC_ARM64_REG_X22, 'x23': UC_ARM64_REG_X23,
                'x24': UC_ARM64_REG_X24, 'x25': UC_ARM64_REG_X25, 'x26': UC_ARM64_REG_X26,
                'x27': UC_ARM64_REG_X27, 'x28': UC_ARM64_REG_X28, 'x29': UC_ARM64_REG_X29,
                'sp': UC_ARM64_REG_SP, 'fp': UC_ARM64_REG_FP, 'pc': UC_ARM64_REG_PC,
            }
            self._REG = regvals
            self.PARAM_REGS = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']
            self.SP = 'sp'; self.FP = 'fp'; self.PC = 'pc'
        self.mu = Uc(self.uc, self.mode)

    # ---------------- 符号/PLT ----------------
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

    def _resolve_plt(self):
        """根据架构解析 PLT stub（回填 imports: name -> stub 地址）"""
        if '.plt' not in self.sections or not self._rela_plt:
            return
        if self.arch_name == 'x86_64':
            if '.got.plt' in self.sections:
                got_addr = self.sections['.got.plt'][0]
                pa, po, psz, _ = self.sections['.plt']
                blob = self.data[po:po + psz]
                for j in range(0, len(blob) - 6):
                    if blob[j] == 0xFF and (blob[j + 1] & 0x3F) == 0x25:
                        disp = struct.unpack_from('<i', blob, j + 2)[0]
                        target = pa + j + 6 + disp
                        if got_addr <= target < got_addr + 0x300:
                            for name, goff in list(self._rela_plt.items()):
                                if goff == target:
                                    self.imports[name] = pa + j
        else:  # aarch64: 标准 PLT entry 16 字节，第 i 个 (i>=1) 对应 .rela.plt[i-1]
            pa, po, psz, _ = self.sections['.plt']
            rela_names = list(self._rela_plt.keys())
            # PLT[0] 是跳板起始；entry i 起自 pa + i*16
            for idx, name in enumerate(rela_names):
                stub = pa + (idx + 1) * 16
                if stub < pa + psz:
                    self.imports[name] = stub

    # ---------------- 指令识别 ----------------
    def _is_call(self, insn, addr):
        """(is_call, target)"""
        if self.arch_name == 'x86_64':
            if insn and insn[0] == 0xE8 and len(insn) >= 5:
                disp = struct.unpack('<i', insn[1:5])[0]
                return True, addr + 5 + disp
        else:  # aarch64: bl 0x94000000 | (imm26 & 0x3ffffff)
            if insn and len(insn) >= 4:
                word = struct.unpack('<I', insn[:4])[0]
                if (word & 0xFC000000) == 0x94000000:
                    imm26 = word & 0x3FFFFFF
                    # sign extend 26位
                    if imm26 & 0x2000000:
                        imm26 -= 0x4000000
                    return True, addr + imm26 * 4
        return False, None

    def _is_ret(self, insn):
        if self.arch_name == 'x86_64':
            return insn and insn[0] in (0xC3, 0xC2)
        else:
            return insn and len(insn) >= 4 and struct.unpack('<I', insn[:4])[0] == 0xD65F03C0  # ret

    # ---------------- 内存映射 ----------------
    def _map_all(self):
        self.mu.mem_map(0x0, 0x08000000)
        # 1) 节表映射（常规）
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
        # 2) 无节表（最小 ELF）：按程序头 PT_LOAD 映射
        if not self.sections or '.text' not in self.sections:
            try:
                d = self.data
                e_phoff = struct.unpack_from('<Q', d, 32)[0]
                e_phentsize = struct.unpack_from('<H', d, 54)[0]
                e_phnum = struct.unpack_from('<H', d, 56)[0]
                for i in range(e_phnum):
                    po = e_phoff + i * e_phentsize
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                        struct.unpack_from('<IIQQQQQQ', d, po)
                    if p_type == 1 and p_filesz:  # PT_LOAD
                        self.mu.mem_write(p_vaddr, d[p_offset:p_offset + p_filesz])
            except Exception:
                pass

    def _setup_stack(self):
        self.STACK = 0x70000000
        self.mu.mem_map(self.STACK, 0x200000)
        self.mu.reg_write(self._REG[self.SP], self.STACK + 0x100000)
        self.mu.reg_write(self._REG[self.FP], self.STACK + 0x100000)

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
        for i, v in enumerate(args[:len(self.PARAM_REGS)]):
            self.mu.reg_write(self._REG[self.PARAM_REGS[i]], v)
        ret = self.STACK + 0x9000
        sp = self.mu.reg_read(self._REG[self.SP])
        # x86_64: call 时返回地址在栈；arm64: bl 也会入栈（但我们直接 start 不确定）——用栈写返回值
        self.mu.mem_write(sp - 8, struct.pack('<Q', ret))
        self.mu.reg_write(self._REG[self.SP], sp - 8)
        self.mu.emu_start(func, until, count=max_steps, timeout=timeout)
        return self.reg(self.PARAM_REGS[0]) if self.arch_name == 'aarch64' else self.reg('rax')

    def setup_argv(self, args):
        sp = self.mu.reg_read(self._REG[self.SP])
        cur = sp - 0x1000
        ptrs = []
        for s in args:
            if isinstance(s, str):
                s = s.encode()
            self.write_mem(cur, s + b'\x00')
            ptrs.append(cur)
            cur += len(s) + 1
        table = sp - 0x2000
        for i, p in enumerate(ptrs):
            self.write_ptr(table + i * 8, p)
        self.write_ptr(table + len(ptrs) * 8, 0)
        return table

    # ---------------- 寄存/内存 ----------------
    def reg(self, name):
        return self.mu.reg_read(self._REG[name])

    def set_reg(self, name, value):
        self.mu.reg_write(self._REG[name], value)

    def pc(self):
        return self.reg(self.PC)

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

    def where(self, addr):
        if hasattr(self, 'symbols_name_rev') and addr in self.symbols_name_rev:
            return self.symbols_name_rev[addr]
        best = None
        for name, va in self.symbols.items():
            if va <= addr < va + 0x1000 and (best is None or addr - va < addr - best[1]):
                best = (name, va)
        if best:
            return f'{best[0]}+0x{addr - best[1]:X}'
        return hex(addr)

    def from_symbol(self, name):
        if name in self.symbols:
            return self.symbols[name]
        if name in self.imports:
            return self.imports[name]
        raise KeyError(name)

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

    # ---------------- hooks ----------------
    def _disasm(self, addr, size):
        if not _HAS_CAPSTONE:
            return f'0x{addr:X}'
        try:
            if not hasattr(self, '_md'):
                if self.arch_name == 'x86_64':
                    self._md = Cs(CS_ARCH_X86, CS_MODE_64)
                else:
                    self._md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            for i in self._md.disasm(self.read(addr, min(size * 4, 16)), addr, count=1):
                return f'0x{i.address:X}: {i.mnemonic} {i.op_str}'
        except Exception:
            pass
        return f'0x{addr:X}'

    def disasm(self, addr, n=1):
        if not _HAS_CAPSTONE:
            raise RuntimeError('需要 capstone')
        if not hasattr(self, '_md'):
            if self.arch_name == 'x86_64':
                self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                self._md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        code = self.read(addr, n * 8)
        out = []
        for i in self._md.disasm(code, addr, count=n):
            out.append(f'0x{i.address:X}: {i.mnemonic} {i.op_str}')
        return out

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
        name_by_addr = dict(self.imports)

        def h(uc, addr, size, user):
            try:
                insn = self.read(addr, 5 if self.arch_name == 'x86_64' else 4)
                is_call, target = self._is_call(insn, addr)
                if is_call and target in name_by_addr:
                    self._call_trace.append(name_by_addr[target])
            except Exception:
                pass
        self.mu.hook_add(UC_HOOK_CODE, h)
        return self._call_trace

    def trace_instructions(self, on=True):
        self._trace_on = on
        if on:
            self._instr_trace = []
        self._ensure_hooks_installed()
        return self._instr_trace

    @property
    def instr_trace(self):
        return self._instr_trace

    def collect_strings(self):
        self._strings = set()
        self._ensure_hooks_installed()

        def h(uc, access, address, size, value, user):
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

    def watch_range(self, addr, size):
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

    def add_breakpoint(self, addr, cb=None):
        self._breakpoints[addr] = cb

    def remove_breakpoint(self, addr):
        self._breakpoints.pop(addr, None)

    def list_breakpoints(self):
        return list(self._breakpoints)

    def _ensure_hooks_installed(self):
        if getattr(self, '_hooks_installed', False):
            return
        stubs_map = dict(self._libc_handlers)
        bp = self._breakpoints
        self._hooks_installed = True

        def code_hook(uc, addr, size, user):
            if addr in bp:
                cb = bp[addr]
                hit = (cb(addr, size) if cb else None)
                if hit is False or cb is None:
                    uc.emu_stop()
                    return
            if self._trace_on:
                self._instr_trace.append((addr, self._disasm(addr, size)))
            try:
                insn = self.read(addr, 5 if self.arch_name == 'x86_64' else 4)
                is_call, target = self._is_call(insn, addr)
                if is_call and target in stubs_map:
                    rax = stubs_map[target](uc)
                    uc.reg_write(self._REG[self.PARAM_REGS[0]], rax)
                    # 跳过 call（x86: rip+=5; arm64: pc = addr+4）
                    uc.reg_write(self._REG[self.PC], addr + (5 if self.arch_name == 'x86_64' else 4))
            except Exception:
                pass
        self.mu.hook_add(UC_HOOK_CODE, code_hook)

    # ---------------- v5/v6 支持（复用） ----------------
    def export_trace(self, path):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self._instr_trace, f)
        return path

    def set_output(self, stream):
        self._out_stream = stream

    def _out(self, text):
        s = getattr(self, '_out_stream', None)
        if s:
            s.write(text)
            try:
                s.flush()
            except Exception:
                pass
        else:
            sys.stdout.write(text)
            sys.stdout.flush()

    def step(self):
        self.mu.emu_start(self.pc(), 0, count=1)
        return self.pc()

    def continue_until(self, addr, max_steps=10**7):
        self.mu.emu_start(self.pc(), addr, count=max_steps)
        return self.pc()

    def skip_call(self, addr):
        self._skips = getattr(self, '_skips', set())
        self._skips.add(addr)
        if not getattr(self, '_skip_hook_installed', False):
            self._skip_hook_installed = True

            def h(uc, addr2, size, user):
                if addr2 in self._skips:
                    uc.reg_write(self._REG[self.PARAM_REGS[0]], 0)
                    uc.reg_write(self._REG[self.PC], addr2 + size)
            self.mu.hook_add(UC_HOOK_CODE, h)

    def diff_memory(self, addr, size, base_blob):
        cur = self.read(addr, size)
        diffs = []
        for i in range(min(len(cur), len(base_blob))):
            if cur[i] != base_blob[i]:
                diffs.append((i, base_blob[i], cur[i]))
        return diffs

    def set_seed(self, seed):
        import random
        self._rand = random.Random(seed)
        try:
            self.install_libc_stub('rand', lambda uc: self._rand.randint(0, 0x7FFFFFFF))
        except KeyError:
            pass

    def save_state(self, path):
        regs = {n: self.reg(n) for n in self._REG}
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
            if n in self._REG:
                self.set_reg(n, v)
        if st.get('data') and '.data' in self.sections:
            blob = bytes.fromhex(st['data'])
            self.write_mem(self.sections['.data'][0], blob)
        return True

    def call_tree(self):
        self._call_tree = []
        self._call_stack = [0]
        if not getattr(self, '_calltree_hook', False):
            self._calltree_hook = True
            if '.text' in self.sections:
                text_lo = self.sections['.text'][0]
                text_hi = text_lo + self.sections['.text'][2]

                def h(uc, addr, size, user):
                    try:
                        insn = self.read(addr, 5 if self.arch_name == 'x86_64' else 4)
                        is_call, target = self._is_call(insn, addr)
                        if is_call and text_lo <= target <= text_hi:
                            self._call_tree.append((len(self._call_stack), target, addr))
                            self._call_stack.append(target)
                        elif self._is_ret(insn):
                            if len(self._call_stack) > 1:
                                self._call_stack.pop()
                    except Exception:
                        pass
                self.mu.hook_add(UC_HOOK_CODE, h)
        return self._call_tree

    def dump_call_tree(self, symbolizer=None):
        sym = symbolizer or self.where
        out = []
        for depth, target, caller in self._call_tree:
            out.append('  ' * depth + sym(target))
        return '\n'.join(out)

    def exec_stats(self, reset=False):
        if not getattr(self, '_stats_hook', False) or reset:
            self._stats = {'insns': 0, 'calls': 0, 'rets': 0}
            self._stats_start = time.time()
            self._stats_hook = True

            def h(uc, addr, size, user):
                self._stats['insns'] += 1
                try:
                    insn = self.read(addr, 5 if self.arch_name == 'x86_64' else 4)
                    is_call, _ = self._is_call(insn, addr)
                    if is_call:
                        self._stats['calls'] += 1
                    elif self._is_ret(insn):
                        self._stats['rets'] += 1
                except Exception:
                    pass
            self.mu.hook_add(UC_HOOK_CODE, h)
        st = dict(self._stats)
        st['elapsed'] = round(time.time() - self._stats_start, 3)
        return st

    def set_log(self, path):
        self._log_file = open(path, 'w', encoding='utf-8')

    def log(self, *args):
        f = getattr(self, '_log_file', None)
        line = ' '.join(str(a) for a in args)
        if f:
            f.write(line + '\n')
            f.flush()
        else:
            print(line)

    def memory_region_hook(self, addr, size, on_read=None, on_write=None):
        lo, hi = addr, addr + size
        blobs = {'writes': []}

        def hw(uc, access, address, sz, value, user):
            if lo <= address < hi:
                blobs['writes'].append((address, value, sz))
                if on_write:
                    on_write(address, value, sz)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, hw)
        if on_read:
            def hr(uc, access, address, sz, value, user):
                if lo <= address < hi:
                    on_read(address, sz)
            self.mu.hook_add(UC_HOOK_MEM_READ, hr)
        return blobs['writes']

    def enable_tracing(self, asm=True, calls=False, strings=False):
        self.trace_instructions(asm)
        if calls:
            self.call_tree()
        if strings:
            self.collect_strings()
        return self

    # ---------------- syscall 拦截（按架构） ----------------
    def _install_syscall_hook(self):
        if self.arch_name == 'x86_64':
            reg_rax, reg_rdi, reg_rsi, reg_rdx = UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX
            SYS = {60: 'exit', 231: 'exit_group', 1: 'write', 0: 'read', 9: 'mmap', 12: 'brk',
                   228: 'clock_gettime', 35: 'nanosleep', 130: 'nanosleep', 7: 'poll'}
            insn_id = UC_X86_INS_SYSCALL
        else:
            reg_rax, reg_rdi, reg_rsi, reg_rdx = UC_ARM64_REG_X8, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
            SYS = {93: 'exit', 94: 'exit_group', 64: 'write', 63: 'read', 222: 'mmap', 214: 'brk',
                   113: 'clock_gettime', 101: 'nanosleep', 7: 'poll', 91: 'munmap'}
            insn_id = None  # ARM64 SVC 常量可能不存在；用 code hook 检测

        def do_syscall(uc):
            n = uc.reg_read(reg_rax)
            name = SYS.get(n)
            if name in ('exit', 'exit_group'):
                uc.emu_stop()
                self._notify_stop()
            elif name == 'write':
                fd = uc.reg_read(reg_rdi)
                buf = uc.reg_read(reg_rsi)
                cnt = uc.reg_read(reg_rdx)
                try:
                    data = self.read(buf, min(cnt, 4096))
                    if fd == 1 or fd == 2:
                        self._out(bytes(data).decode('utf-8', 'replace'))
                except Exception:
                    pass
                uc.reg_write(reg_rax, cnt)
            elif name == 'read':
                uc.reg_write(reg_rax, 0)
            elif name == 'mmap':
                uc.reg_write(reg_rax, 0x74000000)
            elif name == 'brk':
                uc.reg_write(reg_rax, self._heap_cur + 0x1000)
            elif name == 'clock_gettime':
                uc.reg_write(reg_rax, 0)
            elif name in ('nanosleep', 'poll'):
                uc.reg_write(reg_rax, 0)
            else:
                uc.reg_write(reg_rax, 0)

        if insn_id is not None:
            def h(uc, user):
                do_syscall(uc)
            self.mu.hook_add(UC_HOOK_INSN, h, None, 1, 0, insn_id)
        else:
            # ARM64: code hook 检测 svc 指令（0xD4000001 或 0xD4000000）
            def h2(uc, addr, size, user):
                try:
                    word = struct.unpack('<I', self.read(addr, 4))[0]
                    if (word & 0xFFE0001F) == 0xD4000001:
                        do_syscall(uc)
                except Exception:
                    pass
            self.mu.hook_add(UC_HOOK_CODE, h2)

    def _notify_stop(self):
        cb = getattr(self, '_on_stop', None)
        if cb:
            try:
                cb(self.pc())
            except Exception:
                pass

    # ---------------- 桩 ----------------
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

    # ---------- 桩实现（参数访问按架构） ----------
    def _arg(self, uc, idx):
        return uc.reg_read(self._REG[self.PARAM_REGS[idx]])

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
        self._out(s + '\n')
        return 0

    def _parse_fmt(self, fmt, args):
        out = []
        ai = 0
        i = 0
        while i < len(fmt):
            if fmt[i] == '%' and i + 1 < len(fmt):
                spec = fmt[i:i+2]
                if spec in ('%s', '%d', '%i', '%x', '%X', '%u', '%f', '%p', '%c', '%ld'):
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
        vals = []
        for i in range(1, 9):
            try:
                vals.append(self.read_ptr(self.mu.reg_read(self._REG[self.SP]) + i * 8))
            except Exception:
                break
        txt = self._parse_fmt(fmt, vals)
        self._out(txt)
        return len(txt)

    def _s_sprintf(self, uc):
        dst = self._arg(uc, 0)
        fmt = self.read_str(self._arg(uc, 1), 2048)
        vals = []
        for i in range(2, 9):
            try:
                vals.append(self.read_ptr(self.mu.reg_read(self._REG[self.SP]) + i * 8))
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


    # ---------------- v8: 代码清洗（函数重建）与扩展（项目导出） ----------------
    def _resolve_operand_refs(self, insn):
        """解析指令中的地址引用：返回注解字符串（符号名/字符串内容），无则 None"""
        import re as _re
        # capstone op_str 里形如 [rip + 0x1234] 的内存引用
        m = _re.search(r'\[rip \+ (0x[0-9a-f]+)\]|\[rip - (0x[0-9a-f]+)\]', insn.op_str)
        if m:
            disp = int(m.group(1) or m.group(2), 16)
            sign = 1 if m.group(1) else -1
            target = insn.address + insn.size + sign * disp
            # 字符串尝试
            try:
                b = self.read(target, 96)
                i = b.find(b'\x00')
                cand = (b[:i] if i != -1 else b[:48])
                if len(cand) >= 3 and all(32 <= c < 127 or c > 127 for c in cand[:16]):
                    txt = cand.decode('utf-8', 'replace')
                    if sum(c.isprintable() for c in txt) >= len(txt) * 0.7:
                        return f'; "{txt[:60]}"'
            except Exception:
                pass
            # 符号尝试 / 段归属
            sym = self.where(target)
            if not sym.startswith('0x'):
                return f'; {sym}'
            sec_name = None
            for sn, (sa, _o, ss, _t) in self.sections.items():
                if sa <= target < sa + ss:
                    sec_name = sn
                    break
            if sec_name:
                return f'; [{sec_name}+0x{target - self.sections[sec_name][0]:X}]'
            return f'; -> 0x{target:X}'
        # call/jmp 直接目标（x86: imm 操作数；arm64: bl 编码）
        if self.arch_name == 'x86_64':
            op_imm = globals().get('X86_OP_IMM')
            if insn.mnemonic in ('call', 'jmp') and insn.operands and op_imm and insn.operands[0].type == op_imm:
                t = insn.operands[0].imm
                sym = self.where(t)
                if not sym.startswith('0x'):
                    return f'; {sym}'
        else:
            try:
                code = self.read(insn.address, 4)
                is_call, target = self._is_call(code, insn.address)
                if (is_call or insn.mnemonic == 'b') and target:
                    sym = self.where(target)
                    if not sym.startswith('0x'):
                        return f'; {sym}'
            except Exception:
                pass
        return None

    def reconstruct_function(self, addr, max_insns=20000):
        """代码清洗：线性重建函数 → 带注释的反汇编（符号+字符串内联）
        返回 lines: [str]"""
        if not _HAS_CAPSTONE:
            raise RuntimeError('需要 capstone')
        if not hasattr(self, '_md'):
            self._md = Cs(CS_ARCH_X86, CS_MODE_64) if self.arch_name == 'x86_64' else Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self._md.detail = True

        out = []
        seen = set()
        ea = addr
        count = 0
        while count < max_insns:
            if ea in seen:
                break
            seen.add(ea)
            code = self.read(ea, 15 if self.arch_name == 'x86_64' else 4)
            insns = list(self._md.disasm(code, ea, count=1))
            if not insns:
                out.append(f'0x{ea:X}: <invalid>')
                break
            ins = insns[0]
            line = f'0x{ins.address:X}: {ins.mnemonic} {ins.op_str}'
            note = self._resolve_operand_refs(ins)
            if note:
                line += f'  {note}'
            out.append(line)
            if self._is_ret(code):
                out.append(f'0x{ea + ins.size:X}: <end of function>')
                break
            ea += ins.size
            count += 1
        header = f'; ===== function @ 0x{addr:X} ({self.where(addr)}) ====='
        return [header] + out

    def reconstruct_imports_header(self):
        """扩展：生成 C 外部声明骨架（全部导入函数）"""
        lines = ['// ---- imports (auto-generated by elf_sim) ----']
        for name in sorted(self.imports):
            lines.append(f'extern void* {name}(void);  // TODO: fix signature')
        return '\n'.join(lines)

    def generate_c_stub(self, func_addr, name=None):
        """扩展：为函数生成可编译 C 骨架（签名 + 调用/分支结构伪码）"""
        name = name or f'sub_{func_addr:X}'
        try:
            disasm = self.reconstruct_function(func_addr, max_insns=3000)
        except Exception as e:
            return f'// reconstruct failed: {e}'
        body = []
        body.append(f'// ===== reconstructed from 0x{func_addr:X} ({len(disasm)-1} insns) =====')
        body.append(f'void {name}(void) {{')
        depth = 0
        for line in disasm[1:]:
            low = line.lower()
            if low.endswith('<end of function>'):
                continue
            if ' call ' in line or '; ' in line:
                pass
            body.append('    // ' + line.replace('  ', ' '))
        body.append('}')
        return '\n'.join(body)

    def export_project(self, outdir, funcs=None):
        """扩展：导出清洗后的逆向工程目录
        - disasm/  每函数带注释汇编
        - stubs.c  可编译 C 骨架
        - imports.h 导入声明
        - trace.json 执行轨迹（若有）
        """
        import os
        os.makedirs(outdir, exist_ok=True)
        ddir = os.path.join(outdir, 'disasm')
        os.makedirs(ddir, exist_ok=True)

        if funcs is None:
            funcs = set()
            for _, t, _c in getattr(self, '_call_tree', []):
                funcs.add(t)
            if not funcs and '.text' in self.sections:
                text_lo = self.sections['.text'][0]
                text_hi = text_lo + self.sections['.text'][2]
                funcs = {self.entry} | {t for _d, t, _c in self._call_tree}
                funcs.add(text_hi)  # 占位避免空
        files = []
        for fa in sorted(funcs):
            try:
                lines = self.reconstruct_function(fa, max_insns=5000)
                fn = os.path.join(ddir, f'fn_{fa:X}.asm')
                open(fn, 'w', encoding='utf-8').write('\n'.join(lines))
                files.append(fn)
            except Exception:
                continue
        # imports.h
        ih = os.path.join(outdir, 'imports.h')
        open(ih, 'w', encoding='utf-8').write(self.reconstruct_imports_header())
        # stubs.c
        sc = os.path.join(outdir, 'stubs.c')
        stubs = ['#include "imports.h"', '// auto-generated skeletons']
        for fa in list(sorted(funcs))[:20]:
            stubs.append(self.generate_c_stub(fa, f'sub_{fa:X}'))
        open(sc, 'w', encoding='utf-8').write('\n\n'.join(stubs))
        # trace.json
        if self._instr_trace:
            tp = os.path.join(outdir, 'trace.json')
            json.dump(self._instr_trace, open(tp, 'w', encoding='utf-8'))
        meta = {
            'arch': self.arch_name,
            'entry': hex(self.entry),
            'imports': len(self.imports),
            'symbols': len(self.symbols),
            'functions_exported': len(files),
        }
        json.dump(meta, open(os.path.join(outdir, 'meta.json'), 'w', encoding='utf-8'), indent=1)
        return {'dir': outdir, 'functions': len(files), 'meta': meta}

if __name__ == '__main__':
    print('ElfSim v7 (双架构 x86_64/ARM64): from elf_sim import ElfSim')
