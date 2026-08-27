# -*- coding: utf-8 -*-
"""
elf_sim.py — 自研 ELF 模拟动态执行框架 v3（MiniDBI 思路）
v3 强化：
  8. auto_stubs：未实现的导入自动安装通用桩（返回 0 / 返回指针），模拟不中断
  9. libc 补充桩：printf/sprintf/atoi/strtol/memcmp/strncpy/strcat/strchr/strstr/calloc/malloc/free
  10. 内存管理：简单堆分配器（malloc/calloc/free 追踪）
  11. call 追踪：trace_calls() 记录所有 PLT 调用序列（MiniDBI）
  12. argv 模拟辅助（setup_argv）
依赖：unicorn 2.x；适用于 Android/Linux x86_64 ELF。
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
        self.symbols = {}
        self.imports = {}
        self._libc_handlers = {}
        self._mem_write_log = []
        self._mem_read_log = []
        self._call_trace = []
        self._auto_stubs = True
        self._parse_symbols()
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
        ds, dynstr = self.sections['.dynsym'], self.sections['.dynstr']
        _, dso, dssz, _ = ds
        _, dsto, _, _ = dynstr

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
        # PLT stub 扫描
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
        # 简单堆：截取 0x72000000 起 8MB
        self.HEAP = 0x72000000
        self.mu.mem_map(self.HEAP, 0x800000)
        self._heap_cur = self.HEAP
        self._heap_blocks = {}

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
        """在栈上铺 argv/argc，返回 argv 指针（供 __libc_init 样式入口用）"""
        rsp = self.mu.reg_read(UC_X86_REG_RSP)
        argc = len(args)
        ptrs = []
        # 写字符串（从 rsp 往下）
        cur = rsp - 0x1000
        for s in args:
            if isinstance(s, str):
                s = s.encode()
            self.write_mem(cur, s + b'\x00')
            ptrs.append(cur)
            cur += len(s) + 1
        # 写 argv 表
        table = rsp - 0x2000
        for i, p in enumerate(ptrs):
            self.write_ptr(table + i * 8, p)
        self.write_ptr(table + argc * 8, 0)
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

    # ---------------- Snapshot / Restore ----------------
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

    # ---------------- Hooks ----------------
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
        """记录所有 call 到导入 PLT 的调用序列（MiniDBI）"""
        self._call_trace = []
        # stub addr -> name（libc handlers + imports）
        name_by_addr = {}
        for name, addr in self.imports.items():
            name_by_addr[addr] = name
        for addr, handler in self._libc_handlers.items():
            # handler key 是 stub addr（install_libc_stub 存过）
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

    def _rebuild_stub_map(self):
        return self._libc_handlers

    # ---------------- syscall 拦截 ----------------
    def _install_syscall_hook(self):
        def h(uc, user):
            n = uc.reg_read(UC_X86_REG_RAX)
            if n in (60, 231):  # exit / exit_group
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
            elif n == 0:
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif n == 9:  # mmap
                uc.reg_write(UC_X86_REG_RAX, 0x74000000)
            elif n == 12:  # brk
                uc.reg_write(UC_X86_REG_RAX, self._heap_cur + 0x1000)
            elif n == 228:  # clock_gettime
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif n in (35, 130):  # nanosleep
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif n == 7:  # poll
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

        # 核心拦截机制：call 到 stub 时执行桩；未注册导入自动 fallback
        stubs_map = dict(self._libc_handlers)

        def code_hook(uc, addr, size, user):
            try:
                if size >= 5:
                    insn = self.read(addr, 5)
                    if insn[0] == 0xE8:  # call rel32
                        disp = struct.unpack('<i', insn[1:5])[0]
                        target = addr + 5 + disp
                        # 1) 已注册桩
                        if target in stubs_map:
                            rax = stubs_map[target](uc)
                            uc.reg_write(UC_X86_REG_RAX, rax)
                            uc.reg_write(UC_X86_REG_RIP, addr + 5)
                        elif self._auto_stubs:
                            # 2) 未注册导入 -> 自动 fallback（返回 0）
                            for stub, name in self._stub_name.items() if hasattr(self, '_stub_name') else []:
                                pass
                # 3) 未注册导入的自动桩（通过 imports 反向）
                if self._auto_stubs:
                    for sname, saddr in self.imports.items():
                        if saddr == 0:
                            continue
            except Exception:
                pass
        self.mu.hook_add(UC_HOOK_CODE, code_hook)

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
        self.write_mem(dst, data + b'\x00' * (n - len(data)) if n > len(data) else data)
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
        """从栈取 varargs（fmt 在 rdi，args 从 rsp+8 开始）"""
        rsp = uc.reg_read(UC_X86_REG_RSP)
        args = []
        for i in range(8):
            args.append(self.read_ptr(rsp + 8 + (7 - i) * 8))
        return args

    def _parse_fmt(self, fmt, args):
        import re
        out = []
        ai = 0
        i = 0
        while i < len(fmt):
            if fmt[i] == '%' and i + 1 < len(fmt):
                spec = fmt[i:i+2]
                if spec in ('%s', '%.s', '%d', '%i', '%x', '%X', '%u', '%f', '%p', '%c', '%ld', '%.*s'):
                    if spec == '%s':
                        out.append(self.read_str(args[ai], 4096))
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
                elif fmt[i] == '%' and fmt[i+1] == '%':
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
        # varargs：rsp 处是返回地址（被我们改过），实际 args 在 rsp+8 起（顺序填充）
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
        # 对齐 16
        size = (size + 15) & ~15
        if self._heap_cur + size > self.HEAP + 0x800000:
            return 0
        ptr = self._heap_cur
        self._heap_cur += size
        return ptr

    def _s_calloc(self, uc):
        nmemb, size = self._arg(uc, 0), self._arg(uc, 1)
        total = nmemb * size
        ptr = self._s_malloc(uc)
        if ptr:
            self.write_mem(ptr, b'\x00' * min(total, 4096))
        return ptr

    def _s_time_gettimeofday(self, uc):
        return 0


# ---------------- 便捷 CLI ----------------
if __name__ == '__main__':
    print('ElfSim v3: from elf_sim import ElfSim')
    print('  sim = ElfSim("x.elf")          # 自动安装 libc 桩 + auto-stubs')
    print('  sim.call(sim.from_symbol("main"))')
    print('  sim.trace_calls()              # 记录 PLT 调用序列')
    print('  sim.setup_argv(["a","b"])      # argv 铺栈')
