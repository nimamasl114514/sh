# -*- coding: utf-8 -*-
"""
pe_sim.py — Windows PE 模拟器 + 天堂之门运行时检测（elf_sim 家族）
v2 整理版：
- PE32 加载：节区按 VA 映射、导入表解析、IAT 全桩化（假页 ret + 名字拦截器）
- 韧性运行：CPU 异常自动跳过、中断掩码、零页兜底、TEB/PEB/FS 基址
- KCTF/MSVC 语义桩：gets_s/getchar(消费 stdin)/__stdio_common_vfprintf(格式化)/malloc/initterm 等
- 天堂之门：find_gates_static() 静态评分 + 运行时 hook（真实执行的 push 0x33 当场回调+寄存器现场）
"""
import struct
import re
import sys
import time
from unicorn import *
from unicorn.x86_const import *
import capstone as C

_HAS_CS = True


class PESim:
    def __init__(self, path):
        self.path = path
        self.data = open(path, 'rb').read()
        self._parse_pe()
        self._gate_hits = []
        self._imports_stub_map = {}        # fake_addr -> 'dll!func'
        self._imports_stub_map_reverse = {}
        self._stub_name_by_addr = {}
        self._kctf_hook_handlers = {}      # fake_addr -> handler(uc) -> rax
        self._gate_cb = None
        self._stdin_buf = bytearray()
        self._initterm_tables = []
        self._initterm_processed = False
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)

    # ================= PE 解析 =================
    def _parse_pe(self):
        d = self.data
        e = struct.unpack_from('<I', d, 0x3C)[0]
        assert d[e:e+4] == b'PE\0\0'
        self.machine = struct.unpack_from('<H', d, e+4)[0]
        nsec = struct.unpack_from('<H', d, e+6)[0]
        opt_size = struct.unpack_from('<H', d, e+20)[0]
        self.magic = struct.unpack_from('<H', d, e+24)[0]
        self.entry_rva = struct.unpack_from('<I', d, e+24+16)[0]
        self.image_base = struct.unpack_from('<I', d, e+24+28)[0] if self.magic == 0x10b else 0x400000
        self.size_of_image = struct.unpack_from('<I', d, e+24+56)[0]
        sec_off = e + 24 + opt_size
        self.sections = []
        for i in range(nsec):
            off = sec_off + i*40
            name = d[off:off+8].rstrip(b'\0').decode('latin1')
            vs, va, rs, ro = struct.unpack_from('<IIII', d, off+8)
            chars = struct.unpack_from('<I', d, off+36)[0]
            self.sections.append({'name': name, 'vsize': vs, 'va': va,
                                  'raw_size': rs, 'raw_off': ro, 'chars': chars})
        # 导入
        dd_off = e + 24 + 96
        imp_rva = struct.unpack_from('<I', d, dd_off + 8)[0]
        self.imports = {}
        self.iat = {}
        if imp_rva:
            o = self.rva2off(imp_rva)
            while o:
                oft, _ts, _fc, nameRVA, firstThunk = struct.unpack_from('<IIIII', d, o)
                if nameRVA == 0:
                    break
                no = self.rva2off(nameRVA)
                dll = d[no:d.index(b'\0', no)].decode('latin1') if no else '?'
                funcs = []
                t = self.rva2off(oft or firstThunk)
                idx = 0
                while t:
                    v = struct.unpack_from('<I', d, t + idx*4)[0]
                    if v == 0:
                        break
                    if v & 0x80000000:
                        fname = f'#{v & 0xFFFF}'
                    else:
                        ho = self.rva2off(v)
                        fname = d[ho+2:d.index(b'\0', ho+2)].decode('latin1')
                    funcs.append(fname)
                    self.iat[f'{dll}!{fname}'] = self.image_base + firstThunk + idx*4
                    idx += 1
                self.imports[dll] = funcs
                o += 20

    def rva2off(self, rva):
        for s in self.sections:
            if s['va'] <= rva < s['va'] + max(s['vsize'], s['raw_size']):
                return s['raw_off'] + (rva - s['va'])
        return None

    def off2va(self, off):
        t = next((s for s in self.sections if s['name'] == '.text'), None)
        if t and t['raw_off'] <= off < t['raw_off'] + max(t['raw_size'], 1):
            return self.image_base + t['va'] + (off - t['raw_off'])
        for s in self.sections:
            if s['raw_off'] <= off < s['raw_off'] + max(s['raw_size'], 1):
                return self.image_base + s['va'] + (off - s['raw_off'])
        return self.image_base + off

    # ================= 内存映射 =================
    def map_image(self):
        if getattr(self, '_mapped', False):
            return
        self._mapped = True
        mu = self.mu
        base = self.image_base
        img_end = (base + self.size_of_image + 0xFFF) & ~0xFFF
        mu.mem_map(base, img_end - base)
        mu.mem_write(base, self.data[:min(self.sections[0]['va'], 0x1000)])
        for s in self.sections:
            if s['raw_size']:
                mu.mem_write(base + s['va'],
                             self.data[s['raw_off']:s['raw_off'] + s['raw_size']])
        # 假导入桩页
        self.FAKE_BASE = 0xF7000000
        mu.mem_map(self.FAKE_BASE, 0x100000)
        for i, (_full, slot) in enumerate(self.iat.items()):
            fake = self.FAKE_BASE + i * 4
            mu.mem_write(fake, b'\xc3')          # ret
            mu.mem_write(slot, struct.pack('<I', fake))
            self._imports_stub_map[fake] = list(self.iat.keys())[i]
        # 栈
        self.STACK = 0x20000000
        mu.mem_map(self.STACK, 0x400000)
        mu.reg_write(UC_X86_REG_ESP, self.STACK + 0x200000)
        mu.reg_write(UC_X86_REG_EBP, self.STACK + 0x200000)
        # TEB/PEB
        self.TEB = 0x7FFDE000
        self.PEB = 0x7FFDF000
        try:
            mu.mem_map(self.TEB, 0x1000)
            mu.mem_map(self.PEB, 0x1000)
        except UcError:
            pass
        mu.mem_write(self.TEB + 0x18, struct.pack('<I', self.TEB))
        mu.mem_write(self.TEB + 0x30, struct.pack('<I', self.PEB))
        try:
            mu.reg_write(UC_X86_REG_FS_BASE, self.TEB)
        except Exception:
            pass
        self._setup_common_hooks()

    # ================= 公共钩子 =================
    def _setup_common_hooks(self):
        # 零页兜底
        def hzf(uc, access, address, size, value, user):
            page = address & ~0xFFF
            try:
                uc.mem_map(page, 0x1000)
                self.log(f'[zerofill] 0x{page:X}')
                return True
            except UcError:
                return False
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, hzf)

        # 中断处理：int3 -> MSVC SEH 链模拟（int3 是混淆/验证跳板）
        def hintr(uc, intno, user):
            if intno == 3:  # INT3 -> SEH
                self._seh_dispatch(uc)
            else:
                self.log(f'[intr] #{intno:x} masked @ {hex(uc.reg_read(UC_X86_REG_EIP))}')
        self.mu.hook_add(UC_HOOK_INTR, hintr)

        # 导入假桩拦截 + API 日志
        def himp(uc, addr, size, user):
            name = self._imports_stub_map.get(addr)
            if name:
                rax = 0
                hdl = self._kctf_hook_handlers.get(addr)
                if hdl:
                    try:
                        rax = hdl(uc) or 0
                    except Exception as ex:
                        self.log(f'[stub err {name}] {ex}')
                        rax = 0
                uc.reg_write(UC_X86_REG_EAX, rax & 0xFFFFFFFF)
                self.log(f'[api] {name} -> {rax:#x}')
        self.mu.hook_add(UC_HOOK_CODE, himp)

        # 运行时门检测（push 0x33 + 变体 retf/iretd 执行时点）
        def hgate(uc, addr, size, user):
            try:
                b = bytes(uc.mem_read(addr, 2))
                if b == b'\x6a\x33':
                    rec = {'va': addr, 'type': 'push0x33'}
                    ctx = {r: hex(uc.reg_read(getattr(__import__('unicorn.x86_const', fromlist=['X']),
                                           f'UC_X86_REG_{r.upper()}'))) for r in ('eax','ebx','ecx','edx','esi','edi','esp','ebp')}
                    rec['regs'] = ctx
                    self._gate_hits.append(rec)
                    self.log(f'*** GATE(push0x33) @ 0x{addr:X}')
                    if self._gate_cb:
                        self._gate_cb(addr)
                elif b[0] in (0xCB, 0xCF):  # retf / iretd
                    rec = {'va': addr, 'type': 'retf' if b[0] == 0xCB else 'iretd'}
                    ctx = {r: hex(uc.reg_read(getattr(__import__('unicorn.x86_const', fromlist=['X']),
                                           f'UC_X86_REG_{r.upper()}'))) for r in ('eax','ebx','ecx','edx','esi','edi','esp','ebp')}
                    rec['regs'] = ctx
                    # 栈顶（retf 目标 = new CS:new EIP）
                    try:
                        esp = uc.reg_read(UC_X86_REG_ESP)
                        tgt = struct.unpack('<II', bytes(uc.mem_read(esp, 8)))
                        rec['retf_target'] = [hex(t) for t in tgt]
                    except Exception:
                        pass
                    self._gate_hits.append(rec)
                    self.log(f'*** RETF/IRETD @ 0x{addr:X} -> CS:EIP {rec.get("retf_target", "?")}')
                    if self._gate_cb:
                        self._gate_cb(addr)
            except Exception:
                pass
        self.mu.hook_add(UC_HOOK_CODE, hgate)

    def on_gate(self, cb):
        self._gate_cb = cb

    def set_log(self, path):
        self._log_file = open(path, 'w', encoding='utf-8')

    def log(self, msg):
        f = getattr(self, '_log_file', None)
        if f:
            f.write(msg + '\n')
            f.flush()

    def _out(self, text):
        sys.stdout.write(text)
        sys.stdout.flush()

    # ================= 执行 =================
    def entry_va(self):
        return self.image_base + self.entry_rva

    SKIP_MAX = 3000

    def run_resilient(self, start, count=3*10**6):
        """CPU 异常自动跳过的执行循环"""
        md = C.Cs(C.CS_ARCH_X86, C.CS_MODE_32) if not hasattr(self, '_cmd') else self._cmd
        if not hasattr(self, '_cmd'):
            self._cmd = md
        skips = 0
        cur = start
        remaining = count
        while True:
            try:
                self.mu.emu_start(cur, 0, count=remaining, timeout=60*10**9)
                return 'done', self.mu.reg_read(UC_X86_REG_EIP)
            except UcError as err:
                if err.errno != 21:  # UC_ERR_EXCEPTION
                    return f'fatal({err.errno})', self.mu.reg_read(UC_X86_REG_EIP)
                eip = self.mu.reg_read(UC_X86_REG_EIP)
                skipped_len = 1
                try:
                    code = self.read(eip, 16)
                    for i in md.disasm(code, eip, count=1):
                        skipped_len = i.size
                        self.log(f'[skip] {eip:X}: {i.mnemonic} {i.op_str}')
                        break
                except Exception:
                    pass
                cur = eip + skipped_len
                remaining = max(remaining - 50, 10000)
                skips += 1
                if skips > self.SKIP_MAX:
                    return 'skip-limit', eip
                continue

    def run_entry(self, max_steps=3*10**6, test_key=None):
        self.map_image()
        status, pc = self.run_resilient(self.entry_va(), max_steps)
        self.last_status = (status, hex(pc))
        return pc

    # ================= 天堂之门静态 =================
    def find_gates_static(self):
        hits = []
        st = 0
        pat = b'\x6a\x33'
        while True:
            i = self.data.find(pat, st)
            if i == -1:
                break
            seg = self.data[i:i + 48]
            score = 0
            if b'\xcb' in seg:
                score += 2
            if b'\xcf' in seg:
                score += 1
            if re.search(rb'\xe8[\s\S]{4}', seg[:12]):
                score += 1
            va = self.off2va(i)
            hits.append((score, i, va))
            st = i + 1
        hits.sort(key=lambda x: -x[0])
        return hits

    @property
    def gate_hits(self):
        return self._gate_hits

    # ================= KCTF/MSVC 语义桩 =================
    def _seh_dispatch(self, uc):
        """MSVC SEH v1：int3 触发 -> 走 fs:[0] 注册链 -> 调用 handler
        传 4 参 (EXCEPTION_RECORD*, ER*, CONTEXT*, disp)；返回 eax==-1 续执行/1 执行处理器"""
        try:
            teb = self.TEB
            er = struct.unpack('<I', self.read(teb, 4))[0]  # fs:[0] = ExceptionList
            int3_eip = uc.reg_read(UC_X86_REG_EIP)
            if er == 0 or er == 0xFFFFFFFF:
                self.log(f'[seh] int3@{hex(int3_eip)} no handler, skip')
                # 跳过 int3（1 字节）
                uc.reg_write(UC_X86_REG_EIP, int3_eip + 1)
                return
            prev = struct.unpack('<I', self.read(er, 4))[0]
            handler = struct.unpack('<I', self.read(er + 4, 4))[0]
            # EXCEPTION_RECORD 构造（堆）
            rec = 0x74000000
            try:
                self.mu.mem_map(rec, 0x10000)
            except UcError:
                pass
            self.write_mem(rec, struct.pack('<IIIIIII', 0x80000003, 0, 0, int3_eip, 0, 0, 0))
            ctx = rec + 0x100  # 伪 CONTEXT
            self.mu.mem_write(ctx, b'\x00' * 0x100)
            # 压 4 参
            esp = uc.reg_read(UC_X86_REG_ESP)
            esp -= 16
            self.mu.mem_write(esp, struct.pack('<IIII', 0, ctx, er, rec))
            uc.reg_write(UC_X86_REG_ESP, esp)
            uc.reg_write(UC_X86_REG_EIP, handler)
            self.log(f'[seh] int3@{hex(int3_eip)} -> handler@{hex(handler)} (er={hex(er)} prev={hex(prev)})')
        except Exception as ex:
            self.log(f'[seh err] {ex}')
            uc.reg_write(UC_X86_REG_EIP, uc.reg_read(UC_X86_REG_EIP) + 1)

    def init_seh(self):
        """在栈上预置一个默认 SEH 链（fs:[0]）——通常程序自己建立，这里兜底"""
        try:
            teb = self.TEB
            cur = struct.unpack('<I', self.read(teb, 4))[0]
            if cur == 0:
                self.log('[seh] fs:[0] 未设置')
        except Exception:
            pass
    def read(self, addr, size):
        r = self.mu.mem_read(addr, size)
        return bytes(r) if isinstance(r, list) else r

    def read_str(self, addr, maxlen=256):
        b = self.read(addr, maxlen)
        i = b.find(b'\x00')
        return (b[:i] if i != -1 else b).decode('utf-8', 'replace')

    def write_mem(self, addr, data):
        if isinstance(data, str):
            data = data.encode()
        self.mu.mem_write(addr, data)

    def write_ptr(self, addr, value):
        self.mu.mem_write(addr, struct.pack('<I', value))

    def _arg32(self, uc, idx):
        esp = uc.reg_read(UC_X86_REG_ESP)
        return struct.unpack_from('<I', self.read(esp + 4 + idx * 4, 4))[0]


    def set_stdin(self, data):
        self._stdin_buf = bytearray(data)

    def _stdin_pop_line(self):
        buf = getattr(self, '_stdin_buf', bytearray())
        if b'\n' in buf:
            i = buf.index(b'\n')
            line = bytes(buf[:i]); del buf[:i+1]
        elif buf:
            line = bytes(buf); del buf[:]
        else:
            line = b''
        return line

    def install_kctf_stubs(self, test_key=b'TEST-KEY-1234'):
        """KCTF/MSVC 语义桩（需在 map_image 后调用）"""
        self.set_stdin(test_key + b'\n')
        self.IOB_BASE = 0xF8000000
        try:
            self.mu.mem_map(self.IOB_BASE, 0x10000)
        except UcError:
            pass
        self.HEAPB = 0x30000000
        try:
            self.mu.mem_map(self.HEAPB, 0x400000)
        except UcError:
            pass
        self._heap_cur2 = self.HEAPB

        def h_vfprintf(uc):
            esp = uc.reg_read(UC_X86_REG_ESP)
            fmt_ptr, va_ptr = struct.unpack_from('<II', self.read(esp + 12, 8))
            fmt = self.read_str(fmt_ptr, 1024)
            try:
                vals = list(struct.unpack('<8I', self.read(va_ptr, 32)))
            except Exception:
                vals = []
            txt = self._fmt_from(fmt, vals)
            self._out(txt)
            return len(txt)

        handlers = {
            '__acrt_iob_func': lambda uc: self.IOB_BASE + (self._arg32(uc, 0) & 0xFF) * 0x30,
            '__stdio_common_vfprintf': h_vfprintf,
            'gets_s': self._s_gets_s,
            'getchar': self._s_getchar,
            '_initterm': self._s_initterm,
            '_initterm_e': self._s_initterm_e,
            'IsDebuggerPresent': lambda uc: 0,
            'SetUnhandledExceptionFilter': lambda uc: 1,
            '_configure_narrow_argv': lambda uc: 0,
            '_initialize_narrow_environment': lambda uc: 0,
            '_initialize_onexit_table': lambda uc: 0,
            '_register_onexit_function': lambda uc: 0,
            '_register_thread_local_exe_atexit_callback': lambda uc: 0,
            '_crt_atexit': lambda uc: 0,
            '_controlfp_s': lambda uc: 0,
            '__setusermatherr': lambda uc: 0,
            '_configthreadlocale': lambda uc: 0,
            '_set_fmode': lambda uc: 0,
            '__p__commode': lambda uc: 0x700A0000,
            '__p___argc': lambda uc: 0x700A1000,
            '__p___argv': lambda uc: 0x700A2000,
            '_set_new_mode': lambda uc: 0,
            '_invalid_parameter_noinfo_noreturn': lambda uc: 0,
            '_exit': lambda uc: (uc.emu_stop(), 0)[1],
            'exit': lambda uc: (uc.emu_stop(), 0)[1],
            '_c_exit': lambda uc: (uc.emu_stop(), 0)[1],
            '_cexit': lambda uc: 0,
            'terminate': lambda uc: (uc.emu_stop(), 0)[1],
            'malloc': self._s_malloc32,
            'free': lambda uc: 0,
            '_callnewh': lambda uc: 0,
            'GetTickCount': lambda uc: 0x12345678,
            'QueryPerformanceCounter': lambda uc: self._qpc(uc),
            'GetSystemTimeAsFileTime': lambda uc: 0,
            'GetCurrentProcessId': lambda uc: 1234,
            'GetCurrentThreadId': lambda uc: 5678,
            'IsProcessorFeaturePresent': lambda uc: 0,
            'InitializeSListHead': lambda uc: 0,
            'GetModuleHandleW': lambda uc: 0x400000,
            'UnhandledExceptionFilter': lambda uc: 1,
            'TerminateProcess': lambda uc: (uc.emu_stop(), 0)[1],
            'GetCurrentProcess': lambda uc: 0xFFFF0001,
            '_except_handler4_common': lambda uc: 0,
            '__current_exception': lambda uc: 0x700B0000,
            '__current_exception_context': lambda uc: 0x700B1000,
            '__std_exception_copy': lambda uc: 0,
            '__std_exception_destroy': lambda uc: 0,
            '__CxxFrameHandler3': lambda uc: 1,
            '_CxxThrowException': lambda uc: (self.log('[CxxThrow masked]'), 0)[1],
            'memcpy': self._s_memcpy32,
            'memset': self._s_memset32,
            'memmove': self._s_memcpy32,
        }
        n = 0
        for name, h in handlers.items():
            matched = [(full, slot) for full, slot in self.iat.items() if full.endswith('!' + name)]
            for full, slot in matched:
                raw = self.mu.mem_read(slot, 4)
                fake = struct.unpack('<I', bytes(raw) if isinstance(raw, list) else raw)[0]
                self._imports_stub_map_reverse[fake] = full
                self._kctf_hook_handlers[fake] = h
                n += 1
        print(f'[stub] kctf handlers hooked: {n}/{len(handlers)}')

    def _s_initterm(self, uc):
        """捕获初始化表 [begin,end)，返回 0（稍后手工执行）"""
        if not self._initterm_processed:
            begin = self._arg32(uc, 0)
            end = self._arg32(uc, 1)
            self._initterm_tables.append((begin, end))
            self.log(f'[initterm] table {hex(begin)}..{hex(end)}')
        return 0

    def _s_initterm_e(self, uc):
        begin = self._arg32(uc, 0)
        end = self._arg32(uc, 1)
        if not self._initterm_processed:
            self._initterm_tables.append((begin, end))
        return 0

    def process_initterm_tables(self, max_each=500000):
        """手工执行全部初始化器（在第一次 run 后调用，然后重跑 entry）"""
        done = 0
        for begin, end in self._initterm_tables:
            ptr = begin
            while ptr < end:
                fn = struct.unpack('<I', self.read(ptr, 4))[0]
                ptr += 4
                if fn == 0:
                    continue
                if not (self.image_base <= fn < self.image_base + self.size_of_image):
                    self.log(f'[initterm skip] fn 0x{fn:X} 区外')
                    continue
                self.log(f'[initterm call] 0x{fn:X}')
                try:
                    self.run_resilient(fn, max_each)
                except Exception as ex:
                    self.log(f'[initterm err 0x{fn:X}] {ex}')
                done += 1
        self._initterm_processed = True
        self.log(f'[initterm] 执行 {done} 个初始化器')
        return done

        esp = uc.reg_read(UC_X86_REG_ESP)
        return struct.unpack_from('<I', self.read(esp + 4 + idx * 4, 4))[0]

    def _s_gets_s(self, uc):
        buf = self._arg32(uc, 0)
        line = self._stdin_pop_line()
        self.write_mem(buf, line + b'\x00')
        self.log(f'[gets_s] -> {line!r}')
        return buf

    def _s_getchar(self, uc):
        b = getattr(self, '_stdin_buf', bytearray())
        if b:
            return b.pop(0)
        return 0xFFFFFFFF

    def _s_malloc32(self, uc):
        size = self._arg32(uc, 0)
        sz = max((size + 15) & ~15, 16)
        p = self._heap_cur2
        self._heap_cur2 += sz
        return p + 8

    def _s_memcpy32(self, uc):
        dst, src, n = self._arg32(uc, 0), self._arg32(uc, 1), self._arg32(uc, 2)
        if n < 0x1000000:
            self.write_mem(dst, self.read(src, n))
        return dst

    def _s_memset32(self, uc):
        dst, c, n = self._arg32(uc, 0), self._arg32(uc, 1) & 0xFF, self._arg32(uc, 2)
        if n < 0x1000000:
            self.write_mem(dst, bytes([c]) * n)
        return dst

    def _qpc(self, uc):
        self.write_mem(self._arg32(uc, 0), struct.pack('<Q', 100000))
        return 1

    def _fmt_from(self, fmt, vals):
        out = []; ai = 0; i = 0
        while i < len(fmt):
            if fmt[i] == '%' and i + 1 < len(fmt):
                spec = fmt[i:i+2]
                if spec == '%s':
                    try:
                        out.append(self.read_str(vals[ai], 512))
                    except Exception:
                        out.append('(str)')
                    ai += 1
                elif spec in ('%d', '%i'):
                    out.append(str(vals[ai])); ai += 1
                elif spec in ('%x', '%X', '%p'):
                    out.append(hex(vals[ai])); ai += 1
                elif spec == '%c':
                    out.append(chr(vals[ai] & 0xFF)); ai += 1
                else:
                    out.append(spec)
                i += 2
            else:
                out.append(fmt[i]); i += 1
        return ''.join(out)


if __name__ == '__main__':
    print('PESim v2: from pe_sim import PESim; sim.install_kctf_stubs(key)')
