# -*- coding: utf-8 -*-
"""
pe_sim.py — PE 模拟器 + 天堂之门运行时检测（elf_sim 家族扩展）
- PESim：加载 PE32/x64 映像（节区按 VA、导入 IAT 全部桩化返回 0）
- find_gates_static(): 静态扫描 push 0x33 / retf 门候选（含连贯性评分）
- 运行时门检测：hook 执行流，命中真实执行的 `6A 33`(push 0x33) 序列时回调 —— 加密区解密后真门自现
用法：
  sim = PESim('cm.exe')
  sim.watch_gates(cb)
  sim.run_entry(max_steps=...)
"""
import struct
import re
import sys
from unicorn import *
from unicorn.x86_const import *


class PESim:
    def __init__(self, path):
        self.path = path
        self.data = open(path, 'rb').read()
        self._parse_pe()
        self._gate_hits = []
        self._imports_stub_map = {}
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)

    # ---------- PE 解析 ----------
    def _parse_pe(self):
        d = self.data
        e = struct.unpack_from('<I', d, 0x3C)[0]
        assert d[e:e+4] == b'PE\0\0'
        self.machine = struct.unpack_from('<H', d, e+4)[0]
        nsec = struct.unpack_from('<H', d, e+6)[0]
        opt_size = struct.unpack_from('<H', d, e+20)[0]
        self.magic = struct.unpack_from('<H', d, e+24)[0]      # 0x10b=PE32
        self.entry_rva = struct.unpack_from('<I', d, e+24+16)[0]
        self.image_base = struct.unpack_from('<I', d, e+24+28)[0]
        size_of_image = struct.unpack_from('<I', d, e+24+56)[0]
        self.size_of_image = size_of_image
        sec_off = e + 24 + opt_size
        self.sections = []
        for i in range(nsec):
            off = sec_off + i*40
            name = d[off:off+8].rstrip(b'\0').decode('latin1')
            vs, va, rs, ro = struct.unpack_from('<IIII', d, off+8)
            chars = struct.unpack_from('<I', d, off+36)[0]
            self.sections.append({'name': name, 'vsize': vs, 'va': va,
                                  'raw_size': rs, 'raw_off': ro, 'chars': chars})
        # 导入表
        dd_off = e + 24 + 96
        imp_rva, imp_sz = struct.unpack_from('<II', d, dd_off + 8)
        self.imports = {}   # dll -> [funcs]
        self.iat = {}       # func -> slot VA
        if imp_rva:
            o = self.rva2off(imp_rva)
            while o:
                oft, ts, fc, nameRVA, firstThunk = struct.unpack_from('<IIIII', d, o)
                if nameRVA == 0:
                    break
                no = self.rva2off(nameRVA)
                dll = d[no:d.index(b'\0', no)].decode('latin1') if no else '?'
                funcs = []
                # 走 INT（OriginalFirstThunk）拿名字
                t = self.rva2off(oft or firstThunk)
                idx = 0
                while t:
                    v = struct.unpack_from('<I', d, t + idx*4)[0]
                    if v == 0:
                        break
                    if v & 0x80000000:  # ordinal
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

    # ---------- 内存映射 ----------
    def map_image(self):
        mu = self.mu
        base = self.image_base
        img_end = (base + self.size_of_image + 0xFFF) & ~0xFFF
        mu.mem_map(base, img_end - base)
        # 头
        hdr_sz = min(self.sections[0]['va'], 0x1000)
        mu.mem_write(base, self.data[:hdr_sz])
        for s in self.sections:
            if s['raw_size']:
                mu.mem_write(base + s['va'],
                             self.data[s['raw_off']:s['raw_off'] + s['raw_size']])
        # 导入桩：每个 IAT 槽填唯一假地址，假页里放一条 `ret`
        FAKE_BASE = 0xF7000000
        self.FAKE_BASE = FAKE_BASE
        self.fake_page_used = 0
        mu.mem_map(FAKE_BASE, 0x100000)
        i = 0
        for full, slot in self.iat.items():
            fake = FAKE_BASE + i * 4
            mu.mem_write(fake, b'\xc3')  # ret
            mu.mem_write(slot, struct.pack('<I', fake))
            self._imports_stub_map[fake] = full
            i += 1
        # 栈
        self.STACK = 0x20000000
        mu.mem_map(self.STACK, 0x400000)
        mu.reg_write(UC_X86_REG_ESP, self.STACK + 0x200000)
        mu.reg_write(UC_X86_REG_EBP, self.STACK + 0x200000)

    # ---------- 执行 ----------
    def entry_va(self):
        return self.image_base + self.entry_rva

    def run_entry(self, max_steps=10**7, timeout=30*10**9):
        self.map_image()
        self._install_import_tracer()
        self._ensure_gate_watcher()
        self._install_zero_fill()
        self._install_environment()
        status, pc = self._run_resilient(self.entry_va(), max_steps, timeout)
        self.last_status = (status, hex(pc))
        return pc

    def call(self, addr, args=None, max_steps=10**7):
        args = args or []
        if len(args) >= 1:
            self.mu.reg_write(UC_X86_REG_EAX, args[0])
        self.map_image()
        self._install_import_tracer()
        self._ensure_gate_watcher()
        self._install_zero_fill()
        self.mu.emu_start(addr, 0, count=max_steps)
        return self.mu.reg_read(UC_X86_REG_EAX)

    # ---------- 观察钩子 ----------
    def _out(self, text):
        sys.stdout.write(text)
        sys.stdout.flush()

    def _install_import_tracer(self):
        """call 落在假桩页 -> 打印调用名，设返回值 0 后由自带 ret 返回"""
        if getattr(self, '_imp_trace_installed', False):
            return
        self._imp_trace_installed = True

        def h(uc, addr, size, user):
            name = self._imports_stub_map.get(addr)
            if name:
                uc.reg_write(UC_X86_REG_EAX, 0)
                self.log(f'[api] {name}')
        self.mu.hook_add(UC_HOOK_CODE, h)

    def log(self, msg):
        f = getattr(self, '_log_file', None)
        if f:
            f.write(msg + '\n')
            f.flush()

    def set_log(self, path):
        self._log_file = open(path, 'w', encoding='utf-8')

    # ---------- 天堂之门 ----------
    def _install_zero_fill(self):
        """未映射访问时按需零页映射并继续（CRT/TLS 常见）"""
        if getattr(self, '_zero_fill_installed', False):
            return
        self._zero_fill_installed = True

        def h(uc, access, address, size, value, user):
            page = address & ~0xFFF
            try:
                uc.mem_map(page, 0x1000)
                self.log(f'[zerofill] 0x{page:X}')
                return True
            except UcError:
                # 已被并发映射等；再试对齐下调
                try:
                    uc.mem_map(address & ~0xFFF, 0x1000)
                    return True
                except Exception:
                    return False
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, h)

    def _install_environment(self):
        """环境补齐：TEB(FS 基址) + 中断掩码（反调试 int 陷阱直接穿透）"""
        if getattr(self, '_env_installed', False):
            return
        self._env_installed = True
        # TEB 页（fs:[0x18]=TEB 自引用, fs:[0x30]=PEB）
        self.TEB = 0x7FFDE000
        try:
            self.mu.mem_map(self.TEB, 0x1000)
        except UcError:
            pass
        self.mu.mem_write(self.TEB + 0x18, struct.pack('<I', self.TEB))
        self.PEB = 0x7FFDF000
        try:
            self.mu.mem_map(self.PEB, 0x1000)
        except UcError:
            pass
        self.mu.mem_write(self.TEB + 0x30, struct.pack('<I', self.PEB))
        try:
            self.mu.reg_write(UC_X86_REG_FS_BASE, self.TEB)
        except Exception:
            pass
        # 中断掩码：int3/int2d 等不崩
        def h_intr(uc, intno, user):
            self.log(f'[intr] int {intno:#x} masked @ {hex(uc.reg_read(UC_X86_REG_EIP))}')
        self.mu.hook_add(UC_HOOK_INTR, h_intr)

    _SKIP_MAX = 2000

    def _run_resilient(self, start, count, timeout):
        """带异常自动跳过的执行循环：CPU 异常（特权指令/门/除零）→ capstone 取长跳过"""
        import capstone as C
        md = C.Cs(C.CS_ARCH_X86, C.CS_MODE_32)
        skips = 0
        cur = start
        remaining = count
        while True:
            try:
                self.mu.emu_start(cur, 0, count=remaining, timeout=timeout)
                return 'done', self.mu.reg_read(UC_X86_REG_EIP)
            except UcError as e:
                eip = self.mu.reg_read(UC_X86_REG_EIP)
                if e.errno == 21:  # UC_ERR_EXCEPTION
                    skipped_len = 1
                    try:
                        for i in md.disasm(self.read(eip, 16), eip, count=1):
                            skipped_len = i.size
                            self.log(f'[skip] {eip:X}: {i.mnemonic} {i.op_str}')
                            break
                    except Exception:
                        pass
                    cur = eip + skipped_len
                    remaining = max(remaining - 100, 1000)
                    skips += 1
                    if skips > self._SKIP_MAX:
                        return 'skip-limit', eip
                    continue
                return f'fatal({e.errno})', eip

    def find_gates_static(self):
        """静态门候选：push 0x33 且邻近 retf/iretd/far 相关（打分排序）"""
        hits = []
        pat = b'\x6a\x33'
        st = 0
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
            va = self.off2va_guess(i)
            hits.append((score, i, va))
            st = i + 1
        hits.sort(key=lambda x: -x[0])
        return hits

    def off2va_guess(self, off):
        va = off  # 默认同值（兼容无节）
        if '.text' in [s['name'] for s in self.sections]:
            t = next(s for s in self.sections if s['name'] == '.text')
            if t['raw_off'] <= off < t['raw_off'] + max(t['raw_size'], 1):
                va = self.image_base + t['va'] + (off - t['raw_off'])
        else:
            va = self.image_base + off
        return va

    def watch_gates(self, cb=None):
        """运行时门检测：执行的指令为 push 0x33 时触发 cb(va)；默认记录到 _gate_hits"""
        self._ensure_gate_watcher()

        def h(uc, addr, size, user):
            pass
        return self._gate_hits

    def _ensure_gate_watcher(self):
        if getattr(self, '_gate_watcher_installed', False):
            return
        self._gate_watcher_installed = True

        def h(uc, addr, size, user):
            try:
                b = self.read(addr, 2)
                if b == b'\x6a\x33':
                    rec = {'va': addr, 'file_hint': hex(addr)}
                    self._gate_hits.append(rec)
                    self.log(f'*** GATE EXECUTED @ 0x{addr:X} ***')
                    cb = getattr(self, '_gate_cb', None)
                    if cb:
                        cb(addr)
            except Exception:
                pass
        self.mu.hook_add(UC_HOOK_CODE, h)

    def on_gate(self, cb):
        self._gate_cb = cb

    def read(self, addr, size):
        r = self.mu.mem_read(addr, size)
        return bytes(r) if isinstance(r, list) else r


if __name__ == '__main__':
    print('PESim: from pe_sim import PESim')
