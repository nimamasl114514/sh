# -*- coding: utf-8 -*-
"""最终版字节对拍：Ghidra 反汇编字节流 vs 源文件 + capstone mnemonic 三源交叉"""
import sys, io, re, hashlib
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
import capstone as C

d = open(r'C:\Users\wwww\Desktop\cm (1)\cm.exe', 'rb').read()
md = C.Cs(C.CS_ARCH_X86, C.CS_MODE_32)
TEXT_RAW, TEXT_VA = 0x400, 0x1000

entries = {}
for line in open(r'C:\Users\wwww\lobsterai\project\.cowork-temp\cm_ghidra_asm.txt', encoding='utf-8'):
    m = re.match(r'^([0-9A-F]{8}):\s*([0-9a-f]*) *([A-Za-z].*)$', line.strip())
    if not m:
        continue
    va = int(m.group(1), 16)
    hexs = m.group(2)
    desc = m.group(3)
    if hexs:
        entries[va] = (hexs, desc)

byte_ok, byte_fail = 0, 0
mn_ok, mn_fail = 0, 0
msg = []
regions = [(0x4012D0, 0x400), (0x402650, 0x900), (0x402A00, 0x400), (0x402E00, 0x300)]
for start, length in regions:
    for va in sorted(entries):
        if not (start <= va < start + length):
            continue
        hexs, desc = entries[va]
        gb = bytes.fromhex(hexs)
        foff = TEXT_RAW + (va - 0x400000 - TEXT_VA)
        fb = d[foff:foff + len(gb)]
        if gb == fb:
            byte_ok += 1
        else:
            byte_fail += 1
            if len(msg) < 6:
                msg.append(f'字节 0x{va:X}: ghidra={gb.hex()} file={fb.hex()}')
        # mnemonic（capstone vs ghidra）
        try:
            ins = next(md.disasm(fb, va, count=1))
            g_mn = desc.split()[0].lower()
            if ins.mnemonic == g_mn:
                mn_ok += 1
            else:
                mn_fail += 1
                if len(msg) < 10:
                    msg.append(f'mnem 0x{va:X}: cap={ins.mnemonic} ghidra={g_mn}')
        except StopIteration:
            pass

print(f'== 字节对拍(Ghidra vs 文件): {byte_ok} 一致 / {byte_fail} 差异')
print(f'== mnemonic 对拍(capstone vs Ghidra): {mn_ok} 一致 / {mn_fail} 差异')
for m in msg[:10]:
    print('  ', m)

# 汇总 SHA（源文件关键区 vs Ghidra 汇编字节流重组的 hash，完整性终极校验）
recon = b''
for va in sorted(entries):
    recon += bytes.fromhex(entries[va][0])
print(f'\nGhidra 字节流 SHA256: {hashlib.sha256(recon).hexdigest()[:16]}')
print(f'源文件 SHA256      : {hashlib.sha256(d).hexdigest()[:16]}')
