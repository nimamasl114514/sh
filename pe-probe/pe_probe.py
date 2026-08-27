# -*- coding: utf-8 -*-
"""
pe_probe.py — PE 快速侦察：架构/节区/熵/编译器特征/字符串提取
用法：python pe_probe.py <exe>
"""
import struct, sys, io, re, math
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def entropy(b):
    if not b:
        return 0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    print(f'[{path}] size={len(data)}')

    e = struct.unpack_from('<I', data, 0x3C)[0]
    machine = struct.unpack_from('<H', data, e + 4)[0]
    nsec = struct.unpack_from('<H', data, e + 6)[0]
    opt_size = struct.unpack_from('<H', data, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from('<H', data, opt)[0]
    img_base = struct.unpack_from('<Q', data, opt + 24)[0]
    print(f'machine=0x{machine:X} (0x8664=x64/0x14c=x86)  magic=0x{magic:X}  image_base=0x{img_base:X}')

    sec_off = opt + opt_size
    for i in range(nsec):
        off = sec_off + i * 40
        name = data[off:off+8].rstrip(b'\0').decode('latin1')
        vsize, vaddr, rsize, roff = struct.unpack_from('<IIII', data, off + 8)
        ent = entropy(data[roff:roff+rsize]) if rsize else 0
        flag = ' <<< 高熵(加密?)' if ent > 7.2 else ''
        print(f'  {name:<8} VA=0x{vaddr:08X} size=0x{vsize:08X} ent={ent:.3f}{flag}')

    # 编译器特征
    for marker, label in [(b'Go build ID', 'Go'), (b'rustc', 'Rust'), (b'electron', 'Electron'),
                          (b'.NET', '.NET'), (b'PyInstaller', 'PyInstaller'), (b'UPX!', 'UPX'),
                          (b'NSIS', 'NSIS'), (b'Inno Setup', 'Inno')]:
        if marker in data[:2_000_000]:
            print(f'  编译器: {label}')
    if data.find(b'Rich') != -1:
        print('  编译器: MSVC (Rich header)')

    # 提取字符串
    strings = []
    for m in re.finditer(rb'[\x20-\x7e]{5,}', data):
        strings.append(m.group().decode('ascii', 'ignore'))
    print(f'字符串: {len(strings)}')
    for kw in ['http://', 'https://', 'token', 'password', 'secret', '.so', 'dlopen']:
        hits = [s for s in strings if kw in s][:3]
        if hits:
            print(f'  [{kw}] {hits}')


if __name__ == '__main__':
    main()
