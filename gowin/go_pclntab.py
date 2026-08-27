# -*- coding: utf-8 -*-
"""
go_pclntab.py — Go 二进制逆向工具：pclntab 恢复 + 完整符号解析
适用：strip (-s -w) + pclntab 魔数被清零/损坏的 Go 1.20+ Windows x64 二进制
流程：
  1. 扫描 filetab（源码路径字符串）定位 pclntab 起点（暴力恢复被抹的 header）
  2. 解析 ftab/_func 提取全部函数符号（name + VA + source file）
  3. 导出 JSON / 文本
用法：
  python go_pclntab.py <exe> [--json out.json] [--filter sfvproxy]
"""
import struct, sys, io, json

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def load_sections(data):
    e = struct.unpack_from('<I', data, 0x3C)[0]
    opt_size = struct.unpack_from('<H', data, e + 20)[0]
    sec_off = e + 24 + opt_size
    n = struct.unpack_from('<H', data, e + 6)[0]
    image_base = struct.unpack_from('<Q', data, e + 24 + 24)[0]
    secs = []
    for i in range(n):
        off = sec_off + i * 40
        name = data[off:off+8].rstrip(b'\0').decode('latin1')
        vsize, vaddr, rsize, roff = struct.unpack_from('<IIII', data, off + 8)
        secs.append((name, vaddr, vsize, roff, rsize))
    return image_base, secs


def recover_pclntab(data, filetab_start, secs):
    """暴力恢复 pclntab header（通过 filetabOffset 自洽）"""
    HDR = 72
    for start in range(filetab_start - 0x100000, filetab_start - HDR, 16):
        if start < 0:
            continue
        nfunc = struct.unpack_from('<Q', data, start + 8)[0]
        nfiles = struct.unpack_from('<Q', data, start + 16)[0]
        filetab = struct.unpack_from('<Q', data, start + 48)[0]
        if start + filetab != filetab_start:
            continue
        if not (100 < nfunc < 100000) or not (0 < nfiles < 5000):
            continue
        rel = [struct.unpack_from('<Q', data, start + o)[0] for o in (32, 40, 56, 64)]
        if all(HDR <= r < 0x800000 for r in rel):
            return start, nfunc, nfiles
    return None, 0, 0


def cstr(data, off):
    end = data.index(b'\0', off)
    return data[off:end].decode('utf-8', 'replace')


def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    image_base, secs = load_sections(data)

    # 1) 找 filetab 内容起点（第一个 Go 源码路径往回推到 \0 边界）
    marker = data.find(b'C:/Program Files/Go/src/')
    if marker == -1:
        marker = data.find(b'/usr/local/go/src/')
    p = marker
    while p > 0 and data[p-1:p] != b'\x00' and data[p-1] >= 0x20:
        p -= 1
    filetab_start = p
    print(f'[1] filetab @ 0x{filetab_start:X}: {data[p:p+50]}')

    # 2) 恢复 pclntab
    PCLN, nfunc, nfiles = recover_pclntab(data, filetab_start, secs)
    if PCLN is None:
        print('[!] pclntab 恢复失败')
        return
    print(f'[2] pclntab @ 0x{PCLN:X} nfunc={nfunc} nfiles={nfiles}')

    funcname_off = struct.unpack_from('<Q', data, PCLN + 32)[0]
    cu_off = struct.unpack_from('<Q', data, PCLN + 40)[0]
    filetab_off = struct.unpack_from('<Q', data, PCLN + 48)[0]
    pcln_off = struct.unpack_from('<Q', data, PCLN + 64)[0]
    funcnametab = PCLN + funcname_off
    cutab = PCLN + cu_off
    filetab = PCLN + filetab_off
    pclntab = PCLN + pcln_off

    text_va = next(v for n, v, vs, r, rs in secs if n == '.text')
    funcs = []
    for i in range(1, nfunc + 1):
        entryoff, funcoff = struct.unpack_from('<II', data, pclntab + i * 8)
        if entryoff == 0:
            continue
        fpos = pclntab + funcoff
        nameoff = struct.unpack_from('<i', data, fpos + 4)[0]
        name = cstr(data, funcnametab + nameoff)
        va = image_base + text_va + entryoff
        cu_idx = struct.unpack_from('<I', data, fpos + 32)[0]
        try:
            file = cstr(data, filetab + struct.unpack_from('<I', data, cutab + cu_idx * 4)[0])
        except Exception:
            file = '?'
        funcs.append({'va': va, 'name': name, 'file': file})

    print(f'[3] 函数符号: {len(funcs)}')

    flt = sys.argv[sys.argv.index('--filter') + 1] if '--filter' in sys.argv else None
    if flt:
        funcs = [f for f in funcs if flt in f['name'] or flt in f['file']]
        print(f'    过滤 [{flt}]: {len(funcs)}')

    if '--json' in sys.argv:
        out = sys.argv[sys.argv.index('--json') + 1]
        json.dump(funcs, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print(f'    已存 {out}')
    else:
        for f in funcs[:50]:
            print(f"  0x{f['va']:X}  {f['name']}  [{f['file']}]")


if __name__ == '__main__':
    main()
