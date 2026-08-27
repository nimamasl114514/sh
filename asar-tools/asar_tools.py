# -*- coding: utf-8 -*-
"""
asar_tools.py — Electron app.asar 解析/提取/修补（新版双层 Pickle 格式，含 per-file integrity）
用法：
  python asar_tools.py list <asar>                # 列出全部文件
  python asar_tools.py extract <asar> <pattern>   # 提取匹配文件到 stdout/文件
  python asar_tools.py patch <asar> <in_asar_path> <newfile> [out_asar]   # 原位覆写（新文件更小时零移动修补）
"""
import struct, sys, io, re, hashlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def parse_header(data):
    """解析新版 asar 头：返回 (header_json, dataBase)"""
    # [u32=4][u32=headerPickleSize][u32=payloadSize][u32=jsonLen][json][pad4]
    if len(data) < 16:
        raise ValueError('too small')
    json_start = 16
    json_len = struct.unpack_from('<I', data, json_start - 4)[0]
    header = json.loads(data[json_start:json_start + json_len].decode('utf-8'))
    # 数据区起点：jsonStart + jsonLen 对齐到 4
    pad = (4 - (json_start + json_len) % 4) % 4
    data_base = json_start + json_len + pad
    return header, data_base


def walk(header, prefix=''):
    """yield (path, info)"""
    for name, info in header.get('files', {}).items():
        path = prefix + name
        if 'files' in info:
            yield from walk(info, path + '/')
        else:
            yield path, info


def main():
    action = sys.argv[1]
    asar = sys.argv[2]

    data = open(asar, 'rb').read()
    header, data_base = parse_header(data)

    if action == 'list':
        for path, info in walk(header):
            size = info.get('size', 0)
            offset = int(info.get('offset', 0)) if str(info.get('offset', '0')).isdigit() else 0
            print(f'{size:>10}  {path}')

    elif action == 'extract':
        pattern = sys.argv[3]
        rx = re.compile(pattern)
        total = 0
        for path, info in walk(header):
            if rx.search(path):
                offset = int(info.get('offset', 0)) if str(info.get('offset', '0')).isdigit() else 0
                off = data_base + offset
                size = info.get('size', 0)
                blob = data[off:off + size]
                # 检查截断（asar 尾部可能被注入工具截短）
                if len(blob) < size:
                    blob += b'\x00' * (size - len(blob))
                    print(f'[warn] {path} 被截断，补零')
                outname = re.sub(r'[/\\]', '_', path)
                open(outname, 'wb').write(blob)
                print(f'{outname}  <- {path} ({size} B)')
                total += 1
        print(f'total {total}')

    elif action == 'patch':
        target = sys.argv[3]
        newfile = sys.argv[4]
        out = sys.argv[5] if len(sys.argv) > 5 else asar
        new_data = open(newfile, 'rb').read()
        header2, data_base2 = parse_header(data)
        # 找到目标文件 offset/size（字节级定位）
        target_off = None
        target_size = None
        for path, info in walk(header2):
            if path == target:
                target_off = int(info.get('offset', 0))
                target_size = info.get('size', 0)
                break
        if target_off is None:
            sys.exit(f'not found: {target}')
        # 新文件必须 <= 旧大小（否则会覆盖后续文件——提示用重打包）
        if len(new_data) > target_size:
            sys.exit(f'new file larger than old ({len(new_data)} > {target_size}); 不支持零移动修补')
        blob = bytearray(data)
        start = data_base2 + target_off
        blob[start:start + len(new_data)] = new_data
        # 剩余旧字节清零
        for i in range(start + len(new_data), start + target_size):
            blob[i] = 0
        # 更新 header 的 size（JSON 原位改写 need care——若位数相同可直接替换）
        json_start = 16
        json_len = struct.unpack_from('<I', data, json_start - 4)[0]
        header_text = data[json_start:json_start + json_len].decode('utf-8')
        # 简单起见：若 size 数字位数变化则警告
        m = re.search(r'"' + re.escape(target) + r'":"{[^}]*"size":(\d+)', header_text)
        old_sz_str = m.group(1) if m else None
        new_sz_str = str(len(new_data))
        marker = re.compile(
            r'("' + re.escape(target) + r'"(?:"|\\"|})[^}]*?")size":)(' + re.escape(old_sz_str) + r')'
        ) if old_sz_str else None
        if marker:
            header_text = marker.sub(r'\g<1>' + new_sz_str, header_text, count=1)
            blob[json_start:json_start + json_len] = header_text.encode('utf-8')
        open(out, 'wb').write(bytes(blob))
        print(f'patched {target}: {target_size} -> {len(new_data)} B -> {out}')


if __name__ == '__main__':
    main()
