# -*- coding: utf-8 -*-
"""
cm_keygen.py — KCTF2026 cm.exe 序列号求解器
还原链（全部经反编译确认 + Python 复算验证）：
  1. key = 88 字符十六进制（'0-9'+'A-F'）→ 44 字节
  2. xorshift32(seed=0xA5A5A5A5) + Fisher-Yates(256) 生成置换 data
  3. map[data[i]] = i（FUN_00402da0 0x10 偏移表）
  4. local_474[i] = data[TARGET[i]] + 1  → map[local_474[i]-1] == TARGET[i]
  5. 最终比较目标串: "Welcome to KCTF2026! Come and give it a try."
校验算法（第二层）：XOR 累加==0x8F + 加权和 ((sum&0x7F)+1)*b == 0xBEFD
"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

TARGET = b"Welcome to KCTF2026! Come and give it a try."
SEED = 0xA5A5A5A5  # main: local_868 = -0x5A5A5A5B（补码）
N = 256


def xorshift32(state):
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= state >> 17
    state ^= (state << 5) & 0xFFFFFFFF
    return state & 0xFFFFFFFF


def fisher_yates(n, seed):
    data = list(range(n))
    state = seed
    for i in range(n - 1, 0, -1):
        state = xorshift32(state)
        j = state % i
        data[i], data[j] = data[j], data[i]
    return data


def solve():
    data = fisher_yates(N, SEED)
    idx = [data[TARGET[i]] + 1 if TARGET[i] < N else None for i in range(len(TARGET))]
    assert all(x is not None and 0 < x <= 255 for x in idx), '值域越界'
    key = ''.join(f'{x:02x}' for x in idx).upper()
    # 复算验证
    mp = {data[k]: k for k in range(N)}
    res = bytes(mp[x - 1] for x in idx)
    assert res == TARGET, '复算失败'
    return key


def verify_algorithms(key_hex):
    """模拟验证：XOR 校验 + 加权和校验"""
    cur = bytes.fromhex(key_hex)
    xor_acc = 0
    for b in cur:
        xor_acc ^= b
    ws = 0
    for b in cur:
        ws = ((ws & 0x7F) + 1) * b
    return {'xor': hex(xor_acc), 'weight': hex(ws & 0xFFFF),
            'xor_ok': xor_acc == 0x8F, 'weight_ok': (ws & 0xFFFF) == 0xBEFD}


if __name__ == '__main__':
    k = solve()
    print(f'KEY: {k}')
    print(f'长度: {len(k)} 字符')
    print('算法复算:', verify_algorithms(k))
