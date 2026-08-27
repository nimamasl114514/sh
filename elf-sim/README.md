# elf_sim.py — 自研 ELF 模拟动态执行框架 v3

绕过 linker 直接调用 ELF 任意函数（SysV 参数），hook 指令/内存，dump 解密数据。

## v3 能力（自研 MiniDBI）
1. 完整节表 + `.dynsym`/`.rela.plt`/`.plt` 符号体系：`from_symbol('memcpy')` 按名调用（240+ 导入全解析 PLT stub）
2. **libc 桩 30+**：strlen/strcmp/strncmp/memcmp/strcpy/strncpy/strcat/memcpy/memmove/memset/putchar/puts/**printf/sprintf/atoi/strtol**/time/malloc/calloc/free/dlopen/getenv/abort/exit/clock_gettime...
3. **简单堆分配器**：malloc/calloc 从 0x72000000 起 8MB 池（对齐 16）
4. **格式化输出**：printf/sprintf 支持 %s/%d/%i/%u/%x/%X/%p/%c/%f/%ld
5. **auto-stubs**：未实现导入自动 fallback 返回 0，模拟不中断
6. **syscall 拦截**：write/read/mmap/brk/clock_gettime/exit/nanosleep/poll
7. **内存追踪**：hook_mem_write/read（记录+回调）
8. **调用追踪**：trace_calls() 记录所有 PLT 调用序列（MiniDBI 特征）
9. **快照/恢复**：snapshot()/restore()（28 寄存器 + 栈区）
10. **argv 模拟**：setup_argv(['a','b']) 铺栈

## 用法
```python
from elf_sim import ElfSim
sim = ElfSim('x.elf')        # 自动: 符号解析 + libc 桩 + auto-stubs + syscall hook
sim.call('memcpy', [dst, src, 12])
sim.call(sim.from_symbol('main'))          # 按名调用
sim.trace_calls()                          # 开始记录 PLT 调用
ptr = sim.call('malloc', [64])             # 简单堆分配
sim.setup_argv(['prog', 'arg1'])           # argv 铺栈
raw = sim.dump(0x5F0000, 0x1000)           # dump 解密数据
```

## 实测（Android BOLT ELF，sub_1F2B70 解密函数）
- 命中明文：imei / wy.llua / 223.5.5.5 / Content-Length
- malloc 对齐分配 64B 正确、atoi('12345')=12345
- 240 导入全部解析到 PLT stub（0x5e1600+）

```bash
python demo.py target.elf
```
