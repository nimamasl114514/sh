# elf_sim.py — 自研 ELF 模拟动态执行框架 v4

绕过 linker 直接调用 ELF 任意函数（SysV 参数），hook 指令/内存，dump 解密数据。自研 MiniDBI。

## v4 能力
1. 符号体系：`.dynsym`/`.rela.plt`/`.plt` 全解析（240+ 导入 → PLT stub），`from_symbol('memcpy')` 按名调用，`where(addr)` 符号化地址
2. **libc 桩 30+**：strlen/strcmp/memcmp/strcpy/strncpy/strcat/memcpy/memset/putchar/puts/**printf/sprintf/atoi/strtol**/time/malloc/calloc/free/dlopen/abort/exit...
3. **堆分配器**：malloc/calloc 8MB 池（16 对齐）
4. **auto-stubs**：未实现导入自动 fallback，模拟不中断
5. syscall 拦截：write/read/mmap/brk/clock_gettime/exit/nanosleep/poll
6. **执行断点**：`add_breakpoint(addr, cb)`（cb 命中回调；返回 False 停止）
7. **指令追踪**：`trace_instructions()` 记录执行路径（capstone 反汇编）
8. **字符串收集**：`collect_strings()` 抓取执行中访问的 .rodata 字符串常量
9. **区间监视**：`watch_range(addr, size)` 统计读写次数
10. **状态持久化**：`save_state()/load_state()`（JSON 寄存器 + .data 解密结果）
11. **架构检测**：非 x86_64 明确报错（ARM64 提示）
12. 内存追踪 / 快照恢复 / argv 模拟（v2/v3 保留）

## 用法
```python
from elf_sim import ElfSim
sim = ElfSim('x.elf')

sim.add_breakpoint(0x123456, lambda a, s: print('hit', hex(a)) or False)
t = sim.trace_instructions()
strs = sim.collect_strings()
sim.watch_range(0x5F0000, 0x2000)
sim.call(sim.from_symbol('main'))
sim.save_state('s.json')
sim.watch_range(0x5F0000, 0x2000)
```

## 实测（Android BOLT ELF）
- sub_1F2B70 解密：命中 imei/wy.llua/223.5.5.5 明文
- 指令追踪 100w 条、字符串收集 29 条、状态持久化 OK
- 240 导入全解析 PLT stub

```bash
python demo.py target.elf
```
