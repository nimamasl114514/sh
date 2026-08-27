# elf_sim.py — 自研 ELF 模拟动态执行框架 v6

绕过 linker 直接调用 ELF 任意函数（SysV 参数），hook 指令/内存，dump 解密数据。自研 MiniDBI。

## v6 新增
- **函数调用树**：`call_tree()` / `dump_call_tree()`（内部 call/ret 配对，嵌套层级）
- **执行统计**：`exec_stats()`（指令数/调用数/耗时）
- **日志系统**：`set_log(path)` / `log(...)`（框架日志写文件）
- **区间内存 hook**：`memory_region_hook(addr, size, on_read, on_write)`（精确区间监控，低开销）
- **整合开关**：`enable_tracing(asm, calls, strings)` 一键全开

## 全部能力（v2-v6）
1. 符号体系（.dynsym/.rela.plt/.plt → PLT stub），`from_symbol()` / `where()`
2. libc 桩 30+（printf/malloc/atoi/strcmp/memcpy...）+ auto-stubs
3. 堆分配器 / argv 模拟 / syscall 拦截
4. 断点 / 指令追踪 / 字符串收集 / 区间监视 / 状态持久化 / 架构检测
5. 反汇编 API / 输出重定向 / 单步 / continue_until / skip_call / 内存差分 / export_trace / set_seed
6. 调用树 / 执行统计 / 日志 / 区间 hook / enable_tracing

## 用法
```python
from elf_sim import ElfSim
sim = ElfSim('x.elf')

sim.enable_tracing(asm=True, calls=True, strings=True)  # 一键全开
sim.call(sim.from_symbol('main'))
print(sim.dump_call_tree())     # 调用树文本
print(sim.exec_stats())         # {'insns':..., 'calls':..., 'elapsed':...}
```

## 实测（Android BOLT ELF）
- main 入口执行：捕获 3 层嵌套调用树（0x109570→0x149EE0→0x5C2940）
- exec_stats：848 insns / 5 calls / 0.008s
- 解密函数：命中 imei / wy.llua / 223.5.5.5 明文
- 240 导入全解析 PLT stub

```bash
python demo.py target.elf
```
