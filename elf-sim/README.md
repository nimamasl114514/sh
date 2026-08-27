# elf_sim.py — 自研 ELF 模拟动态执行框架 v7（双架构 x86_64 + ARM64）

绕过 linker 直接调用 ELF 任意函数，hook 指令/内存，dump 解密数据。自研 MiniDBI，双架构。

## v7：ARM64 后端
- 自动架构检测（ELF machine: 62=x86_64 / 183=AArch64）
- ARM64：参数 x0-x7 / bl 调用识别 / ret 检测 / svc(syscall) 拦截 / AArch64 标准 PLT（16B entry → .rela.plt）
- capstone ARM64 反汇编 / 寄存器体系 / 全部观察能力通用（断点/追踪/调用树/桩/差分/持久化）
- 无节表最小 ELF 支持（按 PT_LOAD 程序头映射）
- 第三方：Unicorn 原生 ARM64 引擎（允许，已用）

## 全部能力（v2-v7 汇总）
1. 符号体系（.dynsym/.rela.plt/.plt），from_symbol/where
2. libc 桩 30+（printf/malloc/atoi/strcmp/memcpy...）+ auto-stubs
3. 堆分配器 / argv / syscall 拦截（双架构 SYS 号表）
4. 断点 / 指令追踪 / 字符串收集 / 区间监视 / 状态持久化 / 架构检测
5. 反汇编 / 输出重定向 / 单步 / continue_until / skip_call / 内存差分 / export_trace / set_seed
6. 调用树 / 执行统计 / 日志 / 区间 hook / enable_tracing

## 用法（双架构同 API）
```python
from elf_sim import ElfSim
sim = ElfSim('target.elf')        # 自动检测 x86_64 / ARM64
sim.enable_tracing(asm=True, calls=True)
sim.call(sim.from_symbol('main'))  # 按名调用（参数自动按架构）
print(sim.dump_call_tree())
print(sim.exec_stats())
```

## 实测
- x86_64（Android BOLT ELF）：240 导入全解析、解密命中 imei/wy.llua、调用树 3 层
- ARM64（构造 ELF）：加载/执行 ret/寄存器/反汇编全通
