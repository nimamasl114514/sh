# elf_sim.py — 自研 ELF 模拟执行框架

绕过 linker 直接调用 ELF 任意函数（SysV 参数：rdi/rsi/rdx/rcx/r8/r9），hook 指令/内存，dump 解密数据。

适用：BOLT/加密 Android ELF 的运行时解密序列捕获、任意函数单元模拟。

```python
from elf_sim import ElfSim
sim = ElfSim('target.elf')
sim.call(0x123456, [0x70000000], until=0)   # 调用函数
raw = sim.dump(0x5F0000, 0x1000)            # dump 解密后数据
```
