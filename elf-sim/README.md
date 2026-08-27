# elf_sim.py — 自研 ELF 模拟动态执行框架 v2

绕过 linker 直接调用 ELF 任意函数（SysV 参数：rdi/rsi/rdx/rcx/r8/r9），hook 指令/内存，dump 解密数据。

## v2 能力
1. 完整节表解析 + `.dynsym` 符号寻址（`from_symbol('memcpy')`）
2. `.rela.plt`/`.plt` 扫描：导入函数 -> PLT stub 地址（240+ 常用全部解析）
3. **libc 桩系统**：`install_libc_stubs()` 自动 hook strlen/strcmp/memcpy/memset/strcpy/puts/usleep 等（Python 实现，call 到 PLT 时拦截执行）
4. **syscall 拦截**：write/read/mmap/brk/clock_gettime/exit 等简易模拟
5. **内存追踪**：`hook_mem_write()`/`hook_mem_read()`（记录/回调）
6. **快照/恢复**：`snapshot()`/`restore()`（寄存器 + 栈区）
7. 自定义导入桩：`install_libc_stub('puts', handler)`

## 用法
```python
from elf_sim import ElfSim
sim = ElfSim('target.elf')
sim.install_libc_stubs()
writes = sim.hook_mem_write()
sim.call('memcpy', [dst, src, 12])
sim.call(0x123456, [0x70000000], until=0)
raw = sim.dump(0x5F0000, 0x1000)   # dump 解密后数据
```

## 实测（Android BOLT ELF 实战）
- sub_1F2B70 解密函数模拟：命中 `imei`/`wy.llua`/`223.5.5.5`/`Content-Length` 明文
- 240 导入全解析、libc 桩正常运行

```bash
python demo.py target.elf
```
