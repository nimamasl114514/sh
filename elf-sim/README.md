# elf_sim.py — 自研 ELF 模拟动态执行框架 v9（双架构 + 图输出）

绕过 linker 直接调用 ELF 任意函数，hook 指令/内存，dump 解密数据。自研 MiniDBI，双架构。

## v9 新增：直接出图
- **架构图**：`callgraph_dot()` / `callgraph_mermaid()`（节点=函数 where() 符号化、边=调用次数）一键 `export_diagrams()` 落盘
- **变量生命周期图**：`track_variables()`（记录 .data/.bss 写/读事件）→ `variable_lifecycle()`（每变量：诞生=首次写 / 使用=读次 / 消亡=被覆盖）→ 三种出图：`var_lifecycle_dot()` / `var_lifecycle_mermaid()` / `var_lifecycle_table()`

## 全部能力汇总（v2-v9）
| 类别 | 能力 |
|---|---|
| 架构 | x86_64 + ARM64 自动检测（寄存器/ABI/bl-ret/svc/PLT 双后端） |
| 符号 | .dynsym/.rela.plt/.plt → from_symbol()/where() |
| 执行 | call(按名/按址)/run/step/continue_until/setup_argv |
| 桩 | libc 30+（printf/malloc/atoi...）+ auto-stubs + 自定义 |
| 内存 | 堆分配器/追踪/差分/区间 hook/snapshot-restore/save-load |
| 观察 | 断点/指令追踪/call_tree/字符串收集/exec_stats/watch_range |
| 清洗 | reconstruct_function（带符号+字符串+段归属注释）/generate_c_stub/imports.h/export_project |
| **图** | **callgraph dot+mermaid / 变量生命周期 dot+mermaid+表格** |

## 用法
```python
from elf_sim import ElfSim
sim = ElfSim('x.elf')
sim.track_variables()
sim.call_tree()
sim.call(sim.from_symbol('main'))
print(sim.callgraph_mermaid())      # 架构图
print(sim.var_lifecycle_table())    # 变量生命周期表
sim.export_diagrams('out/')         # 一键落盘全部图
```
