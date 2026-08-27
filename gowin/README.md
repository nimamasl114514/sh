# go_pclntab.py — Go 二进制 pclntab 恢复

## 功能
1. filetab 定位（源码路径字符串）
2. 暴力恢复被清零/损坏的 pclntab header（filetabOffset 自洽校验）
3. 全量函数符号解析（name/VA/source file）
4. JSON 导出（供 Ghidra/IDA 批量导入符号）

## 用法
```bash
python go_pclntab.py target.exe --json syms.json
python go_pclntab.py target.exe --filter mypkg
```
