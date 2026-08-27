# asar_tools.py — Electron asar 工具

新版 asar（Chromium 双层 Pickle + per-file integrity）解析/提取/原位修补。

```bash
python asar_tools.py list app.asar
python asar_tools.py extract app.asar 'out/main/.*'
python asar_tools.py patch app.asar out/main/index.js fix.js
```
