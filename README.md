# sh — 逆向 & 自动化工具箱

个人逆向工程 / 自动化实用工具集（自研，实战验证）。

## 工具一览

| 目录 | 工具 | 用途 |
|---|---|---|
| `elf-sim/` | elf_sim.py | 自研 ELF 模拟动态执行框架（Unicorn 内核，绕过 linker 直接调用任意函数，hook 内存捕获） |
| `gowin/` | go_pclntab.py | Go 二进制逆向：**pclntab 损坏恢复** + 全量符号解析（strip/魔数清零样本） |
| `asar-tools/` | asar_tools.py | Electron app.asar 解析/提取/**原位修补**（新版双层 Pickle，含 integrity 处理） |
| `pe-probe/` | pe_probe.py | PE 快速侦察：架构/节区/熵/编译器特征/字符串 |
| `screen-locator/` | screen_locator.py | 电脑操作增强：**按文字(OCR)/颜色定位目标** + 危险指令拦截（删除/支付等黑名单） |
| `sms-otp/` | sms_api.py | 国外临时号自动筛选 API（多源聚合 + 活跃度评分：最后接收时间越近越好） |
| `sms-otp/` | sms_monitor.py | 单号验证码轮询监视器（自动提取 OTP） |

## 亮点功能

- **go_pclntab.py**：GoReSym 失效（pclntab 魔数被清零）时的唯一出路——filetab 暴力恢复 + 手写解析器提取全部函数符号
- **elf_sim.py**：BOLT/加密 ELF 的运行时解密序列捕获（绕过 bionic linker）
- **asar_tools.py**：新文件更小时零移动修补（只改 header size + 数据区，无需重打包）
- **screen_locator.py**：危险词拦截（6 类中英词库），输出坐标前保障

## 快速开始

```bash
python gowin/go_pclntab.py target.exe --json syms.json --filter mypkg
python asar-tools/asar_tools.py list app.asar
python asar-tools/asar_tools.py patch app.asar out/main.js fix.js
python elf-sim/elf_sim.py   # 库：ElfSim(elf).call(addr) / .dump(addr,size)
python pe-probe/pe_probe.py target.exe
python screen-locator/screen_locator.py --window QQ --text "消息"
python sms-otp/sms_api.py --port 8080   # 然后 GET /api/best
```

## 环境

- Python 3.10+
- 依赖：unicorn（elf-sim）、capstone（部分辅助）、rapidocr-onnxruntime + pillow + numpy（screen-locator）、flask + requests（sms-otp）

## 免責

仅用于授权的逆向研究/自动化测试。请遵守当地法律法规与服务条款。
