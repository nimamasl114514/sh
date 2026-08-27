# screen_locator.py — 电脑操作增强定位器

按文字(rapidocr)/颜色(pixel) 定位屏幕目标 + 危险指令拦截（6 类中英危险词，默认拦截）。

```bash
python screen_locator.py --window QQ --text "消息"
python screen_locator.py --color 220,50,50 --tolerance 40
python screen_locator.py --text "删除" --allow-danger
```
