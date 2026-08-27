# -*- coding: utf-8 -*-
"""
screen_locator.py — LobsterAI computer-use 增强：按文字/颜色定位 + 危险指令拦截
==============================================================
在截图中根据「文字」或「颜色」找到目标坐标，供 computer-use click 使用。
内置危险指令拦截：OCR 命中的文字若匹配危险词库（删除/支付/关机/格式化等），
默认拒绝输出坐标，防止自动化误点破坏性操作。

对接方式：
    1. 截图：用 computer-use get_window_state 拿到的截图（PNG 文件/URL），或本工具直接抓屏
    2. 定位：locate_text() / locate_color() 返回匹配项的边界框中心坐标
    3. 点击：把坐标传给 computer-use click（window + x/y）

依赖：pip install rapidocr-onnxruntime pillow numpy
"""

import sys
import io
import argparse

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import numpy as np
from PIL import Image

try:
    from rapidocr_onnxruntime import RapidOCR
    _OCR = None
    _OCR_AVAILABLE = True
except Exception:
    _OCR_AVAILABLE = False


def _get_ocr():
    """懒加载 OCR 引擎"""
    global _OCR
    if not _OCR_AVAILABLE:
        raise RuntimeError('rapidocr-onnxruntime 未安装: pip install rapidocr-onnxruntime')
    if _OCR is None:
        _OCR = RapidOCR()
    return _OCR

# ================================================================
# 危险指令词库（破坏性/支付/权限类操作，命中即拦截）
# ================================================================
DANGER_KEYWORDS = {
    # 破坏性操作
    'delete': ['删除', '移除', '清除', '清空', '卸载', '移除所有', '删除所有', '全部删除', '永久删除',
               'delete', 'remove', 'uninstall', 'erase', 'clear all', 'delete all', 'permanently delete'],
    # 文件系统
    'fs': ['格式化', '重置', '恢复出厂', '覆盖', '重命名', '移动文件', '替换', '覆写',
           'format', 'reset', 'factory reset', 'overwrite', 'replace', 'rename'],
    # 支付/资金
    'payment': ['支付', '付款', '购买', '转账', '汇款', '确认支付', '立即支付', '提交订单', '扣款', '续费', '订阅',
                'pay', 'payment', 'purchase', 'transfer', 'checkout', 'subscribe', 'confirm payment', 'buy now'],
    # 账户/权限
    'account': ['注销账户', '删除账户', '注销账号', '退出登录', '撤销授权', '关闭账户', '冻结',
                'delete account', 'deactivate', 'revoke', 'sign out', 'log out', 'close account'],
    # 系统级
    'system': ['关机', '重启', '睡眠', '休眠', '结束进程', '终止进程', '强制退出', '关闭系统', '锁定计算机',
               'shutdown', 'reboot', 'restart now', 'kill process', 'force quit', 'end task', 'sleep', 'hibernate'],
    # 危险确认
    'confirm': ['确定删除', '确认删除', '确定要', '确定吗', '不可恢复', '无法恢复', '不可撤销', '危险操作', '请确认',
                'are you sure', 'cannot be undone', 'irreversible', 'this cannot be undone'],
}

# 危险词库扁平化（小写，供快速匹配）
_DANGER_FLAT = []
for _cat, _words in DANGER_KEYWORDS.items():
    for _w in _words:
        _DANGER_FLAT.append((_w.lower(), _cat))


def check_danger(text):
    """
    检查文字是否命中危险词库。
    返回 (is_danger, [(matched_word, category), ...])
    """
    low = (text or '').lower()
    hits = []
    for word, cat in _DANGER_FLAT:
        if word in low:
            hits.append((word, cat))
    return (len(hits) > 0, hits)


def danger_report(text):
    """人类可读的危险检测结果"""
    is_danger, hits = check_danger(text)
    if not is_danger:
        return None
    cats = set(c for _, c in hits)
    words = ', '.join(w for w, _ in hits)
    return f'危险指令[{"/".join(sorted(cats))}]: {words}'


# ================================================================
# 文字定位
# ================================================================

def locate_text(text, img, partial=True, case_sensitive=False, danger_check=True):
    """
    在图像中查找文字，返回匹配项列表。
    每项: {'text','x','y','w','h','conf','danger','danger_hits'}
    danger_check=True 时附带危险检测（默认开启，仅标记不拦截，拦截在 CLI/调用方决定）。
    """
    if isinstance(img, str):
        img = Image.open(img)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    arr = np.array(img)
    result, _ = _get_ocr()(arr)
    if not result:
        return []

    needle = text if case_sensitive else text.lower()
    hits = []
    for item in result:
        box, ocr_text, conf = item[0], item[1], item[2]
        cand = ocr_text if case_sensitive else ocr_text.lower()
        if (cand == needle) if not partial else (needle in cand):
            xs = [p[0] for p in box]
            ys = [p[1] for p in box]
            entry = {
                'text': ocr_text,
                'x': int(sum(xs) / 4),
                'y': int(sum(ys) / 4),
                'w': int(max(xs) - min(xs)),
                'h': int(max(ys) - min(ys)),
                'conf': float(conf),
                'danger': False,
                'danger_hits': [],
            }
            if danger_check:
                is_danger, hits2 = check_danger(ocr_text)
                entry['danger'] = is_danger
                entry['danger_hits'] = hits2
            hits.append(entry)
    hits.sort(key=lambda d: -d['conf'])
    return hits


# ================================================================
# 颜色定位
# ================================================================

def locate_color(rgb, img, tolerance=30, min_area=1):
    """颜色定位（无语义，不做危险检测）"""
    if isinstance(img, str):
        img = Image.open(img)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    arr = np.array(img).astype(int)
    target = np.array(rgb, dtype=int)
    mask = (np.abs(arr - target) <= tolerance).all(axis=2)
    if not mask.any():
        return []

    h, w = mask.shape
    visited = np.zeros((h, w), dtype=bool)
    regions = []
    for y in range(h):
        for x in range(w):
            if mask[y, x] and not visited[y, x]:
                stack = [(y, x)]
                visited[y, x] = True
                pts = []
                while stack:
                    cy, cx = stack.pop()
                    pts.append((cx, cy))
                    for dy in (-1, 0, 1):
                        for dx in (-1, 0, 1):
                            ny, nx = cy + dy, cx + dx
                            if 0 <= ny < h and 0 <= nx < w and mask[ny, nx] and not visited[ny, nx]:
                                visited[ny, nx] = True
                                stack.append((ny, nx))
                if len(pts) >= min_area:
                    xs = [p[0] for p in pts]
                    ys = [p[1] for p in pts]
                    regions.append({
                        'x': (min(xs) + max(xs)) // 2,
                        'y': (min(ys) + max(ys)) // 2,
                        'w': max(xs) - min(xs) + 1,
                        'h': max(ys) - min(ys) + 1,
                        'count': len(pts),
                    })
    regions.sort(key=lambda d: -d['count'])
    return regions


# ================================================================
# 截屏
# ================================================================

def capture_screen(region=None):
    from PIL import ImageGrab
    if region:
        img = ImageGrab.grab(bbox=region)
    else:
        img = ImageGrab.grab()
    return img.convert('RGB')


def capture_window_by_title(title_part):
    """按窗口标题子串抓取窗口截图，返回 (PIL.Image, 窗口左上角坐标)"""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32

    def callback(hwnd, _lparam):
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                if title_part.lower() in buf.value.lower():
                    results.append(hwnd)
        return True

    results = []
    user32.EnumWindows(ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)(callback), 0)
    if not results:
        return capture_screen(), (0, 0)

    hwnd = results[0]
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    left, top, right, bottom = rect.left, rect.top, rect.right, rect.bottom
    img = capture_screen(region=(left, top, right, bottom))
    return img, (left, top)


# ================================================================
# CLI
# ================================================================

def main():
    ap = argparse.ArgumentParser(description='computer-use 增强定位器：按文字/颜色找坐标 + 危险指令拦截')
    ap.add_argument('--text', help='要查找的文字')
    ap.add_argument('--color', help='要查找的颜色，格式 R,G,B')
    ap.add_argument('--tolerance', type=int, default=30, help='颜色容差（默认30）')
    ap.add_argument('--image', help='图片路径（缺省=抓取当前屏幕）')
    ap.add_argument('--window', help='按窗口标题子串截取窗口（缺省=全屏）')
    ap.add_argument('--exact', action='store_true', help='文字整行精确匹配（默认子串）')
    ap.add_argument('--json', action='store_true', help='JSON 输出')
    # 危险拦截控制
    ap.add_argument('--allow-danger', action='store_true', help='放行危险指令（默认拦截，不输出坐标）')
    ap.add_argument('--danger-only', action='store_true', help='仅输出命中危险指令的条目（审计用）')
    ap.add_argument('--confirm-danger', action='store_true', help='危险命中时交互确认后才输出')
    args = ap.parse_args()

    if not args.text and not args.color:
        ap.error('必须提供 --text 或 --color')

    # 截图
    if args.image:
        img = Image.open(args.image)
        offset = (0, 0)
    elif args.window:
        img, offset = capture_window_by_title(args.window)
        print(f'# 窗口截图: {img.size}, 窗口原点偏移 {offset}', file=sys.stderr)
    else:
        img = capture_screen()
        offset = (0, 0)

    results = []
    if args.text:
        if not _OCR_AVAILABLE:
            sys.exit('rapidocr-onnxruntime 未安装: pip install rapidocr-onnxruntime')
        for hit in locate_text(args.text, img, partial=not args.exact):
            hit['x'] += offset[0]
            hit['y'] += offset[1]
            results.append({'type': 'text', **hit})
    if args.color:
        r, g, b = map(int, args.color.split(','))
        for hit in locate_color((r, g, b), img, tolerance=args.tolerance):
            hit['x'] += offset[0]
            hit['y'] += offset[1]
            results.append({'type': 'color', 'rgb': [r, g, b], **hit})

    # ---------- 危险指令拦截 ----------
    danger_items = [r for r in results if r.get('danger')]
    safe_items = [r for r in results if not r.get('danger')]

    if args.danger_only:
        results = danger_items
    elif not args.allow_danger:
        if danger_items and args.confirm_danger:
            print(f'!! 命中 {len(danger_items)} 个危险指令，确认输出？[y/N] ', file=sys.stderr, end='')
            try:
                ans = input().strip().lower()
            except EOFError:
                ans = 'n'
            if ans == 'y':
                results = results  # 全部输出
            else:
                results = safe_items
                print('!! 已拦截危险条目，仅输出安全条目', file=sys.stderr)
        else:
            results = safe_items
            if danger_items:
                print(f'!! 拦截 {len(danger_items)} 个危险指令条目（--allow-danger 放行 / --danger-only 查看）',
                      file=sys.stderr)

    if args.json:
        import json
        print(json.dumps(results, ensure_ascii=False, indent=1))
        return

    if not results:
        print('未找到匹配项')
        return
    print(f'找到 {len(results)} 个匹配:')
    for r in results[:20]:
        tag = f"[{r['conf']:.2f}] {r['text']!r}" if r['type'] == 'text' else f"[rgb{r['rgb']}]"
        danger_mark = ' ⚠️危险' if r.get('danger') else ''
        print(f"  {tag}: 中心 ({r['x']},{r['y']}) 区域 {r['w']}x{r['h']}{danger_mark}")
    if results and results[0]['type'] == 'text':
        print('\n# 传给 computer-use click: window 坐标 (x={}, y={})'.format(results[0]['x'], results[0]['y']))


if __name__ == '__main__':
    main()
