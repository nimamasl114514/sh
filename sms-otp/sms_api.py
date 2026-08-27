# -*- coding: utf-8 -*-
"""
sms_api.py — 国外临时号自动筛选 API 服务（多数据源）
======================================================
数据源（按优先级，自动切换）:
  1. sms-receive.net        [active] 同接口 get_sms_register.php，含消息时间戳
  2. temporary-phone-number.com  [active] 号码列表 /xxx-Phone-Number/yyy
  3. receive-sms-online.info     [fallback] 原源（可能故障，恢复后自动生效）

筛选标准: 号码「最后一次接收短信时间」距现在越近 = 越活跃可用

API:
  GET /api/numbers                 全部号码（含活跃评分）
  GET /api/numbers/country/<cc>    按国家过滤
  GET /api/number/<phone>          单号详情
  GET /api/best                    [默认标准] 当前最优号码
  GET /api/best?min_recent_min=30  最近30分钟内活跃的号
  GET /api/history/<phone>         某号最近消息
  GET /api/health                  服务健康

后台每 60 秒重扫并缓存。运行: python sms_api.py [--port 8080] [--interval 60]
"""

import re
import time
import threading
import urllib3
import requests
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, jsonify, request

urllib3.disable_warnings()
app = Flask(__name__)

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36')
BASE_HDRS = {'User-Agent': UA, 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'}

COUNTRY_MAP = {
    'UnitedKingdom': 'GB', 'UK': 'GB', 'United Kindgom': 'GB', 'United Kingdom': 'GB',
    'Finland': 'FI', 'Sweden': 'SE', 'Belgium': 'BE', 'Netherlands': 'NL',
    'USA': 'US', 'US': 'US', 'United States': 'US', 'Canada': 'CA',
    'Romania': 'RO', 'Spain': 'ES', 'France': 'FR', 'Germany': 'DE',
    'Denmark': 'DK', 'Norway': 'NO', 'Poland': 'PL', 'Italy': 'IT',
    'Puerto Rico': 'PR', 'Estonia': 'EE', 'Latvia': 'LV', 'New Zealand': 'NZ',
    'South Africa': 'ZA', 'Bulgaria': 'BG', 'Portugal': 'PT',
}

_cache = {'numbers': [], 'updated_at': 0, 'sources': {}}


def _get(url, timeout=(8, 20), retries=2, headers=None):
    headers = {**BASE_HDRS, **(headers or {})}
    for i in range(retries):
        try:
            r = requests.get(url, headers=headers, timeout=timeout, verify=False)
            if r.status_code == 200:
                return r
        except Exception:
            pass
        time.sleep(1.5)
    return None


def parse_ts(s):
    if not s or s in ('xxx', 'no result'):
        return None
    import datetime
    s = str(s).strip()
    for fmt in ('%Y-%m-%d %H:%M:%S', '%d-%m-%Y %H:%M:%S', '%Y-%m-%d %H:%M',
                '%m-%d-%Y %H:%M:%S', '%d.%m.%Y %H:%M'):
        try:
            return datetime.datetime.strptime(s, fmt).timestamp()
        except Exception:
            continue
    return None


# ================================================================
# 数据源 1: sms-receive.net
# ================================================================

def src_smsreceive():
    """抓 sms-receive.net 号码列表 + 各号消息时间"""
    r = _get('https://sms-receive.net/')
    if r is None:
        return [], 'down'
    html = r.text
    links = re.findall(r'href="(\d{6,15})-([A-Za-z]+)"', html)
    phs = []
    seen = set()
    for phone, country in links:
        if phone not in seen:
            seen.add(phone)
            phs.append({'phone': phone, 'country': country})
    if not phs:
        return [], 'no-numbers'

    def fetch_msgs(item):
        r2 = _get(f'https://sms-receive.net/get_sms_register.php?phone={item["phone"]}',
                  timeout=(6, 12), headers={'Referer': f'https://sms-receive.net/',
                                            'X-Requested-With': 'XMLHttpRequest'})
        msgs = []
        if r2 is not None:
            try:
                for m in r2.json():
                    if isinstance(m, dict) and m.get('mesaje_id') and m.get('mesaj') != 'no result':
                        msgs.append({'from': m.get('telefon'), 'text': m.get('mesaj'),
                                     'time': m.get('data')})
            except Exception:
                pass
        return msgs

    with ThreadPoolExecutor(max_workers=6) as ex:
        all_msgs = list(ex.map(fetch_msgs, phs))
    return phs, all_msgs, 'ok'


# ================================================================
# 数据源 2: temporary-phone-number.com
# ================================================================

def src_tpn():
    """抓 temporary-phone-number.com 号码列表（无消息时间，用 total 近似）"""
    r = _get('https://www.temporary-phone-number.com/')
    if r is None:
        return [], 'down'
    html = r.text
    links = re.findall(r'href="/([A-Za-z]+)-Phone-Number/(\d{6,15})"', html)
    items = []
    seen = set()
    for country, phone in links:
        if phone not in seen:
            seen.add(phone)
            items.append({'phone': phone, 'country': country})
    return items, 'ok'


# ================================================================
# 数据源 3: receive-sms-online.info (fallback)
# ================================================================

def src_rosi():
    r = _get('https://receive-sms-online.info/')
    if r is None:
        return [], 'down'
    html = r.text
    items = []
    seen = set()
    for m in re.finditer(r'href="(\d{6,15})-([A-Za-z]+)"[^>]*>\s*\+(\d+)', html):
        phone, country = m.group(1), m.group(2)
        if phone not in seen:
            seen.add(phone)
            items.append({'phone': phone, 'country': country})

    def fetch_msgs(item):
        r2 = _get(f'https://receive-sms-online.info/get_sms_register.php?phone={item["phone"]}',
                  timeout=(6, 12), headers={'Referer': f'https://receive-sms-online.info/',
                                            'X-Requested-With': 'XMLHttpRequest'})
        msgs = []
        if r2 is not None:
            try:
                for m in r2.json():
                    if isinstance(m, dict) and m.get('mesaje_id') and m.get('mesaj') != 'no result':
                        msgs.append({'from': m.get('telefon'), 'text': m.get('mesaj'),
                                     'time': m.get('data')})
            except Exception:
                pass
        return msgs

    with ThreadPoolExecutor(max_workers=6) as ex:
        all_msgs = list(ex.map(fetch_msgs, items))
    return items, all_msgs, 'ok'


# ================================================================
# 数据源 3: freephonenum.com（美国/加拿大等 18 国，公开短信全文+验证码）
# ================================================================

FPN_CC = {  # 页面 2-letter 前缀 -> 国家名
    'us': 'United States', 'uk': 'United Kingdom', 'gb': 'United Kingdom',
    'ca': 'Canada', 'be': 'Belgium', 'pl': 'Poland', 'es': 'Spain',
    'se': 'Sweden', 'fi': 'Finland', 'nz': 'New Zealand', 'pr': 'Puerto Rico',
    'ro': 'Romania', 'lv': 'Latvia', 'ee': 'Estonia', 'in': 'India',
    'za': 'South Africa', 'bg': 'Bulgaria', 'pt': 'Portugal', 'nl': 'Netherlands',
}


def src_fpn():
    """freephonenum: 列表页 626 号码 + live 详情（短信全文+验证码）"""
    r = _get('https://freephonenum.com/numbers')
    if r is None:
        return [], 'down'
    html = r.text
    links = re.findall(r'href="/([a-z]{2})/receive-sms/(\d{6,15})"', html)
    items, seen = [], set()
    for cc, phone in links:
        if (cc, phone) not in seen:
            seen.add((cc, phone))
            items.append({'phone': phone, 'country': FPN_CC.get(cc, cc.upper())})
    # 只采集前 40 个做详情（避免请求过多），前 = 按页面顺序（live 优先）
    # 全量收集所有号码（用户要求收集全）
    def fetch_detail(item):
        cc_guess = None
        for c in list(FPN_CC) + ['us', 'uk', 'ca', 'be', 'pl', 'es', 'se', 'fi']:
            pass
        # 用列表里的实际 cc 链接（重新从 html 找）
        m = re.search(r'href="/([a-z]{2})/receive-sms/' + item['phone'] + r'"', html)
        cc = m.group(1) if m else 'us'
        r2 = _get(f'https://freephonenum.com/{cc}/receive-sms/{item["phone"]}')
        msgs = []
        if r2 is not None:
            h = r2.text
            blocks = re.findall(r'class="([^"]*js-msgtext[^"]*)"[^>]*>(.*?)</div>', h, re.S)
            for cls, content in blocks:
                text = re.sub(r'<[^>]+>', '', content).strip()
                if text:
                    codes = re.findall(r'\b(\d{4,8})\b', text)
                    msgs.append({'text': text[:300], 'codes': codes})
        return msgs

    # 常见国家优先拉详情（+1 美国/加拿大、英、比、荷、芬等）
    PREF = {'United States': 0, 'Canada': 0, 'United Kingdom': 1, 'Belgium': 2,
            'Netherlands': 3, 'Finland': 3, 'Poland': 4, 'Spain': 4}
    items_sorted = sorted(items, key=lambda x: PREF.get(x['country'], 9))
    detail_items = items_sorted[:80]  # 详情拉前 80（常见国家优先），其余只有号码
    with ThreadPoolExecutor(max_workers=6) as ex:
        all_msgs = list(ex.map(fetch_detail, detail_items))
    # 合并：未拉详情的补空
    by_phone = {it['phone']: msgs for it, msgs in zip(detail_items, all_msgs)}
    out = []
    for it in items:
        out.append((it, by_phone.get(it['phone'], [])))
    return out, 'ok'


# ================================================================
# 数据源 4: free-sms-receive.com（英国号，无需注册，消息含相对时间）
# ================================================================

import datetime as _dt


def parse_relative_ago(s):
    """把 '7 months ago' / '3 minutes ago' 转成 epoch 秒"""
    if not s:
        return None
    m = re.search(r'(\d+)\s+(second|minute|hour|day|week|month|year)s?\s+ago', s.strip().lower())
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2)
    secs = {'second': 1, 'minute': 60, 'hour': 3600, 'day': 86400,
            'week': 604800, 'month': 2592000, 'year': 31536000}[unit]
    return time.time() - n * secs


def src_fsr():
    """free-sms-receive.com 英国号列表 + 消息时间"""
    r = _get('https://free-sms-receive.com/')
    if r is None:
        return [], 'down'
    html = r.text
    links = re.findall(r'href="(/message/(\d{6,15})\.html)"', html)
    items, seen = [], set()
    for path, phone in links:
        if phone not in seen:
            seen.add(phone)
            items.append({'phone': phone, 'country': 'United Kingdom'})
    items = items[:30]

    def fetch_detail(item):
        r2 = _get(f'https://free-sms-receive.com/message/{item["phone"]}.html')
        msgs = []
        if r2 is not None:
            h = r2.text
            # 短信行: From +xxx / N ago / content
            rows = re.findall(r'(?s)From ([+\d]+)</div>.*?<div class="col-xs-0 col-md-2">([^<]+)</div>.*?<div class="col-xs-12 col-md-8"[^>]*>(.*?)</div>', h)
            for sender, ago, content in rows[:8]:
                ts = parse_relative_ago(ago)
                text = re.sub(r'<[^>]+>', '', content).strip()
                msgs.append({'from': sender.strip(), 'time': ago.strip(),
                             'text': text[:300], 'codes': re.findall(r'\b\d{4,8}\b', text),
                             'ts': ts})
        return msgs

    with ThreadPoolExecutor(max_workers=5) as ex:
        all_msgs = list(ex.map(fetch_detail, items))

    # 汇总带 last_ts
    out = []
    for it, msgs in zip(items, all_msgs):
        last_ts = None
        for m in msgs:
            if m['ts'] and (last_ts is None or m['ts'] > last_ts):
                last_ts = m['ts']
        out.append((it, msgs, last_ts))
    return out, 'ok'


# ================================================================
# 扫描聚合
# ================================================================

def scan_all():
    now = time.time()
    enriched = []
    src_status = {}

    # 1) sms-receive.net（首选，有消息时间）
    try:
        r = src_smsreceive()
        if len(r) == 3:
            items, all_msgs, st = r
            src_status['sms-receive.net'] = st
            if st == 'ok':
                for it, msgs in zip(items, all_msgs):
                    ts = None
                    for m in msgs:
                        t = parse_ts(m.get('time'))
                        if t is not None and (ts is None or t > ts):
                            ts = t
                    enriched.append({
                        'phone': it['phone'],
                        'country': it['country'],
                        'cc': COUNTRY_MAP.get(it['country'], '?'),
                        'last_received': ts,
                        'last_age_s': round(now - ts, 1) if ts else None,
                        'recent_msgs': msgs[-5:],
                        'source': 'sms-receive.net',
                    })
    except Exception as e:
        src_status['sms-receive.net'] = f'err:{e}'


    # 2.8) free-sms-receive.com（英国号，消息含相对时间→可评分）
    try:
        items, st = src_fsr()
        src_status['free-sms-receive.com'] = st
        if st == 'ok':
            existing = {n['phone'] for n in enriched}
            for it, msgs, last_ts in items:
                if it['phone'] in existing:
                    continue
                age = (now - last_ts) if last_ts else None
                enriched.append({
                    'phone': it['phone'],
                    'country': 'United Kingdom',
                    'cc': 'GB',
                    'last_received': last_ts,
                    'last_age_s': round(age, 1) if age is not None else None,
                    'recent_msgs': msgs[:3],
                    'source': 'free-sms-receive.com',
                })
    except Exception as e:
        src_status['free-sms-receive.com'] = f'err:{e}'

    # 2) temporary-phone-number.com（兜底号码池）
    try:
        items, st = src_tpn()
        src_status['temporary-phone-number.com'] = st
        if st == 'ok':
            existing = {n['phone'] for n in enriched}
            for it in items:
                if it['phone'] in existing:
                    continue
                enriched.append({
                    'phone': it['phone'],
                    'country': it['country'],
                    'cc': COUNTRY_MAP.get(it['country'], '?'),
                    'last_received': None,
                    'last_age_s': None,
                    'recent_msgs': [],
                    'source': 'temporary-phone-number.com',
                })
    except Exception as e:
        src_status['temporary-phone-number.com'] = f'err:{e}'

    # 2.5) freephonenum.com（全量 626 号，常见国家 80 个含短信详情）
    try:
        items, st = src_fpn()
        src_status['freephonenum.com'] = st
        if st == 'ok':
            existing = {n['phone'] for n in enriched}
            for it, msgs in items:
                if it['phone'] in existing:
                    continue
                # 短信详情里有最后 ts 估算（无明确时间戳，用文本存在与否）
                ts = None
                for m in msgs:
                    pass
                enriched.append({
                    'phone': it['phone'],
                    'country': it['country'],
                    'cc': COUNTRY_MAP.get(it['country'], it['country'][:2].upper()),
                    'last_received': None,
                    'last_age_s': None,
                    'recent_msgs': msgs[:3],
                    'source': 'freephonenum.com',
                })
    except Exception as e:
        src_status['freephonenum.com'] = f'err:{e}'


    # 3) receive-sms-online.info（恢复后自动补）
    if not any(n['source'] == 'sms-receive.net' for n in enriched):
        try:
            r = src_rosi()
            if len(r) == 3:
                items, all_msgs, st = r
                src_status['receive-sms-online.info'] = st
                if st == 'ok':
                    existing = {n['phone'] for n in enriched}
                    for it, msgs in zip(items, all_msgs):
                        if it['phone'] in existing:
                            continue
                        ts = None
                        for m in msgs:
                            t = parse_ts(m.get('time'))
                            if t is not None and (ts is None or t > ts):
                                ts = t
                        enriched.append({
                            'phone': it['phone'],
                            'country': it['country'],
                            'cc': COUNTRY_MAP.get(it['country'], '?'),
                            'last_received': ts,
                            'last_age_s': round(now - ts, 1) if ts else None,
                            'recent_msgs': msgs[-5:],
                            'source': 'receive-sms-online.info',
                        })
        except Exception as e:
            src_status['receive-sms-online.info'] = f'err:{e}'

    # ======== 刷洗（清洗分级 + 去重 + +1优先） ========
    # 1) 跨源去重（同号码保留信息最全的）
    seen_phone, dedup = set(), []
    for n in sorted(enriched, key=lambda x: -len(x['recent_msgs'])):
        if n['phone'] not in seen_phone:
            seen_phone.add(n['phone'])
            dedup.append(n)
    enriched = dedup

    # 2) 分级（活跃度标签 + 分数）
    for n in enriched:
        a = n['last_age_s']
        if a is None:
            n['grade'] = 'cold' if n.get('recent_msgs') else 'unknown'
            n['score'] = 0
        elif a < 3600:
            n['grade'] = 'hot'; n['score'] = 5
        elif a < 14400:
            n['grade'] = 'warm'; n['score'] = 4
        elif a < 86400:
            n['grade'] = 'normal'; n['score'] = 3
        else:
            n['grade'] = 'cold'; n['score'] = 1
        # +1 国家标记（美国/加拿大/加勒比）
        n['is_us'] = n.get('cc') in ('US', 'CA')

    # 3) 排序：活跃度分数降序 -> 有消息 -> +1 优先 -> 有评分
    enriched.sort(key=lambda x: (-x['score'], -len(x['recent_msgs']),
                                 not x['is_us'], x['last_age_s'] if x['last_age_s'] is not None else 9e9))
    _cache['numbers'] = enriched
    _cache['updated_at'] = now
    _cache['sources'] = src_status
    print(f'[scan] {len(enriched)} numbers | {src_status}')


def scanner_loop(interval):
    while True:
        scan_all()
        time.sleep(interval)


# ================================================================
# API
# ================================================================

@app.route('/api/numbers')
def api_numbers():
    c = request.args.get('country')
    data = _cache['numbers']
    if c:
        data = [n for n in data if n['country'].lower() == c.lower()
                or n['cc'].lower() == c.lower()]
    return jsonify({'updated_at': _cache['updated_at'], 'count': len(data), 'numbers': data})


@app.route('/api/numbers/country/<country>')
def api_country(country):
    data = [n for n in _cache['numbers']
            if n['country'].lower() == country.lower() or n['cc'].lower() == country.lower()]
    return jsonify({'count': len(data), 'numbers': data})


@app.route('/api/number/<phone>')
def api_number(phone):
    for n in _cache['numbers']:
        if n['phone'] == phone:
            return jsonify(n)
    return jsonify({'error': 'number not found'}), 404


@app.route('/api/best')
def api_best():
    min_recent = request.args.get('min_recent_min', default=0, type=int)
    country = request.args.get('country')  # us/gb/ca/be/nl/fi...
    data = [n for n in _cache['numbers']
            if n['last_age_s'] is not None and n['last_age_s'] <= min_recent * 60]
    if not data:
        data = [n for n in _cache['numbers'] if n['last_age_s'] is not None]
    if country:
        cl = country.lower()
        data = [n for n in data if n['cc'].lower() == cl or n['country'].lower() == cl]
    data.sort(key=lambda x: x['last_age_s'])
    return jsonify({'best': data[:10], 'total': len(data), 'updated_at': _cache['updated_at']})


@app.route('/api/history/<phone>')
def api_history(phone):
    # 先试 sms-receive / rosi 接口，再试 freephonenum
    r = _get(f'https://sms-receive.net/get_sms_register.php?phone={phone}',
             headers={'X-Requested-With': 'XMLHttpRequest'})
    if r is None:
        r = _get(f'https://receive-sms-online.info/get_sms_register.php?phone={phone}',
                 headers={'X-Requested-With': 'XMLHttpRequest'})
    msgs = []
    if r is not None:
        try:
            for m in r.json():
                if isinstance(m, dict) and m.get('mesaje_id') and m.get('mesaj') != 'no result':
                    msgs.append({'from': m.get('telefon'), 'text': m.get('mesaj'),
                                 'time': m.get('data'), 'codes': re.findall(r'\b\d{4,8}\b', m.get('mesaj', ''))})
        except Exception:
            pass
    if not msgs:
        # freephonenum 详情（按号码在列表里的国家前缀猜）
        for n in _cache['numbers']:
            if n['phone'] == phone:
                cc_map = {'United States': 'us', 'United Kingdom': 'uk', 'Canada': 'ca',
                          'Belgium': 'be', 'Poland': 'pl', 'Spain': 'es', 'Sweden': 'se'}
                cc = cc_map.get(n['country'], 'us')
                r2 = _get(f'https://freephonenum.com/{cc}/receive-sms/{phone}')
                if r2 is not None:
                    blocks = re.findall(r'class="([^"]*js-msgtext[^"]*)"[^>]*>(.*?)</div>', r2.text, re.S)
                    for cls, content in blocks:
                        text = re.sub(r'<[^>]+>', '', content).strip()
                        if text:
                            msgs.append({'from': '', 'text': text[:300], 'time': '',
                                         'codes': re.findall(r'\b\d{4,8}\b', text)})
                break
    return jsonify({'phone': phone, 'messages': msgs[-30:]})


@app.route('/api/health')
def api_health():
    return jsonify({'ok': True, 'updated_at': _cache['updated_at'],
                    'numbers_cached': len(_cache['numbers']),
                    'sources': _cache['sources']})


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--interval', type=int, default=60)
    args = ap.parse_args()

    print('[start] scanning...')
    scan_all()
    threading.Thread(target=scanner_loop, args=(args.interval,), daemon=True).start()
    print(f'[start] API on http://127.0.0.1:{args.port} (interval={args.interval}s)')
    app.run(host='127.0.0.1', port=args.port, debug=False)


if __name__ == '__main__':
    main()
