# -*- coding: utf-8 -*-
"""
sms_monitor.py — 轮询 receive-sms-online.info 号码，等待验证码
用法: python sms_monitor.py <phone> <regex-sub> <outfile> [interval]
"""
import re, requests, sys, io, json, time
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
import urllib3
urllib3.disable_warnings()

phone = sys.argv[1] if len(sys.argv) > 1 else '46731299507'
outfile = sys.argv[2] if len(sys.argv) > 2 else r'C:\Users\wwww\lobsterai\project\.cowork-temp\otp_result.txt'
interval = int(sys.argv[3]) if len(sys.argv) > 3 else 10
max_seconds = int(sys.argv[4]) if len(sys.argv) > 4 else 1800

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
           'X-Requested-With': 'XMLHttpRequest',
           'Referer': f'https://receive-sms-online.info/{phone}-Sweden'}
URL = f'https://receive-sms-online.info/get_sms_register.php?phone={phone}'

seen = set()
start = time.time()
print(f'[monitor] {phone} started, interval={interval}s, max={max_seconds}s')

# 先跑一次，记录已有消息（避免把历史消息当新验证码）
def fetch():
    for attempt in range(3):
        try:
            r = requests.get(URL, headers=headers, timeout=20, verify=False)
            return r
        except Exception as e:
            print(f'[monitor] fetch err {type(e).__name__}, retry')
            time.sleep(2)
    return None

# baseline
r = fetch()
if r is not None and 'no result' not in r.text:
    try:
        for m in r.json():
            if m.get('mesaje_id'):
                seen.add(m['mesaje_id'])
    except Exception:
        pass
print(f'[monitor] baseline seen={len(seen)}')

while time.time() - start < max_seconds:
    r = fetch()
    if r is not None:
        try:
            data = r.json()
            new_msgs = [m for m in data if m.get('mesaje_id') and m['mesaje_id'] not in seen and m.get('mesaj') not in (None, '', 'no result')]
            if new_msgs:
                for m in new_msgs:
                    seen.add(m['mesaje_id'])
                    mesaj = m.get('mesaj', '')
                    # 提取验证码: 4-8位数字
                    codes = re.findall(r'\b\d{4,8}\b', mesaj)
                    print(f'[monitor] NEW SMS from {m.get("telefon")}: {mesaj!r}')
                    if codes:
                        for c in codes:
                            print(f'[monitor] >>> OTP CANDIDATE: {c}')
                    # 写结果文件（JSON 全量 + 纯文本）
                    with open(outfile, 'a', encoding='utf-8') as f:
                        f.write(f'[{time.strftime("%H:%M:%S")}] FROM={m.get("telefon")} TEXT={mesaj}\n')
                    if codes:
                        with open(outfile + '.otp', 'a', encoding='utf-8') as f:
                            f.write(f'OTP: {codes[0]}\n')
                        print(f'[monitor] >>> saved OTP {codes[0]} to {outfile}.otp')
                        # 命中后仍继续轮询（可能有多条），但把结果写好了
        except Exception as e:
            print(f'[monitor] parse err: {e}')
    time.sleep(interval)

print('[monitor] timeout, done')
