# sms-otp — 国外临时号筛选/监控

- sms_api.py：多源聚合（免费站）+ 活跃度评分（最后接收时间）+ 多源自动切换
- sms_monitor.py：单号轮询 OTP 提取

```bash
python sms_api.py --port 8080
curl http://127.0.0.1:8080/api/best
```
