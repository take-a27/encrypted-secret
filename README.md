# 32byteの共通鍵生成
```
openssl rand -base64 1000 | dd of=sample.key bs=32 count=1
```
