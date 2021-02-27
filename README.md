# XY.CDNMiss (CDN Miss 预热)

## 功能

实时监控 `Nginx` 日志, 定时推送 `MISS URL` 到 `CDN`

**注意:**

- 重启程序后, 可能再次提交已经预热中的 URL (不影响)

## 特征

- 高性能
- 易扩展
- 推送黑名单: 每组支持单个/多个正则或字符串
- ES 数据格式日志

## 依赖

- `python3.7+`
- `requests`

## 使用

```shell
# python3.7+
pip3 install requests

export CDN_MISS_DEBUG=1
export CDN_ADMIN_KEY=******

python3 cdn_miss.py
```

配置参数见代码文件头部.

日志格式示例:

> 26/Feb/2021:16:39:39 +0800 12.3.4.5 content.warframe.com/Cache.Windows/F.Light1E1F2D276E8D6.bulk 0.001 - 32768 bytes=3930357760-3930390527 GET MISS - 206

格式变化后需要修改正则:

```python
([^\s]+\s\+0800)\s([^\s]+)\s([\w\-\.]+)(/[^\s]+)\s(.*)?GET\sMISS\s
```





*ff*