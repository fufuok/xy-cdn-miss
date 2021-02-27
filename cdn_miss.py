#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""
    cdn_miss.py
    ~~~~~~~~
    实时监控 Nginx 日志, 定时推送 MISS URL 到 CDN

    e.g.::

        # python3.7+
        export CDN_MISS_DEBUG=1
        export CDN_ADMIN_KEY=******
        python3 cdn_miss.py

    :author: Fufu, 2021/2/26
"""
import asyncio
import base64
import hmac
import json
import logging
import os
import re
from datetime import datetime
from hashlib import sha256
from shlex import quote

import requests

# 监控日志文件列表
log_files = ['access.log', "f.txt';echo f;echo'x"]

# txt = '26/Feb/2021:16:39:39 +0800 12.3.4.5 content.warframe.com/Cache.Windows/F.Light1E1F2D276E8D6.bulk 0.001 ' \
#       '- 32768 bytes=3930357760-3930390527 GET MISS - 206'
miss_re = re.compile(r'([^\s]+\s\+0800)\s([^\s]+)\s([\w\-\.]+)(/[^\s]+)\s(.*)?GET\sMISS\s')

# 禁止缓存, 正则, 字符串包含 (单个/多个)
miss_deny = {
    'regexp': [r'\.php(\b|\?)'],
    'contains': ['version.txt', ['test', 'xunyou']],
}

# 域名对应表
miss_domains = {
    'content.warframe.com': 'cdnwarframe-steam.mydomain.com',
}

# 网址目前都是 http
scheme = 'http://'

# CDN 推送间隔秒数
interval = 120

# 1 小时内不重复预热
miss_ttl = 3600

# 公共密钥 / 密码
cdn_admin_key = os.getenv('CDN_ADMIN_KEY')

# 初始化日志 (ES 数据上报格式)
logging.basicConfig(
    level=logging.DEBUG if os.getenv('CDN_MISS_DEBUG') else logging.INFO,
    format=json.dumps({
        'time': '%(asctime)s',
        'name': '%(name)s',
        'level': '%(levelname)s',
        'msg': '%(message)s',
    }) + '=-:-=',
    datefmt='%Y-%m-%dT%H:%M:%S+08:00',
)


class CDNMiss:
    """监控日志和检查 MISS URL"""

    def __init__(self, queue=None):
        # 黑名单 (正则)
        self.miss_deny = {'regexp': [], 'contains': []}
        for x in miss_deny.get('regexp', []):
            re_list = x if isinstance(x, (list, tuple)) else [x]
            self.miss_deny['regexp'].append([re.compile(y) for y in re_list])

        # 黑名单 (字符串包含)
        for x in miss_deny.get('contains', []):
            self.miss_deny['contains'].append(x if isinstance(x, (list, tuple)) else [x])

        # 文件和 tail 命令
        self.file_cmds = [(x, f'tail -n0 -F {quote(x)}') for x in log_files]

        # CDN 推送间隔至少 10 秒
        self.miss_ttl = miss_ttl if miss_ttl >= 10 else 120

        # 数据队列
        self.queue = queue if queue else asyncio.Queue()

        # 待预热: {网址: 时间戳}
        self.miss_urls = {}
        self.last_miss = ''

    async def main(self):
        """
        主程序, 分派任务

        :return:
        """
        # 清理
        asyncio.create_task(self.cleanup())

        # 实时获取日志
        for file, cmd in self.file_cmds:
            asyncio.create_task(self.gen_miss(file, cmd))

        # 心跳
        asyncio.create_task(self.heartbeat())
        logging.info('working...')

        while True:
            # 定时推送
            await asyncio.sleep(interval)

            # 取队列数据
            urls = []
            while not self.queue.empty():
                urls.append(self.queue.get_nowait())
                self.queue.task_done()

            # 执行推送
            urls and asyncio.create_task(PushCDN.push_cdn(urls))

    async def cleanup(self):
        """
        清理 MISS 记录

        :return:
        """
        while True:
            await asyncio.sleep(self.miss_ttl)
            now = datetime.now().timestamp()
            for k, v in list(self.miss_urls.items()):
                now - v > self.miss_ttl and self.miss_urls.pop(k, None)

    async def heartbeat(self):
        """
        心跳日志

        :return:
        """
        while True:
            logging.info('heartbeat, miss_num: %d, queue_num: %d, last_miss: %s',
                         len(self.miss_urls), self.queue.qsize(), self.last_miss)
            await asyncio.sleep(60)

    async def gen_miss(self, file, cmd):
        """
        获取最新日志记录

        :param file: str, 文件路径
        :param cmd: str, tail 命令
        :return:
        """
        # 文件不存在时重试
        while not os.access(file, os.R_OK):
            logging.error('文件不可读, 20 秒后重试: <%s>', file)
            await asyncio.sleep(20)

        # 监控日志新内容
        async for row in self.cmd_read(cmd):
            logging.debug('row: %s', row)
            asyncio.create_task(self.chk_miss(row))

    @staticmethod
    async def cmd_read(cmd):
        """
        获取持续输出的命令结果

        e.g.::

            self.cmd_read('tail -n0 -F access.log')

        :param cmd:
        :return:
        """
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        while True:
            new_line = await proc.stdout.readline()
            yield new_line.decode().strip()

    async def chk_miss(self, txt):
        """
        检查 MISS URL 是否需要推送, 加入队列

        :param txt:
        :return:
        """
        # 检查是否为 MISS URL
        res = miss_re.match(txt)
        if not res:
            logging.debug('not match miss_re: %s', txt)
            return

        # 域名转换
        domain = miss_domains.get(res.group(3))
        if not domain:
            logging.debug('not match domain: %s', txt)
            return

        miss_url = scheme + domain + res.group(4)

        # 黑名单 (字符串包含)
        for x in self.miss_deny['contains']:
            if all([y in miss_url for y in x]):
                logging.debug('deny contains: %s, %s', x, miss_url)
                return

        # 黑名单 (正则包含)
        for x in self.miss_deny['regexp']:
            if all([y.search(miss_url) for y in x]):
                logging.debug('deny regexp: %s, %s', x, miss_url)
                return

        # 新的或已过期的 MISS URL 推送到队列
        last_time = self.miss_urls.get(miss_url)
        now = datetime.now().timestamp()
        if not last_time or now - last_time > self.miss_ttl:
            self.miss_urls[miss_url] = now
            self.last_miss = miss_url
            self.queue.put_nowait(miss_url)


class PushCDN:
    """推送到 CDN"""

    @classmethod
    async def push_cdn(cls, urls):
        """
        推送 urls 到 CDN

        :param urls:
        :return:
        """
        logging.info('Preheat: %s', urls)
        asyncio.create_task(cls.preheat_hwy(urls))
        asyncio.create_task(cls.preheat_ccm(urls))

    @classmethod
    async def preheat_hwy(cls, urls):
        """
        华为云 CDN 预热
        单个 URL 的长度限制为: 10240 字符
        单次最多输入 1000 个 URL
        每天最多预热 1000 个 URL

        :param urls:
        :return:
        """
        api_url = 'https://cdn.myhuaweicloud.com/v1.0/cdn/preheatingtasks'
        token_api = 'https://cdn.myhuaweicloud.com/v3/auth/tokens'
        token_var = {
            'auth': {
                'identity': {
                    'methods': [
                        'password'
                    ],
                    'password': {
                        'user': {
                            'name': 'admin_user',
                            'password': cdn_admin_key,
                            'domain': {
                                'name': 'xunyou'
                            }
                        }
                    }
                },
                'scope': {
                    'domain': {
                        'name': 'xunyou'
                    }
                }
            }
        }

        # 获取 Token
        # https://support.huaweicloud.com/api-cdn/cdn_02_0030.html
        resp = await cls.post_json(token_api, token_var, resp_header=True)
        token = resp and resp.get('headers', {}).get('X-Subject-Token')
        if not token:
            logging.error('华为云 CDN Token 获取失败')
            return
        headers = {'X-Auth-Token': token}

        # 预热
        # Ref: https://support.huaweicloud.com/api-cdn/cdn_02_0046.html
        pos = 0
        num = 900
        urls_seg = urls[pos:num]
        while urls_seg:
            data = {
                'preheatingTask': {
                    'urls': urls_seg,
                }
            }
            resp = await cls.post_json(api_url, data, headers)
            if not resp or not resp.get('preheatingTask', {}).get('total'):
                logging.error('华为云 CDN 预热失败: %s', resp)
            urls_seg = urls[pos + num:num]

    @classmethod
    async def preheat_ccm(cls, urls):
        """
        网宿 CDN 预热
        调用频率: 10/5min
        每个 URL 最大长度: 2000 字符
        每次提交: < 400 URL
        每日不超过: 20000 条

        :param urls:
        :return:
        """
        api_url = 'https://open.chinanetcenter.com/ccm/fetch/ItemIdReceiver'
        api_user = 'admin_user'
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        # 生成鉴权
        # Ref: https://www.wangsu.com/document/cate/13076/13077
        sign = hmac.new(cdn_admin_key.encode(), date.encode(), sha256).digest()
        sign = base64.b64encode(sign)
        sign = api_user + ':' + sign.decode()
        sign = base64.b64encode(sign.encode()).decode()
        headers = {
            'Date': date,
            'Accept': 'application/json',
            'Content-type': 'application/json',
            'Authorization': 'Basic ' + sign,
        }

        # 预热
        # Ref: https://www.wangsu.com/document/cate/13076/17537
        pos = 0
        num = 350
        urls_seg = urls[pos:num]
        while urls_seg:
            data = {
                'urls': urls,
            }
            resp = await cls.post_json(api_url, data, headers)
            if not resp or not resp.get('Code', 0) == 1:
                logging.error('网宿 CDN 预热失败: %s', resp)
            urls_seg = urls[pos + num:num]

    @classmethod
    async def post_json(cls, url, data, headers=None, resp_header=False):
        """
        JSON POST 请求

        :param url:
        :param data:
        :param headers: dict, 请求头
        :param resp_header: bool, 是否返回头信息
        :return:
        """
        return await asyncio.get_running_loop().run_in_executor(None, cls.post_json_requests,
                                                                url, data, headers, resp_header)
        # try:
        #     async with aiohttp.request('POST', url, json=data, headers=headers) as resp:
        #         res = await resp.json()
        #         logging.debug('url: %s, res: %s, headers: %s', url, res, resp.headers)
        #         return {'headers': resp.headers, 'resp': res} if resp_header else res
        # except Exception as e:
        #     logging.error('POST 请求失败: %s, url: %s, data: %s', e, url, data)
        #     return {}

    @classmethod
    def post_json_requests(cls, url, data, headers=None, resp_header=False):
        """
        JSON POST 请求

        :param url:
        :param data:
        :param headers: dict, 请求头
        :param resp_header: bool, 是否返回头信息
        :return:
        """
        try:
            resp = requests.post(url, json=data, headers=headers)
            res = resp.json()
            logging.debug('url: %s, req_header: %s, req_body: %s, resp_header: %s, resp_body: %s',
                          url, resp.request.headers, resp.request.body, resp.headers, res)
            return {'headers': resp.headers, 'resp': res} if resp_header else res
        except Exception as e:
            logging.error('POST 请求失败: %s, url: %s, data: %s', e, url, data)
            return {}


if __name__ == '__main__':
    cdn_admin_key and log_files or logging.critical('环境变量(CDN_ADMIN_KEY) 或 日志文件为空') or exit(1)
    asyncio.run(CDNMiss().main())
