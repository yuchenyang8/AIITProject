from functools import wraps
from flask import session, redirect, url_for, current_app
import random
import psutil
import os
import requests
import json


def login_required(func):
    """登录验证装饰器"""

    @wraps(func)
    def inner(*args, **kwargs):
        user = session.get('status')
        if not user:
            return redirect(url_for('system_login'), 302)
        return func(*args, **kwargs)

    return inner


def get_user_agent():
    user_agent_list = [
        {'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)'},
        {'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00'},
        {
            'User-Agent': 'Mozilla/5.0 (X11; U; Linux i686; de; rv:1.9.0.2) Gecko/2008092313 Ubuntu/8.04 (hardy) Firefox/3.0.2'},
        {
            'User-Agent': 'Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.9.1.15) Gecko/20101027 Fedora/3.5.15-1.fc12 Firefox/3.5.15'},
        {
            'User-Agent': 'Mozilla/5.0 (X11; U; Linux i686; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.551.0 Safari/534.10'},
        {'User-Agent': 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.2) Gecko/2008092809 Gentoo Firefox/3.0.2'},
        {
            'User-Agent': 'Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/7.0.544.0'},
        {'User-Agent': 'Opera/9.10 (Windows NT 5.2; U; en)'},
        {
            'User-Agent': 'Mozilla/5.0 (iPhone; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko)'},
        {'User-Agent': 'Opera/9.80 (X11; U; Linux i686; en-US; rv:1.9.2.3) Presto/2.2.15 Version/10.10'},
        {
            'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5'},
        {'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; ru; rv:1.9b3) Gecko/2008020514 Firefox/3.0b3'},
        {
            'User-Agent': 'Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_4_11; fr) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16'},
        {
            'User-Agent': 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-US) AppleWebKit/534.20 (KHTML, like Gecko) Chrome/11.0.672.2 Safari/534.20'},
        {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)'},
        {'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux x86_64; en) Opera 9.60'},
        {
            'User-Agent': 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_2; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.366.0 Safari/533.4'},
        {'User-Agent': 'Mozilla/5.0 (Windows NT 6.0; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.51'}
    ]
    return random.choice(user_agent_list)


def kill_process(name):
    pids = psutil.pids()
    for pid in pids:
        p = psutil.Process(pid)
        if p.name() == name:
            print(pid, name)
            # Windows
            cmd = r'taskkill /F /IM ' + name
            os.system(cmd)
            break


def push_dingding_group(content):
    headers = {"Content-Type": "application/json"}
    # 消息类型和数据格式参照钉钉开发文档
    data = {"msgtype": "markdown", "markdown": {"title": "xray 发现了新漏洞"}}
    data['markdown']['text'] = content
    r = requests.post(
        "https://oapi.dingtalk.com/robot/send?access_token=add36dd6ed87b89f7ae4de8db77f9810df57aced7fc466a68fcda06dc9aa4cde",
        data=json.dumps(data),
        headers=headers)
