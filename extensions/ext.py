# -*- coding: utf-8 -*-
import requests
import re
import nmap
import subprocess
import os
from extensions.OneForAll.oneforall import OneForAll
import platform

SYSTEM = platform.system()


class NmapExt(object):
    """Nmap插件类"""

    def __init__(self, hosts, ports):
        self.hosts = hosts
        self.ports = ports
        # self.arguments = arguments

    def host_discovery(self):
        """主机存活探测"""
        nm = nmap.PortScanner()
        hosts = self.hosts
        # -------------------------------------------------------------------------------------------------
        # big ip segment
        # arguments = '-sP -n -PE -PP -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 --source-port 53 ' \
        #             '--min-hostgroup 1024 --min-parallelism 1024 -oG hosts.txt'
        # -------------------------------------------------------------------------------------------------
        # small ip segment
        arguments = '-sP -PE -PP -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 --source-port 53 -T4'
        result = nm.scan(hosts=hosts, arguments=arguments)
        host_list = []
        for r in result['scan']:
            host_list.append(r)
        return host_list
        # print(nm.scaninfo())
        # print(nm.scanstats())
        # print(nm.scan_result)

    def port_scan(self):
        """端口扫描"""
        nm = nmap.PortScanner()
        hosts = self.hosts
        ports = self.ports
        arguments = '-Pn -T4 -sV --version-all'
        print('1: ', dir(nm))
        nm.scan(hosts=hosts, ports=ports, arguments=arguments)
        print(dir(nm))
        print(nm._scan_result)
        # {'nmap': {'command_line': 'nmap -oX - -p 1-65535 -Pn -T4 -sV --version-all --min-parallelism 1024 aiit.org.cn', 'scaninfo': {'error': ["Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.\r\nWarning: Your --min-parallelism option is pretty high!  This can hurt reliability.\r\n"], 'warning': ['Warning: Your --min-parallelism option is pretty high!  This can hurt reliability.\r\n'], 'tcp': {'method': 'syn', 'services': '1-65535'}}, 'scanstats': {'timestr': 'Tue Mar 02 17:02:39 2021', 'elapsed': '196.52', 'uphosts': '1', 'downhosts': '0', 'totalhosts': '1'}}, 'scan': {'47.98.147.82': {'hostnames': [{'name': 'aiit.org.cn', 'type': 'user'}], 'addresses': {'ipv4': '47.98.147.82'}, 'vendor': {}, 'status': {'state': 'up', 'reason': 'user-set'}, 'tcp': {22: {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh', 'product': 'OpenSSH', 'version': '6.6.1', 'extrainfo': 'protocol 2.0', 'conf': '10', 'cpe': 'cpe:/a:openbsd:openssh:6.6.1'}, 80: {'state': 'open', 'reason': 'syn-ack', 'name': 'http', 'product': 'nginx', 'version': '', 'extrainfo': '', 'conf': '10', 'cpe': 'cpe:/a:igor_sysoev:nginx'}, 3389: {'state': 'closed', 'reason': 'reset', 'name': 'ms-wbt-server', 'product': '', 'version': '', 'extrainfo': '', 'conf': '3', 'cpe': ''}}}}}
        #
        # nm.scan(hosts=hosts, ports=ports, arguments='-sF -T4')
        # print(nm.scan_result)
        #
        # nm.scan(hosts=hosts, ports=ports, arguments='-sA -T4')
        # print(nm.scan_result)
        #
        port_list = []
        value_list = []
        for ip in nm.scan_result['scan']:
            for port in nm.scan_result['scan'][ip]['tcp']:
                port_list.append(str(port))
                value_list.append(nm.scan_result['scan'][ip]['tcp'][port])
        scan_result = dict(zip(port_list, value_list))
        # nm.scan_result['scan'][ip]['tcp'] = scan_result
        return scan_result

    def c_segment(self):
        """C段扫描"""
        nm = nmap.PortScanner()
        hosts = self.hosts + '/24'
        ports = '80'
        arguments = '-Pn -sS -T4'
        nm.scan(hosts=hosts, ports=ports, arguments=arguments)
        # 'nmap -Pn -sS -p80 -T4 aiit.org.cn/24 -oG result.txt'
        open_ip = []
        filtered_ip = []
        for ip in nm.scan_result['scan']:
            if nm.scan_result['scan'][ip]['tcp'][80]['state'] == 'open':
                open_ip.append(ip)
            if nm.scan_result['scan'][ip]['tcp'][80]['state'] == 'filtered':
                filtered_ip.append(ip)
        ip_title = []
        for ip in open_ip:
            url = 'http://' + ip + ':' + ports
            headers = {'Accept-Language': 'zh-CN,zh;q=0.9'}
            try:
                r = requests.get(url=url, headers=headers, timeout=5)
            except requests.exceptions.RequestException as e:
                pass
            charset = re.findall(r'charset=.*?(.+?)"', r.text)
            r.encoding = charset[0] if charset else 'utf-8'
            result = re.findall(r"<title.*?>(.+?)</title>", r.text)
            title = result[0] if result else 'None'
            ip_title.append(title)
        c_result = dict(zip(open_ip, ip_title))
        # filtered_result = dict.fromkeys(filtered_ip, 'FILTERED')
        # c_result.update(filtered_result)
        return c_result


# -----------------------------------
# 子域扫描模块
# -----------------------------------
class OneForAllExt(object):
    """OneForAll插件类"""

    def __init__(self, domain):
        self.domain = domain

    def subdomain_discovery(self):
        task = OneForAll(self.domain)
        task.dns = True
        task.brute = True
        task.req = True
        task.takeover = True
        task.run()
        result = []
        for d in task.datas:
            result.append(d['subdomain'])
        result = list(set(result))
        return result


# -----------------------------------
# web指纹模块
# -----------------------------------
class WhatwebExt(object):
    """whatweb插件类"""

    def __init__(self, domain):
        self.domain = domain

    def web_fingerprint(self):
        project_root_dir = os.getcwd()
        print(project_root_dir)
        whatweb_dir = project_root_dir + '/WhatWeb/whatweb'
        print('!!!!!', SYSTEM)
        if SYSTEM == "Windows":
            command_str = 'ruby ' + f'{whatweb_dir} ' + ' --colour=never ' + self.domain
        else:
            command_str = f'{whatweb_dir} ' + ' --colour=never ' + self.domain
        command = command_str.split(' ')

        p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.wait()
        out = p.stdout.read().decode()
        items = out.split('\n')
        items.remove('')
        # print(len(items))
        # print(items)
        # print('out: ', out)

        ip_re = r'IP\[(.*?)\]'
        domain_re = r'(.*?) \[200'
        country_re = r'Country\[(.*?)\]'
        httpserver_re = r'HTTPServer\[(.*?)\]'
        metagenerator_re = r'MetaGenerator\[(.*?)\]'
        xpoweredby_re = r'X-Powered-By\[(.*?)\]'

        result = {}

        for item in items:
            ip = re.findall(ip_re, item, re.S)
            print('###', type(ip))
            print('###', ip)
            domain = re.findall(domain_re, item, re.S)
            print('###', type(domain))
            country = re.findall(country_re, item, re.S)
            httpserver = re.findall(httpserver_re, item, re.S)
            metagenerator = re.findall(metagenerator_re, item, re.S)
            xpoweredby = re.findall(xpoweredby_re, item, re.S)

            temp = {}

            temp['ip'] = ip[0] if ip else ''
            temp['domain'] = domain[0] if domain else ''
            temp['country'] = country[0] if country else ''
            temp['httpserver'] = httpserver[0] if httpserver else ''
            temp['metagenerator'] = metagenerator[0] if metagenerator else ''
            temp['xpoweredby'] = xpoweredby[0] if xpoweredby else ''

            result[domain[0]] = temp

        print(result)
        return result


w = WhatwebExt('aiit.org.cn').web_fingerprint()