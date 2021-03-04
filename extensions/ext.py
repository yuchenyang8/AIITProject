# -*- coding: utf-8 -*-
import requests
import re
import nmap


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
        nm.scan(hosts=hosts, ports=ports, arguments=arguments)
        # print(nm.scan_result)
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

# n = NmapExt(hosts='aiit.org.cn', ports='1-65535')
# n.c_segment()
# n = NmapExt(hosts='aiit.org.cn/24', ports='1-100')
# result = n.host_discovery()
#
# n = NmapExt(hosts='aiit.org.cn', ports='1-100')
# result = n.port_scan()
# print(result)

# import requests
# import json
#
# url = "http://finger.tidesec.com"
# header = {
#     "Host": "finger.tidesec.com",
#     "Content-Length": "17",
#     "Accept": "*/*",
#     "X-Requested-With": "XMLHttpRequest",
#     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
#     "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
#     "Origin": "http://finger.tidesec.com",
#     "Referer": "http://finger.tidesec.com/",
#     "Accept-Encoding": "gzip, deflate",
#     "Accept-Language": "zh-CN,zh;q=0.9",
#     "Connection": "close"
# }
# cookie = {'PHPSESSID': 'bmp5rpm38h6n7k9pdnjgt2prb4'}
# data = {'target': 'aiit.org.cn'}
# r = requests.post(url=url, headers=header, cookies=cookie, data=data)
# print(r.text)
