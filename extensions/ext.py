# -*- coding: utf-8 -*-
import requests
import re
import nmap
import subprocess
import os
from extensions.OneForAll.oneforall import OneForAll
import platform
import json
from web.utils.auxiliary import exist_process, kill_process, url_detect
from extensions.Wappalyzer import Wappalyzer, WebPage
import warnings
import urllib3
import time

urllib3.disable_warnings()

warnings.filterwarnings(action='ignore')

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
        nm.scan(hosts=hosts, ports=ports, arguments=arguments)
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
        result = url_detect(list(set(result)))

        return result


class WhatwebExt(object):
    """whatweb插件类"""

    def __init__(self, domain):
        self.domain = domain
        self.TOOL_DIR = r'D:\UY\AIITProject\extensions\WhatWeb\whatweb'

    def web_fingerprint(self):
        whatweb_dir = self.TOOL_DIR
        # print('!!!!!', SYSTEM)
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

        # ip_re = r'IP\[(.*?)\]'
        # domain_re = r'(.*?) \[200'
        # country_re = r'Country\[(.*?)\]'
        httpserver_re = r'HTTPServer\[(.*?)\]'
        metagenerator_re = r'MetaGenerator\[(.*?)\]'
        xpoweredby_re = r'X-Powered-By\[(.*?)\]'

        result = {}
        print(items)
        for item in items:
            # ip = re.findall(ip_re, item, re.S)
            # domain = re.findall(domain_re, item, re.S)
            # country = re.findall(country_re, item, re.S)
            httpserver = re.findall(httpserver_re, item, re.S)
            metagenerator = re.findall(metagenerator_re, item, re.S)
            xpoweredby = re.findall(xpoweredby_re, item, re.S)

            # temp['ip'] = ip[0] if ip else ''
            # temp['domain'] = domain[0] if domain else ''
            # temp['country'] = country[0] if country else ''
            result['httpserver'] = httpserver[0] if httpserver else ''
            result['metagenerator'] = metagenerator[0] if metagenerator else ''
            result['xpoweredby'] = xpoweredby[0] if xpoweredby else ''

        return result


class DirExt(object):
    """Dirsearch插件类"""

    def __init__(self, url):
        self.url = url
        self.TOOL_DIR = r'D:\UY\dirsearch\dirsearch.py'
        self.RESULT_DIR = r'D:\UY\dirsearch\result.json'

    def dir_scan(self):
        command = 'python {} -e * -x 403,404,405,500,501,502,503 -u {} --json-report {}'.format(self.TOOL_DIR, self.url,
                                                                                                self.RESULT_DIR)
        os.popen(command).read()
        with open(self.RESULT_DIR, 'r+', encoding='utf-8') as f:
            data = json.load(f)
        result = []
        for d in data:
            if d == 'time':
                continue
            for i in data[d]:
                if i['status'] == 200:
                    result.append(d[:-1] + i['path'])
                # elif i['status'] == 301:
                #     result.append(i['redirect'])
        result = list(set(result))
        f.close()
        return result


class WafExt(object):
    """Wafw00f插件类"""

    def __init__(self):
        self.TOOL_DIR = r'D:\UY\AIITProject\extensions\wafw00f\wafw00f\main.py'
        self.RESULT_DIR = r'D:\UY\AIITProject\extensions\wafw00f\result.json'

    def detect(self, url):
        flag = False
        try:
            https_url = 'https://' + url
            requests.get(https_url, timeout=3)
            command = 'python {} -v -o {} {}'.format(self.TOOL_DIR, self.RESULT_DIR, https_url)
            os.popen(command).read()
            flag = True
        except:
            pass
        if not flag:
            try:
                http_url = 'http://' + url
                command = 'python {} -v -o {} {}'.format(self.TOOL_DIR, self.RESULT_DIR, http_url)
                os.popen(command).read()
            except:
                pass

        with open(self.RESULT_DIR, 'r+', encoding='utf-8') as f:
            data = json.load(f)
        result = data[0]['firewall'] if data else 'None'
        f.close()
        return result


class HydraExt(object):
    """Hydra插件类"""

    def __init__(self, host):
        self.host = host
        self.thread = 16
        self.TOOL_DIR = r'D:\HYDRA'
        # self.RESULT_DIR = r'D:\HYDRA\result.txt'

    def crack(self, service):
        username = r'D:\HYDRA\username.txt'
        password = r'D:\HYDRA\password.txt'
        thread = self.thread
        host = self.host
        command = r'{}\hydra -L {} -P {} -t {} -f {} {}'.format(self.TOOL_DIR, username, password, thread,
                                                                host, service)
        result = os.popen(command).readlines()
        resultdict = {'host': host}
        pattern_username = 'login:\s(.+?)\s+password:'
        pattern_password = 'password:\s(.+?)$'
        flag = False
        for res in result:
            print(res)
            if not res.find('[' + service + ']'):
                continue
            if re.findall(pattern_username, res):
                resultdict['username'] = re.findall(pattern_username, res)[0]
            if re.findall(pattern_password, res):
                resultdict['password'] = re.findall(pattern_password, res)[0]
                flag = True
                break
        if flag:
            return resultdict
        else:
            return flag


class XrayExt(object):
    """Xray插件类"""

    def __init__(self):
        self.XRAY_DIR = r'D:\Xray'
        self.RAD_DIR = r'D:\UY\rad'
        self.CHROME_DIR = r'C:\Program Files\Google\Chrome\Application\chrome.exe'
        self.start_xray()

    def start_xray(self):
        print('***xray')
        # result_dir = r'D:\Xray\{}.json'.format(datetime.datetime.now().strftime("%Y_%m%d_%H%M%S"))
        # print(result_dir)
        if exist_process('xray.exe'):
            kill_process('xray.exe')
        webhook = 'http://127.0.0.1:5000/func/webhook'
        command = r'{}\xray webscan --listen 127.0.0.1:7777 --webhook-output {}'.format(self.XRAY_DIR, webhook)
        subprocess.Popen(command, shell=True)

    # def scan_all(self):
    #     file = open(self.CRAWLERGO_DIR + r"\targets.txt")
    #     for text in file.readlines():
    #         url = text.strip('\n')
    #         self.scan_one(url)

    def scan_one(self, url):
        print('***scan')
        # command = r'{}/crawlergo -c {} -t 10 -f smart --fuzz-path --output-mode json {}'.format(self.CRAWLERGO_DIR,
        #                                                                                         self.CHROME_DIR, url)
        cmd = r'{}\rad -t {} --http-proxy 127.0.0.1:7777'.format(self.RAD_DIR, url)
        subprocess.Popen(cmd)
        # [*] All pending requests have been scanned


class WappExt(object):
    """Wappalyzer插件类"""

    # def __init__(self):

    def detect(self, url):
        url = 'http://' + url
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        result = wappalyzer.analyze_with_versions_and_categories(webpage)
        return result


class NessusExt(object):
    """Nessus插件类"""

    def __init__(self):
        self.url = 'https://localhost:8834'
        self.accessKey = '2179ddb0a05e92c6b35f394a597290d6ae95645d0918859135ae3b06d4e9b013'
        self.secretKey = '6bc3a119840685bcf1fc58cfdc693791185227f85dd4cef40f72c0fe86c4afb5'
        self.verify = False

    def __build_url(self, resource):
        """拼接url"""

        return '{0}{1}'.format(self.url, resource)

    def __connect(self, method, resource, data=None):
        """向Nessus发送请求"""

        headers = {'X-ApiKeys': 'accessKey={accesskey};secretKey={secretkey}'.format(accesskey=self.accessKey,
                                                                                     secretkey=self.secretKey),
                   'content-type': 'application/json'}
        verify = self.verify
        data = json.dumps(data)

        if method == 'POST':
            r = requests.post(self.__build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'PUT':
            r = requests.put(self.__build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'DELETE':
            r = requests.delete(self.__build_url(resource), data=data, headers=headers, verify=verify)
        else:
            r = requests.get(self.__build_url(resource), params=data, headers=headers, verify=verify)

        # Exit if there is an error.
        if r.status_code != 200:
            e = r.json()
            print(e['error'])

        # When downloading a scan we need the raw contents not the JSON data.
        if 'download' in resource:
            return r.content
        else:
            return r.json()

    def __get_policies(self):
        """获取扫描模板"""

        data = self.__connect('GET', '/editor/policy/templates')

        return dict((p['title'], p['uuid']) for p in data['templates'])

    def __get_history_ids(self, sid):
        """获取任务的所有历史扫描id"""

        data = self.__connect('GET', '/scans/{0}'.format(sid))

        return dict((h['uuid'], h['history_id']) for h in data['history'])

    def __update(self, scan_id, name, targets, enabled, pid=None):
        """更新扫描任务信息"""

        scan = {'settings': {}}
        scan['settings']['name'] = name
        scan['settings']['enabled'] = enabled
        scan['settings']['text_targets'] = targets

        if pid is not None:
            scan['uuid'] = pid

        data = self.__connect('PUT', '/scans/{0}'.format(scan_id), data=scan)

        return data

    def __get_scan_history(self, sid, hid):
        """
        Scan history details
        Get the details of a particular run of a scan.
        """
        params = {'history_id': hid}
        data = self.__connect('GET', '/scans/{0}'.format(sid), params)

        return data['info']

    def __status(self, sid, hid):
        """查询扫描状态"""

        d = self.__get_scan_history(sid, hid)
        return d['status']

    def __export_status(self, sid, fid):
        """
        Check export status
        Check to see if the export is ready for download.
        """

        data = self.__connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))

        return data['status'] == 'ready'

    def __export(self, sid, hid):
        """
        Make an export request
        Request an export of the scan results for the specified scan and
        historical run. In this case the format is hard coded as nessus but the
        format can be any one of nessus, html, pdf, csv, or db. Once the request
        is made, we have to wait for the export to be ready.
        """

        data = {'history_id': hid,
                'format': 'nessus'}

        data = self.__connect('POST', '/scans/{0}/export'.format(sid), data=data)

        fid = data['file']

        while self.__export_status(sid, fid) is False:
            time.sleep(5)

        return fid

    def __download(self, sid, fid):
        """
        Download the scan results
        Download the scan results stored in the export file specified by fid for
        the scan specified by sid.
        """

        data = self.__connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
        filename = 'nessus_{0}_{1}.nessus'.format(sid, fid)

        print('Saving scan results to {0}.'.format(filename))
        with open(filename, 'w') as f:
            f.write(data)

    def __delete(self, scan_id):
        """删除扫描任务"""

        self.__connect('DELETE', '/scans/{0}'.format(scan_id))

    def __history_delete(self, sid, hid):
        """删除任务历史扫描"""

        self.__connect('DELETE', '/scans/{0}/history/{1}'.format(sid, hid))

    def create(self, name, targets, enabled=False, uuid=''):
        """添加一个新的扫描任务"""
        if uuid == '':
            uuid = self.__get_policies()['Advanced Scan']
        scan = {'uuid': uuid,
                'settings': {
                    'name': name,  # 任务名称
                    'enabled': enabled,  # 是否开启定时任务
                    'text_targets': targets,
                }
                }
        data = self.__connect('POST', '/scans', data=scan)

        # 返回scan_id
        return data['scan']['id']

    def launch(self, scan_id):
        """执行扫描"""
        try:
            data = self.__connect('POST', '/scans/{0}/launch'.format(scan_id))
            scan_uuid = data['scan_uuid']
            history_ids = self.__get_history_ids(scan_id)
            history_id = history_ids[scan_uuid]
            return history_id
        except:
            return False

    def get_plugin_detail(self, plugin_id):
        """获取漏洞详情"""

        data = self.__connect('GET', '/plugins/plugin/{0}'.format(plugin_id))
        detail = {'family_name': data['family_name']}
        for item in data['attributes']:
            attr_name = item['attribute_name']
            attr_value = item['attribute_value']
            if attr_name == 'cve':
                detail.update({'cve': attr_value})
            elif attr_name == 'exploitability_ease':
                detail.update({'exploitability_ease': attr_value})
            elif attr_name == 'vuln_publication_date':
                detail.update({'vuln_publication_date': attr_value})
            elif attr_name == 'solution':
                detail.update({'solution': attr_value})
            elif attr_name == 'risk_factor':
                detail.update({'risk_factor': attr_value})
            elif attr_name == 'description':
                detail.update({'description': attr_value})
            elif attr_name == 'synopsis':
                detail.update({'synopsis': attr_value})

        return detail

    def get_vuln_result(self, scan_id, history_id):
        """获取扫描结果"""

        while self.__status(scan_id, history_id) != 'completed':
            time.sleep(5)
        params = {'history_id': history_id}
        data = self.__connect('GET', '/scans/{0}'.format(scan_id), params)

        return data['vulnerabilities']


if __name__ == '__main__':
    # kill_process('xray.exe')
    # r = HydraExt('192.168.31.13').crack('ssh')
    # XrayExt().scan_one(url='testphp.vulnweb.com')

    # scan_id = n.create(name='192.168.31.19', targets='192.168.31.19')
    # history_id = n.launch(scan_id)

    pass
