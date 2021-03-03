# -*- coding: utf-8 -*-
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


# n = NmapExt(hosts='aiit.org.cn/24', ports='1-100')
# result = n.host_discovery()
#
# n = NmapExt(hosts='aiit.org.cn', ports='1-100')
# result = n.port_scan()
# print(result)

