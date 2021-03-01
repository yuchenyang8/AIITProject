import nmap


class NmapExt:
    """Nmap插件类"""
    def __init__(self, ip, ports, arguments):
        self.ip = ip
        self.ports = ports
        self.arguments = arguments

    def hostscan(self):
        """主机存活探测"""
        nm = nmap.PortScanner()
        ports = self.ports
        ip = self.ip
        arguments = self.arguments
        nm.scan(hosts=ip, ports=ports, arguments=arguments)
        # '-Pn -T4 -sV --version-intensity=5'
        # print(nm[ip])
        mydict = nm[ip]
        key_list = []
        value_list = []
        for i in mydict['tcp'].keys():
            key_list.append(str(i))
            value_list.append(mydict['tcp'][i])
        newdict = dict(zip(key_list, value_list))
        mydict['tcp'] = newdict
        print(mydict)
        return mydict
