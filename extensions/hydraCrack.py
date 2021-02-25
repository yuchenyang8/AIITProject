import os
import re


def hydraTask(ip):
    # ip = '192.168.31.11'
    # cmd = 'D:\HYDRA\hydra.exe -l admin -p admin 10.0.102.66 ssh'
    username = r'D:\HYDRA\username.txt'
    password = r'D:\HYDRA\password.txt'
    service = 'ssh'
    cmd = 'D:\HYDRA\hydra.exe -L %s -P %s %s %s' % (username, password, ip, service)
    osresult = os.popen(cmd)
    result = osresult.readlines()

    mydict = {}
    mydict['host'] = ip
    pattern_username = 'login:\s(.+?)\s+password:'
    pattern_password = 'password:\s(.+?)$'
    for res in result:
        if re.findall(pattern_username, res):
            username = re.findall(pattern_username, res)[0]
            mydict['username'] = username
        else:
            username = "None"
        if re.findall(pattern_password, res):
            password = re.findall(pattern_password, res)[0]
            mydict['password'] = password
        else:
            password = "None"
    return mydict

print(hydraTask('192.168.31.11'))