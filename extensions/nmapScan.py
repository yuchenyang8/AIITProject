import nmap
from flask_pymongo import PyMongo
from flask import Flask


app = Flask(__name__)
mongo = PyMongo(app, uri="mongodb://localhost:27017/test")
print(mongo.db.portsdb.find())


def Nmap_portscan(ip):
    nm = nmap.PortScanner()
    # ip = '60.190.132.226'
    ports = '1-65535'
    nm.scan(hosts=ip, ports=ports, arguments='-Pn -T4 -sV --version-intensity=5')
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
    # mongo.db.portsdb.insert_one(mydict)