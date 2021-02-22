from flask import Flask
from flask_pymongo import PyMongo
from client.nmapScan import Nmap_portscan

app = Flask(__name__)
mongo = PyMongo(app, uri="mongodb://localhost:27017/test")

@app.route('/')
def hello_world():
    return 'Hello World!'

@app.route('/home')
def hello():
    return '22'

if __name__ == '__main__':
    app.run()
