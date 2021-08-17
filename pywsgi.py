from gevent import monkey

monkey.patch_all()
from app import APP
from gevent.pywsgi import WSGIServer

server = WSGIServer(('127.0.0.1', 5000), APP)
server.serve_forever()
