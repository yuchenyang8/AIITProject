from gevent import monkey
from gevent.pywsgi import WSGIServer
from web import APP


if __name__ == '__main__':

    monkey.patch_all()
    WSGIServer(('127.0.0.1', 5000), APP).serve_forever()
