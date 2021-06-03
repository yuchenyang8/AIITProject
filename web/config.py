import uuid


class Config(object):
    """Flask数据配置"""
    SECRET_KEY = str(uuid.uuid4())
    MONGO_URI = 'mongodb://localhost:27017/AIIT'

