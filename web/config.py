import uuid
import pathlib
import os


class Config(object):
    """Flask数据配置"""
    SECRET_KEY = str(uuid.uuid4())
    MONGO_URI = 'mongodb://localhost:27017/test'
    MAIL_ADDRES = '695981841@qq.com'  # 接收邮件
    UPLOAD_FOLDER = pathlib.Path(__file__).parent.joinpath('upload').resolve()
    if not os.path.isdir(UPLOAD_FOLDER):
        os.mkdir(UPLOAD_FOLDER)
    UPLOAD_FOLDER_TMP = os.path.join(UPLOAD_FOLDER, 'tmp')
    if not os.path.isdir(UPLOAD_FOLDER_TMP):
        os.mkdir(UPLOAD_FOLDER_TMP)
