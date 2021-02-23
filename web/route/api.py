from flask_restful import reqparse, Resource
from flask import session, request, json, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
from web import DB, APP


class UserLogin(Resource):
    """user login类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("username", type=str, required=True, location='json')
        self.parser.add_argument("password", type=str, required=True, location='json')

    def post(self):
        """登录接口"""
        args = self.parser.parse_args()
        key_username = args.username
        key_password = args.password

        user_query = DB.db.user.find_one({'uname': key_username})
        if not user_query:  # 若不存在此用户
            return {'status_code': 201, 'msg': '用户名或密码错误'}
        if user_query['upassword'] == key_password:  # 进行密码核对
            session['status'] = True  # 登录成功设置session
            session['username'] = key_username

            return {'status_code': 200}
        else:
            return {'status_code': 201, 'msg': '用户名或密码错误'}
