from flask_restful import reqparse, Resource
from flask import session, request, json, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
from web import DB, APP


class UserLoginAPI(Resource):
    """用户登录类"""

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


class DashBoardAPI(Resource):
    """展示面板类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()

    def get(self):
        """ 取出所有公司的名称"""
        company_collection = list(DB.db.company.find())
        company_name = []
        for i in company_collection:
            company_name.append(i['ename'])
        """ 获取任务数量 """
        task_collection = DB.db.task.find()
        asset_collection = DB.db.asset.find()
        num_task = task_collection.count()

        """ 获取web任务和host任务的数量 """
        num_webscan = 0
        num_hostscan = 0
        finger_types = {}
        for asset in asset_collection:
            if asset['type'] == 'WEB':
                num_webscan += 1
                for f in asset['finger'].keys():
                    if f in finger_types:
                        finger_types[f] += 1
                    else:
                        finger_types[f] = 1
            elif asset['type'] == '主机':
                num_hostscan += 1
        """ 获取指纹排序信息 """
        finger_types_sorted = sorted(finger_types, key=finger_types.__getitem__)[0:3]

        return {'company_name': company_name,
                'num_task': num_task,
                'num_webscan': num_webscan,
                'num_hostscan': num_hostscan,
                'finger_types_sorted': finger_types_sorted,
                }
