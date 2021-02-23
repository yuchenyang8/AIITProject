from flask_restful import reqparse, Resource
from flask import session, request, json, redirect, url_for
import datetime
from web import DB, APP


class FuncCompanyAPI(Resource):
    """厂商管理类"""
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("cus_name", type=str, location='json')
        self.parser.add_argument("cus_home", type=str, location='json')
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def put(self):
        return {'status_code': 200, 'msg': '添加厂商成功'}

    def get(self):
        if not session.get('status'):
            return redirect(url_for('html_system_login'), 302)
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchParams = args.searchParams
        count = SrcCustomer.query.count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchParams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = SrcCustomer.query.limit(20).offset(0).all()
            else:
                paginate = SrcCustomer.query.limit(key_limit).offset((key_page - 1) * key_limit).all()
        else:
            try:
                search_dict = json.loads(key_searchParams)  # 解析查询参数
            except:
                paginate = SrcCustomer.query.limit(20).offset(0).all()
            else:
                if 'cus_name' not in search_dict or 'cus_home' not in search_dict:  # 查询参数有误
                    paginate = SrcCustomer.query.limit(20).offset(0).all()
                else:
                    paginate1 = SrcCustomer.query.filter(
                        SrcCustomer.cus_name.like("%" + search_dict['cus_name'] + "%"),
                        SrcCustomer.cus_home.like("%" + search_dict['cus_home'] + "%"),
                    )
                    paginate = paginate1.limit(key_limit).offset((key_page - 1) * key_limit).all()
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1.all())}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {}
                data1['id'] = index
                data1['cus_name'] = i.cus_name
                data1['cus_home'] = i.cus_home
                data1['cus_time'] = i.cus_time
                data1['cus_number'] = len(i.src_assets)
                data1['cus_number_port'] = len(i.src_ports)
                num = 0
                if len(i.src_task) > 0:
                    for j in i.src_task:
                        if not j.task_flag:
                            num += 1
                data1['cus_number_task'] = num
                num = 0
                if len(i.src_assets) > 0:
                    for j in i.src_assets:
                        if not j.asset_xray_flag:
                            num += 1
                data1['cus_number_vul'] = num
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        return {'status_code': 200, 'msg': '删除厂商成功'}