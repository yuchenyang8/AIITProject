import datetime
import os
import re
import time

import bson
from flask import session, json, redirect, url_for, request
from flask_restful import reqparse, Resource
from werkzeug.utils import secure_filename

from extensions.ext import NmapExt, XrayExt, WafExt, DirExt, OneForAllExt, WappExt, NessusExt, HydraExt, PocExt, MobExt, \
    BinExt
from web import DB
from web.utils.auxiliary import get_title


class FuncCompanyAPI(Resource):
    """厂商管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("company_name", type=str, location='json')  # 名称
        self.parser.add_argument("company_people", type=str, location='json')  # 名称
        self.parser.add_argument("company_contact", type=str, location='json')  # 联系方式
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def put(self):
        if not session.get('status'):
            return redirect(url_for('html_system_login'), 302)
        args = self.parser.parse_args()
        company_name = args.company_name
        company_people = args.company_people
        company_contact = args.company_contact
        company_query = DB.db.company.find_one({'ename': company_name})
        if company_query:
            return {'status_code': 201, 'msg': f'已存在[{company_name}]厂商名'}
        new_company = {
            'ename': company_name,
            'epeople': company_people,
            'econtact': company_contact,
        }
        DB.db.company.insert_one(new_company)
        return {'status_code': 200, 'msg': '添加厂商成功'}

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchparams = args.searchParams
        count = DB.db.company.find().count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchparams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = DB.db.company.find().limit(20).skip(0)
            else:
                paginate = DB.db.company.find().limit(key_limit).skip((key_page - 1) * key_limit)
        else:
            try:
                search_dict = json.loads(key_searchparams)  # 解析查询参数
            except:
                paginate = DB.db.company.find().limit(20).skip(0)
            else:
                if 'company_name' not in search_dict:  # 查询参数有误
                    paginate = DB.db.company.find().limit(20).skip(0)
                else:
                    paginate1 = DB.db.company.find({'ename': re.compile(search_dict['company_name'])})
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {
                    'id': index,
                    'company_name': i['ename'],
                    'company_contact': i['econtact'],
                    'company_people': i['epeople'],
                }
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        if not session.get('status'):
            return redirect(url_for('html_system_login'), 302)
        args = self.parser.parse_args()
        searchdict = {'ename': args.company_name}
        company_query = DB.db.company.find_one(searchdict)
        if not company_query:  # 删除的厂商不存在
            return {'status_code': 500, 'msg': '删除厂商失败，无此厂商'}
        DB.db.company.delete_one(searchdict)
        DB.db.task.delete_many(searchdict)
        DB.db.asset.delete_many(searchdict)
        DB.db.vuln.delete_many(searchdict)
        return {'status_code': 200, 'msg': '删除厂商成功'}


class CompanyInfoAPI(Resource):
    """厂商详细信息类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()

    def get(self, asset_type, company):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        assets = DB.db.asset.find({'type': asset_type, 'ename': company})
        result = []
        for asset in assets:
            vulns = DB.db.vuln.find({'vasset': asset['aname']}).count()
            if vulns > 0:
                asset_dict = {'name': asset['aname'], 'value': vulns}
                result.append(asset_dict)
        return result


class CompanyVulnTrendsAPI(Resource):
    """厂商漏洞趋势类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()

    def get(self, company):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        result = []
        hostvulns = 0
        webvulns = 0
        appvulns = 0
        firmvulns = 0
        for i in range(-6, 1, 1):
            day = str(datetime.date.today() + datetime.timedelta(days=i))
            hostvulns += DB.db.vuln.find({'type': '主机', 'ename': company, 'vdate': re.compile(day)}).count()
            webvulns += DB.db.vuln.find({'type': 'WEB', 'ename': company, 'vdate': re.compile(day)}).count()
            appvulns += DB.db.vuln.find({'type': 'APP', 'ename': company, 'vdate': re.compile(day)}).count()
            firmvulns += DB.db.vuln.find({'type': '固件', 'ename': company, 'vdate': re.compile(day)}).count()
            result.append({'date': day, 'host': hostvulns, 'web': webvulns, 'app': appvulns, 'firm': firmvulns})
        return result


class FuncTaskAPI(Resource):
    """任务管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("name", type=str, location='json')
        self.parser.add_argument("task_name", type=str, location='json')
        self.parser.add_argument("task_company", type=str, location='json')
        self.parser.add_argument("task_type", type=str, location='json')
        self.parser.add_argument("task_cycle", type=int, location='json')
        self.parser.add_argument("task_message", type=str, location='json')
        self.parser.add_argument("file_name", type=str, location='json')
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)
        self.path = 'D:\\UY\\AIITProject\\upload\\'

    def put(self):
        """添加任务"""
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        task_name = args.task_name
        task_company = args.task_company
        task_type = args.task_type
        task_cycle = args.task_cycle
        task_message = args.task_message
        file_name = args.file_name
        company_query = DB.db.company.find_one({'ename': task_company})
        if not company_query:
            return {'status_code': 201, 'msg': f'不存在[{task_company}]厂商名，请检查'}
        ename = company_query['ename']
        uname = session['username']
        task_success = False

        if task_type == 'WEB' or task_type == '主机':  # WEB任务/主机任务
            message_list = list(set(task_message.split()))  # 过滤重复内容
        else:
            message_list = list(set(file_name.split()))
        new_task = {
            'tname': task_name,
            'type': task_type,
            'infocycle': task_cycle,
            'ename': ename,
            'tstatus': '未开始',
            'uname': uname,
            'tinfo': message_list,
            'tdate': datetime.datetime.now(),
        }
        try:
            DB.db.task.insert_one(new_task)
            task_success = True
        except:
            pass
        if task_success:
            return {'status_code': 200, 'msg': '添加任务成功'}
        else:
            return {'status_code': 500, 'msg': '添加任务失败'}

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)

        task_count = DB.db.task.find().count()
        asset_count = DB.db.asset.find().count()
        count = task_count + asset_count
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata

        paginate = DB.db.task.find()

        data = []
        if paginate:
            index = 1
            for i in paginate:
                task_data = {
                    # 'id': index,
                    'authorityId': str(i['_id']),
                    'name': i['tname'],
                    'type': i['type'],
                    'company': i['ename'],
                    'status': i['tstatus'],
                    'time': i['tdate'].strftime("%Y-%m-%d %H:%M:%S"),
                    'parentId': -1,
                }
                data.append(task_data)
                index += 1
                objid = i['_id']
                assets = DB.db.asset.find({'taskid': objid})
                for asset in assets:
                    asset_data = {
                        # 'id': index,
                        'authorityId': str(asset['_id']),
                        'name': asset['aname'],
                        'type': asset['type'],
                        'company': asset['ename'],
                        'status': asset['infostatus'],
                        'time': asset['createdate'].strftime("%Y-%m-%d %H:%M:%S"),
                        'parentId': str(asset['parentid']),
                    }
                    data.append(asset_data)
                    index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def post(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        # args = self.parser.parse_args()
        try:
            file_data = request.files['file']
            if file_data:
                if file_data.filename.split('.')[-1] in ['bin']:
                    file_data.save(self.path + 'firmware\\' + secure_filename(file_data.filename))
                    return {'code': 200, 'msg': '上传成功！'}
                else:
                    file_data.save(self.path + 'app\\' + secure_filename(file_data.filename))
                    return {'code': 200, 'msg': '上传成功！'}
            else:
                return {'code': 500, 'msg': '上传失败！'}
        except:
            pass

    def delete(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        task_name = args.name
        searchdict = {'tname': task_name}
        task_query = DB.db.task.find_one(searchdict)
        if not task_query:  # 删除的任务不存在
            return {'status_code': 500, 'msg': '删除资产任务失败，此任务不存在'}
        taskid = task_query['_id']
        DB.db.asset.delete_many({'taskid': taskid})
        DB.db.task.delete_one(searchdict)
        return {'status_code': 200, 'msg': '删除资产任务成功'}


class FuncAssetAPI(Resource):
    """资产管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("asset_company", type=str, location='json')
        self.parser.add_argument("u", type=str)
        self.parser.add_argument("name", type=str, location='json')
        self.parser.add_argument("type", type=str)
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        u = args.u
        asset_type = args.type
        key_page = args.page
        key_limit = args.limit
        key_searchparams = args.searchParams

        count = DB.db.asset.find(
            {'infostatus': '探测完成', 'type': asset_type}).count() if asset_type else DB.db.asset.find(
            {'infostatus': '探测完成'}).count()

        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        asset_transfer_list = []
        if u == 'uy':
            assets = DB.db.asset.find()
            c = 1
            for asset in assets:
                asset_transfer_list.append({'value': c, 'title': asset['aname']})
                c += 1
            jsondata.update({'data': asset_transfer_list})
            return jsondata
        if asset_type:
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = DB.db.asset.find({'infostatus': '探测完成', 'type': asset_type}).limit(20).skip(0)
            else:
                paginate = DB.db.asset.find({'infostatus': '探测完成', 'type': asset_type}).limit(key_limit).skip(
                    (key_page - 1) * key_limit)
        elif not key_searchparams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = DB.db.asset.find({'infostatus': '探测完成'}).limit(20).skip(0)
            else:
                paginate = DB.db.asset.find({'infostatus': '探测完成'}).limit(key_limit).skip((key_page - 1) * key_limit)
        else:
            try:
                search_dict = json.loads(key_searchparams)  # 解析查询参数
            except:
                paginate = DB.db.asset.find({'infostatus': '探测完成'}).limit(20).skip(0)
            else:
                if 'asset_name' not in search_dict or 'asset_company' not in search_dict:  # 查询参数有误
                    paginate = DB.db.asset.find({'infostatus': '探测完成'}).limit(20).skip(0)
                elif 'asset_company' not in search_dict:
                    paginate1 = DB.db.asset.find({'infostatus': '探测完成', 'aname': re.compile(search_dict['asset_name'])})
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
                elif 'asset_name' not in search_dict:
                    paginate1 = DB.db.asset.find(
                        {'infostatus': '探测完成', 'ename': re.compile(search_dict['asset_company'])})
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
                else:
                    paginate1 = DB.db.asset.find({
                        'ename': re.compile(search_dict['asset_company']),
                        'aname': re.compile(search_dict['asset_name']),
                    })
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                if 'vulndate' in i.keys():
                    vtime = i['vulndate'].strftime("%Y-%m-%d %H:%M:%S")
                else:
                    vtime = 'None'
                data1 = {
                    'id': index,
                    'name': i['aname'],
                    'asset_type': i['type'],
                    'asset_company': i['ename'],
                    'vuln_status': i['vulnstatus'],
                    'vuln_time': vtime
                }
                if i['type'] == '主机':
                    host_os = i['detail']['operating-system'] if 'operating-system' in i['detail'].keys() else '-'
                    netbios_name = i['detail']['netbios-name'] if 'netbios-name' in i['detail'].keys() else '-'
                    data1.update({
                        'os': host_os,
                        'netbios-name': netbios_name,
                    })
                elif i['type'] == 'WEB':
                    data1.update({
                        'title': i['title'],
                        'ip': i['ip'],
                    })
                elif i['type'] == 'APP':
                    data1.update({
                        'hash': i['hash'],
                    })
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        asset_name = args.name
        searchdict = {'aname': asset_name}
        asset_query = DB.db.asset.find_one(searchdict)
        if not asset_query:  # 删除的资产不存在
            return {'status_code': 500, 'msg': '删除资产失败，此资产不存在'}
        DB.db.asset.delete_one(searchdict)
        DB.db.vuln.delete_many({'vasset': asset_name})
        return {'status_code': 200, 'msg': '删除资产成功'}


class FuncHostInfoAPI(Resource):
    """主机资产详情管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("ename", type=str)
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        company_name = args.ename
        key_page = args.page
        key_limit = args.limit

        count = DB.db.asset.find({'infostatus': '探测完成', 'type': '主机', 'ename': company_name}).count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_page or not key_limit:  # 判断是否有分页查询参数
            paginate = DB.db.asset.find({'infostatus': '探测完成', 'type': '主机', 'ename': company_name}).limit(20).skip(0)
        else:
            paginate = DB.db.asset.find({'infostatus': '探测完成', 'type': '主机', 'ename': company_name}).limit(
                key_limit).skip((key_page - 1) * key_limit)

        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                host_os = i['detail']['operating-system'] if 'operating-system' in i['detail'].keys() else '-'
                netbios_name = i['detail']['netbios-name'] if 'netbios-name' in i['detail'].keys() else '-'
                data1 = {
                    'id': index,
                    'name': i['aname'],
                    'os': host_os,
                    'netbios-name': netbios_name,
                }
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata


class FuncWebInfoAPI(Resource):
    """WEB资产详情管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("ename", type=str)
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        company_name = args.ename
        key_page = args.page
        key_limit = args.limit

        count = DB.db.asset.find({'infostatus': '探测完成', 'type': 'WEB', 'ename': company_name}).count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_page or not key_limit:  # 判断是否有分页查询参数
            paginate = DB.db.asset.find({'infostatus': '探测完成', 'type': 'WEB', 'ename': company_name}).limit(20).skip(0)
        else:
            paginate = DB.db.asset.find({'infostatus': '探测完成', 'type': 'WEB', 'ename': company_name}).limit(
                key_limit).skip(
                (key_page - 1) * key_limit)

        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {
                    'id': index,
                    'name': i['aname'],
                    'title': i['title'],
                    'ip': i['ip'],
                }
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata


class FuncAppInfoAPI(Resource):
    """APP资产详情管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("ename", type=str)
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        company_name = args.ename
        key_page = args.page
        key_limit = args.limit

        count = DB.db.asset.find({'infostatus': '探测完成', 'type': 'APP', 'ename': company_name}).count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_page or not key_limit:  # 判断是否有分页查询参数
            paginate = DB.db.asset.find({'infostatus': '探测完成', 'type': 'APP', 'ename': company_name}).limit(20).skip(0)
        else:
            paginate = DB.db.asset.find({'infostatus': '探测完成', 'type': 'APP', 'ename': company_name}).limit(
                key_limit).skip(
                (key_page - 1) * key_limit)

        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {
                    'id': index,
                    'name': i['app_name'],
                    'package_name': i['package_name'],
                    'android_version': i['android_version'],
                    'average_cvss': i['average_cvss'],
                }
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata


class FuncFirmInfoAPI(Resource):
    """固件资产详情管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("ename", type=str)
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        company_name = args.ename
        key_page = args.page
        key_limit = args.limit

        count = DB.db.asset.find({'infostatus': '探测完成', 'type': '固件', 'ename': company_name}).count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_page or not key_limit:  # 判断是否有分页查询参数
            paginate = DB.db.asset.find({'infostatus': '探测完成', 'type': '固件', 'ename': company_name}).limit(20).skip(0)
        else:
            paginate = DB.db.asset.find({'infostatus': '探测完成', 'type': '固件', 'ename': company_name}).limit(
                key_limit).skip(
                (key_page - 1) * key_limit)

        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {
                    'id': index,
                    'name': i['name'],
                }
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata


class InfoAPI(Resource):
    """渗透阶段信息收集工具"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("name", type=str, location='json')
        self.parser.add_argument("type", type=str, location='json')
        self.parser.add_argument("company", type=str, location='json')
        self.ports = '1-1000'

    def post(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        ports = self.ports
        task_name = args.name
        task_type = args.type
        task_company = args.company
        task_info = DB.db.task.find_one({'tname': task_name})['tinfo']
        task_objid = DB.db.task.find_one({'tname': task_name})['_id']
        # 更新任务状态
        DB.db.task.update_one({'tname': task_name}, {'$set': {'tstatus': '进行中'}})
        if task_type == '主机':
            for info in task_info:
                # 主机探测
                uphost = NmapExt(hosts=info, ports=ports).host_discovery()
                # 端口扫描
                for host in uphost:
                    if not DB.db.asset.find_one({'aname': host}):
                        self.create_asset(aname=host, asset_type='主机', ename=task_company, objid=task_objid,
                                          taskid=task_objid)
                    DB.db.asset.update_one({'aname': host}, {'$set': {'infostatus': '探测中(端口扫描)'}})
                    portsinfo = NmapExt(hosts=host, ports=ports).port_scan()
                    DB.db.asset.update_one({'aname': host},
                                           {'$set': {'ports': portsinfo, 'infostatus': '探测完成',
                                                     'vulnstatus': '未扫描'}})
            # 更新任务状态
            DB.db.task.update_one({'tname': task_name}, {'$set': {'tstatus': '已完成'}})
        elif task_type == 'WEB':
            for asset_name in task_info:
                # WEB信息搜集
                if DB.db.asset.find_one({'aname': asset_name}):
                    continue
                self.create_asset(aname=asset_name, asset_type='WEB', ename=task_company, objid=task_objid,
                                  taskid=task_objid)
                asset_objid = DB.db.asset.find_one({'aname': asset_name})['_id']
                title = get_title(asset_name)
                DB.db.asset.update_one({'aname': asset_name}, {'$set': {'title': title, 'infostatus': '探测中(IP检测)'}})
                self.ip_detect(asset_name, asset_objid, task_objid)
                DB.db.asset.update_one({'aname': asset_name}, {'$set': {'infostatus': '探测中(指纹识别)'}})
                webfinger = WappExt().detect(asset_name)
                DB.db.asset.update_one({'aname': asset_name},
                                       {'$set': {'finger': webfinger, 'infostatus': '探测中(目录扫描)'}})
                dir_list = DirExt(asset_name).dir_scan()
                DB.db.asset.update_one({'aname': asset_name}, {'$set': {'dir': dir_list, 'infostatus': '探测中(WAF检测)'}})
                waf = WafExt().detect(asset_name)
                DB.db.asset.update_one({'aname': asset_name}, {'$set': {'waf': waf, 'infostatus': '探测中(子域探测)'}})
                subdomain_list = OneForAllExt(asset_name).subdomain_discovery()
                DB.db.asset.update_one({'aname': asset_name}, {
                    '$set': {'subdomain': subdomain_list, 'infostatus': '探测完成', 'vulnstatus': '未扫描'}})
                for subdomain in subdomain_list:
                    if not DB.db.asset.find_one({'aname': subdomain}):
                        # 创建WEB任务
                        self.create_asset(aname=subdomain, asset_type='WEB', ename=task_company, objid=asset_objid,
                                          taskid=task_objid)
                    s = subdomain_list.copy()
                    s.remove(subdomain)
                    s.append(asset_name)
                    title = get_title(subdomain)
                    DB.db.asset.update_one({'aname': subdomain},
                                           {'$set': {'title': title, 'subdomain': s, 'infostatus': '探测中(IP检测)'}})
                    self.ip_detect(subdomain, asset_objid, task_objid)
                    DB.db.asset.update_one({'aname': subdomain}, {'$set': {'infostatus': '探测中(指纹识别)'}})
                    subdomain_webfinger = WappExt().detect(subdomain)
                    DB.db.asset.update_one({'aname': subdomain},
                                           {'$set': {'finger': subdomain_webfinger, 'infostatus': '探测中(WAF检测)'}})
                    waf = WafExt().detect(subdomain)
                    DB.db.asset.update_one({'aname': subdomain}, {'$set': {'waf': waf, 'infostatus': '探测中(目录扫描)'}})
                    subdomain_dir_list = DirExt(subdomain).dir_scan()
                    DB.db.asset.update_one({'aname': subdomain},
                                           {'$set': {'dir': subdomain_dir_list, 'infostatus': '探测完成',
                                                     'vulnstatus': '未扫描'}})
                # 更新任务状态
                DB.db.task.update_one({'tname': task_name}, {'$set': {'tstatus': '已完成'}})
        elif task_type == 'APP':
            for app in task_info:
                if not DB.db.asset.find_one({'aname': app}):
                    self.create_asset(aname=app, asset_type='APP', ename=task_company, objid=task_objid,
                                      taskid=task_objid)
                DB.db.asset.update_one({'aname': app}, {'$set': {'infostatus': '探测中'}})
                m = MobExt()
                app_hash = m.upload(app)
                res = m.get_result(file_hash=app_hash)
                while True:
                    if not res:
                        time.sleep(60)
                        res = m.get_result(file_hash=app_hash)
                    else:
                        break
                for item in res:
                    DB.db.asset.update_one({'aname': app}, {'$set': {item: res[item]}})
                DB.db.asset.update_one({'aname': app},
                                       {'$set': {'hash': app_hash, 'infostatus': '探测完成', 'vulnstatus': '未扫描'}})
            DB.db.task.update_one({'tname': task_name}, {'$set': {'tstatus': '已完成'}})
        elif task_type == '固件':
            for firm in task_info:
                if not DB.db.asset.find_one({'aname': firm}):
                    self.create_asset(aname=firm, asset_type='固件', ename=task_company, objid=task_objid,
                                      taskid=task_objid)
                DB.db.asset.update_one({'aname': firm}, {'$set': {'infostatus': '探测中'}})
                b = BinExt()
                res = b.scan(firm)
                DB.db.asset.update_one({'aname': firm}, {
                    '$set': {'disasm': res['Disasm'], 'signature': res['Signature'], 'infostatus': '探测完成',
                             'vulnstatus': '未扫描'}})
            DB.db.task.update_one({'tname': task_name}, {'$set': {'tstatus': '已完成'}})
        return {'status_code': 200}

    @staticmethod
    def create_asset(aname, asset_type, ename, objid, taskid):
        new_asset = {
            'aname': aname,
            'type': asset_type,
            'ename': ename,
            'infostatus': '未探测',
            'uname': session['username'],
            'createdate': datetime.datetime.now(),
            'parentid': objid,
            'taskid': taskid,
        }
        if asset_type == '主机':
            new_asset.update({'info': []})
            new_asset.update({'detail': {}})
        DB.db.asset.insert_one(new_asset)

    def ip_detect(self, target, objid, taskid):
        # IP检测
        ports = self.ports
        i = NmapExt(hosts=target, ports=ports).host_discovery()
        if i:
            ip = i[0]
            DB.db.asset.update_one({'aname': target}, {'$set': {'ip': ip}})
            if not DB.db.asset.find_one({'aname': ip}):
                # 创建主机任务
                self.create_asset(aname=ip, asset_type='主机', ename=DB.db.asset.find_one({'aname': target})['ename'],
                                  objid=objid, taskid=taskid)
                DB.db.asset.update_one({'aname': ip}, {'$set': {'infostatus': '探测中(端口扫描)'}})
                portsinfo = NmapExt(hosts=ip, ports=ports).port_scan()
                DB.db.asset.update_one({'aname': ip},
                                       {'$set': {'ports': portsinfo, 'infostatus': '探测完成', 'vulnstatus': '未扫描'}})
        else:
            DB.db.asset.update_one({'aname': target}, {'$set': {'ip': 'None'}})


class FuncInfoAPI(Resource):
    """端口信息类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("ip", type=str)
        self.parser.add_argument("asset_dir", type=str)
        self.parser.add_argument("asset_sub", type=str)
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        ip = args.ip
        adir = args.asset_dir
        asub = args.asset_sub
        key_page = args.page
        key_limit = args.limit
        if ip:
            jsondata = {'code': 0, 'msg': ''}
            paginate = DB.db.asset.find_one({'aname': ip})['ports']
            data = []
            if paginate:
                index = 1
                for i in paginate:
                    data1 = {
                        'id': index,
                        'port': i,
                        'port_state': paginate[i]['state'],
                        'port_protocol': paginate[i]['name'],
                        'port_service': paginate[i]['product'],
                        'sercive_version': paginate[i]['version'],
                    }
                    data.append(data1)
                    index += 1
                jsondata.update({'data': data})
                return jsondata
            else:
                jsondata = {'code': 0, 'msg': '', 'count': 0}
                jsondata.update({'data': []})
                return jsondata
        elif adir:
            dir_list = DB.db.asset.find_one({'aname': adir})['dir']
            count = len(dir_list)
            jsondata = {'code': 0, 'msg': '', 'count': count}
            if count == 0:  # 若没有数据返回空列表
                jsondata.update({'data': []})
                return jsondata
            paginate = dir_list[(key_page - 1) * key_limit:key_page * key_limit]
            data = []
            if paginate:
                index = 1
                for i in paginate:
                    data1 = {
                        'id': index,
                        'dir': i,
                    }
                    data.append(data1)
                    index += 1
                jsondata.update({'data': data})
                return jsondata
            else:
                jsondata = {'code': 0, 'msg': '', 'count': 0}
                jsondata.update({'data': []})
                return jsondata
        elif asub:
            sub_list = DB.db.asset.find_one({'aname': asub})['subdomain']
            count = len(sub_list)
            jsondata = {'code': 0, 'msg': '', 'count': count}
            if count == 0:  # 若没有数据返回空列表
                jsondata.update({'data': []})
                return jsondata
            paginate = DB.db.asset.find_one({'aname': asub})['subdomain'][
                       (key_page - 1) * key_limit:key_page * key_limit]
            data = []
            if paginate:
                index = 1
                for i in paginate:
                    data1 = {
                        'id': index,
                        'subdomain': i,
                    }
                    data.append(data1)
                    index += 1
                jsondata.update({'data': data})
                return jsondata
            else:
                jsondata = {'code': 0, 'msg': '', 'count': 0}
                jsondata.update({'data': []})
                return jsondata


class VulnAPI(Resource):
    """漏洞扫描类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("name", type=str, location='json')
        self.parser.add_argument("asset_type", type=str, location='json')
        self.parser.add_argument("asset_company", type=str, location='json')
        self.parser.add_argument("port_protocol", type=str, location='json')
        self.parser.add_argument("ip", type=str)

    def post(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        asset_type = args.asset_type
        asset_name = args.name
        company_name = args.asset_company
        port_protocol = args.port_protocol
        ip = args.ip
        support_protocol = ['ssh', 'ftp', 'mysql']
        # 弱口令检测
        if ip and port_protocol in support_protocol:
            h = HydraExt()
            r = h.crack(host=ip, service=port_protocol)
            if r:
                weakpass = {
                    'host': ip,
                    'time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'service': port_protocol,
                    'company': DB.db.asset.find_one({'aname': ip})['ename']
                }
                weakpass.update(r)
                DB.db.weak.insert_one(weakpass)
        if asset_type == 'WEB':
            XrayExt().scan_one(url=asset_name)
        elif asset_type == '主机':
            n = NessusExt()
            hostdict = DB.db.asset.find_one({'aname': asset_name})
            if 'severity' not in hostdict.keys():
                DB.db.asset.update_one({'aname': asset_name}, {
                    '$set': {'severity': {'INFO': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}}})
            if 'scan_id' not in hostdict.keys():
                scan_id = n.create(name=asset_name, targets=asset_name)
                DB.db.asset.update_one({'aname': asset_name}, {'$set': {'scan_id': scan_id}})
            hostdict = DB.db.asset.find_one({'aname': asset_name})
            scan_id = hostdict['scan_id']
            history_id = n.launch(scan_id)
            vulns = n.get_vuln_result(scan_id, history_id)
            for v in vulns:
                plugin_id = v['plugin_id']
                detail = n.get_plugin_detail(plugin_id=plugin_id)
                output = n.get_plugin_output(scan_id=scan_id, host_id=2, plugin_id=plugin_id)
                detail.update(output)
                if v['severity'] == 0:
                    info_detail = {v['plugin_name']: detail}
                    DB.db.asset.update_one({'aname': asset_name}, {'$addToSet': {'info': info_detail}})
                else:
                    DB.db.vuln.insert_one({'vasset': asset_name,
                                           'vtype': v['plugin_name'],
                                           'vdate': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                           'type': '主机',
                                           'vdetail': detail,
                                           'vstatus': '未修复',
                                           'ename': company_name, })
            info = n.get_host_details(scan_id=scan_id, host_id=2)
            severitycount = n.get_severitycount(scan_id=scan_id, history_id=history_id)
            DB.db.asset.update_one({'aname': asset_name}, {'$set': {'detail': info, 'severity': severitycount}})
        DB.db.asset.update_one({'aname': asset_name},
                               {'$set': {'vulndate': datetime.datetime.now(), 'vulnstatus': '扫描完成'}})


class FuncVulnAPI(Resource):
    """漏洞管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("asset_name", type=str)
        self.parser.add_argument("vuln_company", type=str, location='json')
        self.parser.add_argument("vuln_asset", type=str, location='json')
        self.parser.add_argument("vuln_type", type=str, location='json')
        self.parser.add_argument("type", type=str)
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        asset_name = args.asset_name
        key_page = args.page
        key_limit = args.limit
        key_searchparams = args.searchParams
        vuln_type = DB.db.asset.find_one({'aname': asset_name})['type'] if asset_name else args.type

        count = DB.db.vuln.find({'type': vuln_type, 'vasset': asset_name}).count() if asset_name else DB.db.vuln.find(
            {'type': vuln_type}).count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if asset_name:  # 若有get参数
            if not key_page or not key_limit:
                paginate = DB.db.vuln.find({'vasset': asset_name}).limit(20).skip(0)
            else:
                paginate = DB.db.vuln.find({'vasset': asset_name}).limit(key_limit).skip((key_page - 1) * key_limit)
        elif not key_searchparams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = DB.db.vuln.find({'type': vuln_type}).limit(20).skip(0)
            else:
                paginate = DB.db.vuln.find({'type': vuln_type}).limit(key_limit).skip((key_page - 1) * key_limit)
        else:
            try:
                search_dict = json.loads(key_searchparams)  # 解析查询参数
            except:
                paginate = DB.db.vuln.find({'type': vuln_type}).limit(20).skip(0)
            else:
                if 'vuln_asset' not in search_dict or 'vuln_company' not in search_dict:  # 查询参数有误
                    paginate = DB.db.vuln.find({'type': vuln_type}).limit(20).skip(0)
                elif 'vuln_company' not in search_dict:
                    paginate1 = DB.db.vuln.find({'type': vuln_type, 'vasset': re.compile(search_dict['vuln_asset'])})
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
                elif 'vuln_asset' not in search_dict:
                    paginate1 = DB.db.vuln.find(
                        {'type': vuln_type, 'ename': re.compile(search_dict['vuln_company'])})
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
                else:
                    paginate1 = DB.db.vuln.find({'type': vuln_type,
                                                 'ename': re.compile(search_dict['vuln_company']),
                                                 'vasset': re.compile(search_dict['vuln_asset']),
                                                 })
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {
                    'id': index,
                    'vuln_type': i['vtype'],
                    'vuln_asset': i['vasset'],
                    'vuln_company': i['ename'],
                    'vuln_status': i['vstatus'],
                    'vuln_time': i['vdate'],
                    'objid': str(i['_id']),
                }
                if i['type'] == '主机':
                    data1.update({
                        'vuln_severity': i['vdetail']['risk_factor'],
                        'vuln_synopsis': i['vdetail']['synopsis'],
                    })
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        vuln_asset = args.vuln_asset
        vuln_type = args.vuln_type
        searchdict = {'vasset': vuln_asset, 'vtype': vuln_type}
        asset_query = DB.db.vuln.find_one(searchdict)
        if not asset_query:  # 删除的资产不存在
            return {'status_code': 500, 'msg': '删除漏洞失败，此漏洞不存在'}
        DB.db.vuln.delete_one(searchdict)
        return {'status_code': 200, 'msg': '删除漏洞成功'}


class ChartAPI(Resource):
    """图表信息类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("ip", type=str)
        self.parser.add_argument("company", type=str)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        ip = args.ip
        company = args.company
        if ip:
            data = DB.db.asset.find_one({'aname': ip})['severity']
            result = []
            for i in data:
                newdict = {'value': data[i], 'name': i}
                result.append(newdict)

            return result


class PasswordAPI(Resource):
    """弱口令信息类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("objid", type=str, location='json')
        self.parser.add_argument("asset_name", type=str)
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        host = args.asset_name
        key_page = args.page
        key_limit = args.limit
        key_searchparams = args.searchParams

        count = DB.db.weak.find({'host': host}).count() if host else DB.db.weak.find().count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata

        if host:
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = DB.db.weak.find({'host': host}).limit(20).skip(0)
            else:
                paginate = DB.db.weak.find({'host': host}).limit(key_limit).skip((key_page - 1) * key_limit)
        elif not key_searchparams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = DB.db.weak.find().limit(20).skip(0)
            else:
                paginate = DB.db.weak.find().limit(key_limit).skip((key_page - 1) * key_limit)
        else:
            try:
                search_dict = json.loads(key_searchparams)  # 解析查询参数
            except:
                paginate = DB.db.weak.find().limit(20).skip(0)
            else:
                if 'company_name' not in search_dict:  # 查询参数有误
                    paginate = DB.db.weak.find().limit(20).skip(0)
                else:
                    paginate1 = DB.db.weak.find({'company': re.compile(search_dict['company_name'])})
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {
                    'id': index,
                    'host': i['host'],
                    'time': i['time'],
                    'service': i['service'],
                    'company': i['company'],
                    'username': i['username'],
                    'password': i['password'],
                    'objid': str(i['_id']),
                }
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        objid = bson.ObjectId(args.objid)
        searchdict = {'_id': objid}
        weak_query = DB.db.weak.find_one(searchdict)
        if not weak_query:
            return {'status_code': 500, 'msg': '删除失败，不存在'}
        DB.db.weak.delete_one(searchdict)
        return {'status_code': 200, 'msg': '删除成功'}


class PocTaskAPI(Resource):
    """POC任务管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("poc_task_name", type=str, location='json')
        self.parser.add_argument("poc_task_cycle", type=str, location='json')
        self.parser.add_argument("input_asset", type=str, location='json')
        self.parser.add_argument("objid", type=str, location='json')
        self.parser.add_argument("poc", type=str, location='json')
        self.parser.add_argument("asset", type=str, location='json')
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def put(self):
        if not session.get('status'):
            return redirect(url_for('html_system_login'), 302)
        args = self.parser.parse_args()
        input_asset = args.input_asset
        task_name = args.poc_task_name
        cycle = args.poc_task_cycle
        asset = [a['title'] for a in eval(args.asset)]
        if input_asset:
            alist = list(set(input_asset.split()))
            for a in alist:
                asset.append(a)
        poc = [p['title'] for p in eval(args.poc)]
        new_poc_task = {
            'task_name': task_name,
            'cycle': cycle if cycle else '-',
            'asset': asset,
            'poc': poc,
            'time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'status': '未开始',
        }
        DB.db.poc.insert_one(new_poc_task)
        return {'status_code': 200, 'msg': '创建POC任务成功'}

    def post(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        poc = args.poc
        url = args.url
        p = PocExt()
        results = p.verify(url=url, poc=poc)
        for result in results:
            result_info = {}
            for item in result.items():
                result_info.update({item[0]: item[1]})
            DB.db.poc.insert_one(result_info)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        # key_searchparams = args.searchParams
        count = DB.db.poc.find().count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        # if not key_searchparams:  # 若没有查询参数
        if not key_page or not key_limit:  # 判断是否有分页查询参数
            paginate = DB.db.poc.find().limit(20).skip(0)
        else:
            paginate = DB.db.poc.find().limit(key_limit).skip((key_page - 1) * key_limit)
        # else:
        #     try:
        #         search_dict = json.loads(key_searchparams)  # 解析查询参数
        #     except:
        #         paginate = DB.db.poc.find().limit(20).skip(0)
        #     else:
        #         if 'company_name' not in search_dict:  # 查询参数有误
        #             paginate = DB.db.poc.find().limit(20).skip(0)
        #         else:
        #             paginate1 = DB.db.poc.find({'ename': re.compile(search_dict['company_name'])})
        #             paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
        #             jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {
                    'id': index,
                    'objid': str(i['_id']),
                    'task_name': i['task_name'],
                    'cycle': i['cycle'],
                    'asset': i['asset'],
                    'poc': i['poc'],
                    'time': i['time'],
                    'status': i['status'],
                }
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        if not session.get('status'):
            return redirect(url_for('html_system_login'), 302)
        args = self.parser.parse_args()
        objid = bson.ObjectId(args.objid)
        searchdict = {'_id': objid}
        poctask_query = DB.db.poc.find_one(searchdict)
        if not poctask_query:
            return {'status_code': 500, 'msg': '删除失败，不存在'}
        DB.db.poc.delete_one(searchdict)
        return {'status_code': 200, 'msg': '删除成功'}


class PocAPI(Resource):
    """POC管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("filename", type=str, location='json')
        self.parser.add_argument("poc", type=list, location='json')
        self.parser.add_argument("asset", type=list, location='json')
        self.parser.add_argument("objid", type=str, location='json')
        self.parser.add_argument("u", type=str)
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)
        self.p = PocExt()
        self.poc_file_path = r'D:\VENV\py3flask\Lib\site-packages\pocsuite3\pocs'

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        u = args.u
        key_page = args.page
        key_limit = args.limit
        key_searchparams = args.searchParams
        poc_list = self.p.get_poc_list()
        count = len(poc_list)
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        poc_info_list = []
        value = 1
        poc_transfer_list = []
        for poc in poc_list:
            poc_info = self.p.get_poc_info(poc_name=poc)
            poc_info_list.append(poc_info)
            poc_transfer_list.append({'value': value, 'title': poc})
            value += 1

        if u == 'uy':
            jsondata.update({'data': poc_transfer_list})
            return jsondata
        if not key_searchparams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = poc_info_list[:20]
            else:
                paginate = poc_info_list[(key_page - 1) * key_limit:key_page * key_limit]
        else:
            try:
                search_dict = json.loads(key_searchparams)  # 解析查询参数
            except:
                paginate = poc_info_list[:20]
            else:
                if 'poc_name' not in search_dict:  # 查询参数有误
                    paginate = poc_info_list[:20]
                else:
                    paginate1 = [x for i, x in enumerate(poc_info_list) if search_dict['poc_name'] in x['name']]
                    paginate = paginate1[(key_page - 1) * key_limit:key_page * key_limit]
                    jsondata = {'code': 0, 'msg': '', 'count': len(paginate1)}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                version = i['appVersion'] if 'appVersion' in i.keys() else '-'
                data1 = {
                    'id': index,
                    'name': i['name'],
                    'appName': i['appName'],
                    'appVersion': version,
                    'vulType': i['vulType'],
                    'filename': i['filename'],
                }
                data.append(data1)
                index += 1
            jsondata.update({'data': data})
            return jsondata
        else:
            jsondata = {'code': 0, 'msg': '', 'count': 0}
            jsondata.update({'data': []})
            return jsondata

    def delete(self):
        args = self.parser.parse_args()
        if args.filename.split('.')[0] not in self.p.get_poc_list():
            return {'status_code': 500, 'msg': '删除POC失败，此POC不存在'}
        filename = self.poc_file_path + '\\' + args.filename
        cmd = r'del {}'.format(filename)
        os.system(cmd)
        return {'status_code': 200, 'msg': '删除POC成功'}

    def post(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        objid = bson.ObjectId(args.objid)
        poc = args.poc
        url = args.asset
        try:
            file_data = request.files['file']
            path = self.poc_file_path
            if file_data:
                file_data.save(path + '\\' + secure_filename(file_data.filename))
                return {'code': 200, 'msg': '上传成功！'}
            else:
                return {'code': 500, 'msg': '上传失败！'}
        except:
            p = PocExt()
            DB.db.poc.update_one({'_id': objid}, {'$set': {'status': '检测中'}})
            res = p.verify(url=url, poc=poc)
            DB.db.poc.update_one({'_id': objid}, {'$set': {'result': res, 'status': '检测完成',
                                                           'time': datetime.datetime.now().strftime(
                                                               "%Y-%m-%d %H:%M:%S")}})
            web = ['Struts2-015远程代码执行', 'Struts2-045远程代码执行', 'Struts2-046远程代码执行']
            for r in res:
                if r['status'] == 'success':
                    DB.db.vuln.insert_one({
                        'vasset': r['target'].split('/')[0],
                        'vdate': r['created'],
                        'vstatus': '未修复',
                        'vtype': r['poc_name'],
                        'type': 'WEB' if r['poc_name'] in web else '主机',
                        'ename': '-',
                    })
