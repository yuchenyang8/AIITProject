from flask_restful import reqparse, Resource
from flask import session, json, redirect, url_for
import datetime
from web import DB
import re
from extensions.ext import NmapExt, HydraExt, XrayExt, WafExt, DirExt, WhatwebExt, OneForAllExt, WappExt


class FuncCompanyAPI(Resource):
    """厂商管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("company_name", type=str, location='json')  # 名称
        self.parser.add_argument("company_contact", type=str, location='json')  # 联系方式
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def put(self):
        if not session.get('status'):
            return redirect(url_for('html_system_login'), 302)
        args = self.parser.parse_args()
        company_name = args.company_name
        company_contact = args.company_contact
        company_query = DB.db.company.find_one({'ename': company_name})
        if company_query:
            return {'status_code': 201, 'msg': f'已存在[{company_name}]厂商名'}
        new_company = {
            'ename': company_name,
            'econtact': company_contact,
        }
        DB.db.company.insert_one(new_company)
        return {'status_code': 200, 'msg': '添加厂商成功'}

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        company_name = args.company_name
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
                    'company_contact': i['econtact']
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
        return {'status_code': 200, 'msg': '删除厂商成功'}


class FuncTaskAPI(Resource):
    """任务管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("task_name", type=str, location='json')
        self.parser.add_argument("task_company", type=str, location='json')
        self.parser.add_argument("task_type", type=str, location='json')
        self.parser.add_argument("task_cycle", type=int, location='json')
        self.parser.add_argument("task_message", type=str, location='json')
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

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
        company_query = DB.db.company.find_one({'ename': task_company})
        if not company_query:
            return {'status_code': 201, 'msg': f'不存在[{task_company}]厂商名，请检查'}
        ename = company_query['ename']
        uname = session['username']
        task_success = False

        if task_type == 'WEB' or task_type == '主机':  # WEB任务/主机任务
            message_list = list(set(task_message.split()))  # 过滤重复内容
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
            DB.db.task.insert_one(new_task)
            # task = DB.db.task.find_one({'tname': task_name})
            # for m in message_list:
            #     new_asset = {
            #         'aname': '',
            #         'type': task_type,
            #         'ename': ename,
            #         'infostatus': '未开始',
            #         'uname': uname,
            #         'createdate': datetime.datetime.now(),
            #         'parentid': task['_id'],
            #     }
            #     message = m.strip()
            #     if message:
            #         asset_sql = DB.db.asset.find_one({'aname': message})  # 过滤已有重复任务
            #         if asset_sql:
            #             continue
            #         new_asset['tname'] = message
            #         DB.db.asset.insert_one(new_asset)
            task_success = True
        if task_success:
            return {'status_code': 200, 'msg': '添加任务成功'}
        else:
            return {'status_code': 500, 'msg': '添加任务失败'}

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchparams = args.searchParams
        count = DB.db.task.find().count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchparams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = DB.db.task.find().limit(20).skip(0)
            else:
                paginate = DB.db.task.find().limit(key_limit).skip((key_page - 1) * key_limit)
        else:
            try:
                search_dict = json.loads(key_searchparams)  # 解析查询参数
            except:
                paginate = DB.db.task.find().limit(20).skip(0)
            else:
                if 'task_name' not in search_dict or 'task_company' not in search_dict:  # 查询参数有误
                    paginate = DB.db.task.find().limit(20).skip(0)
                elif 'task_company' not in search_dict:
                    paginate1 = DB.db.task.find({'tname': re.compile(search_dict['task_name'])})
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
                elif 'task_name' not in search_dict:
                    paginate1 = DB.db.task.find({'ename': re.compile(search_dict['task_company'])})
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
                else:
                    paginate1 = DB.db.task.find({
                        'ename': re.compile(search_dict['task_company']),
                        'tname': re.compile(search_dict['task_name']),
                    })
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
        data = []
        if paginate:
            index = (key_page - 1) * key_limit + 1
            for i in paginate:
                data1 = {
                    'id': index,
                    'task_name': i['tname'],
                    'task_type': i['type'],
                    'task_company': i['ename'],
                    'task_status': i['tstatus'],
                    'task_time': i['tdate'].strftime("%Y-%m-%d %H:%M:%S")
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
        task_name = args.task_name
        searchdict = {'tname': task_name}
        task_query = DB.db.task.find_one(searchdict)
        if not task_query:  # 删除的任务不存在
            return {'status_code': 500, 'msg': '删除资产任务失败，此任务不存在'}
        DB.db.task.delete_one(searchdict)
        return {'status_code': 200, 'msg': '删除资产任务成功'}


class FuncAssetAPI(Resource):
    """资产管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("asset_company", type=str, location='json')
        self.parser.add_argument("asset_type", type=str, location='json')
        self.parser.add_argument("asset_name", type=str, location='json')
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchparams = args.searchParams
        count = DB.db.asset.find({'infostatus': '探测完成'}).count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchparams:  # 若没有查询参数
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
                    'asset_name': i['aname'],
                    'asset_type': i['type'],
                    'asset_company': i['ename'],
                    'vuln_status': i['vulnstatus'],
                    'vuln_time': vtime
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
        asset_name = args.asset_name
        searchdict = {'aname': asset_name}
        asset_query = DB.db.asset.find_one(searchdict)
        if not asset_query:  # 删除的资产不存在
            return {'status_code': 500, 'msg': '删除资产失败，此资产不存在'}
        DB.db.asset.delete_one(searchdict)
        return {'status_code': 200, 'msg': '删除资产成功'}


class InfoAPI(Resource):
    """渗透阶段信息收集工具"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("task_name", type=str, location='json')
        self.parser.add_argument("task_type", type=str, location='json')
        self.parser.add_argument("task_company", type=str, location='json')
        self.ports = '1-1000'

    def post(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        ports = self.ports
        task_name = args.task_name
        task_type = args.task_type
        task_company = args.task_company
        task_info = DB.db.task.find_one({'tname': task_name})['tinfo']
        task_objid = DB.db.task.find_one({'tname': task_name})['_id']

        if task_type == '主机':
            for info in task_info:
                # 主机探测
                uphost = NmapExt(hosts=info, ports=ports).host_discovery()
                # 端口扫描
                for host in uphost:
                    if not DB.db.asset.find_one({'aname': host}):
                        self.create_asset(aname=host, asset_type='主机', ename=task_company, objid=task_objid)
                        DB.db.asset.update_one({'aname': host}, {'$set': {'infostatus': '探测中(端口扫描)'}})
                        portsinfo = NmapExt(hosts=host, ports=ports).port_scan()
                        DB.db.asset.update_one({'aname': host},
                                               {'$set': {'ports': portsinfo, 'infostatus': '探测完成',
                                                         'vulnstatus': '未扫描'}})
        elif task_type == 'WEB':
            for asset_name in task_info:
                # WEB信息搜集
                if DB.db.asset.find_one({'aname': asset_name}):
                    continue
                self.create_asset(aname=asset_name, asset_type='WEB', ename=task_company, objid=task_objid)
                asset_objid = DB.db.asset.find_one({'aname': asset_name})['_id']
                DB.db.asset.update_one({'aname': asset_name}, {'$set': {'infostatus': '探测中(IP检测)'}})
                self.ip_detect(asset_name, asset_objid)
                DB.db.asset.update_one({'aname': asset_name}, {'$set': {'infostatus': '探测中(指纹识别)'}})
                webfinger = WappExt().detect(asset_name)
                DB.db.asset.update_one({'aname': asset_name},
                                       {'$set': {'finger': webfinger, 'infostatus': '探测中(目录扫描)'}})
                # dir_list = DirExt(asset_name).dir_scan()
                # DB.db.asset.update_one({'aname': asset_name}, {'$set': {'dir': dir_list, 'infostatus': '探测中(WAF检测)'}})
                waf = WafExt(asset_name).waf_detect()
                DB.db.asset.update_one({'aname': asset_name}, {'$set': {'waf': waf, 'infostatus': '探测中(子域探测)'}})
                subdomain_list = OneForAllExt(asset_name).subdomain_discovery()
                DB.db.asset.update_one({'aname': asset_name}, {'$set': {'infostatus': '探测完成', 'vulnstatus': '未扫描'}})
                for subdomain in subdomain_list:
                    if not DB.db.asset.find_one({'aname': subdomain}):
                        # 创建WEB任务
                        self.create_asset(aname=subdomain, asset_type='WEB', ename=task_company, objid=asset_objid)
                    DB.db.asset.update_one({'aname': subdomain}, {'$set': {'infostatus': '探测中(IP检测)'}})
                    self.ip_detect(subdomain, asset_objid)
                    DB.db.asset.update_one({'aname': subdomain}, {'$set': {'infostatus': '探测中(指纹识别)'}})
                    subdomain_webfinger = WappExt().detect(subdomain)
                    DB.db.asset.update_one({'aname': subdomain},
                                           {'$set': {'finger': subdomain_webfinger, 'infostatus': '探测中(WAF检测)'}})
                    waf = WafExt(subdomain).waf_detect()
                    DB.db.asset.update_one({'aname': subdomain}, {'$set': {'waf': waf, 'infostatus': '探测中(目录扫描)'}})
                    # subdomain_dir_list = DirExt(subdomain).dir_scan()
                    # DB.db.asset.update_one({'aname': subdomain},
                    #                        {'$set': {'dir': subdomain_dir_list, 'infostatus': '探测完成',
                    #                                  'vulnstatus': '未扫描'}})
                    DB.db.asset.update_one({'aname': subdomain}, {'$set': {'infostatus': '探测完成', 'vulnstatus': '未扫描'}})
        return {'status_code': 200}

    def create_asset(self, aname, asset_type, ename, objid):
        new_asset = {
            'aname': aname,
            'type': asset_type,
            'ename': ename,
            'infostatus': '未探测',
            'uname': session['username'],
            'createdate': datetime.datetime.now(),
            'parentid': objid,
        }
        DB.db.asset.insert_one(new_asset)

    def ip_detect(self, target, objid):
        # IP检测
        ports = self.ports
        i = NmapExt(hosts=target, ports=ports).host_discovery()
        if i:
            ip = i[0]
            DB.db.asset.update_one({'aname': target}, {'$set': {'ip': ip}})
            if not DB.db.asset.find_one({'aname': ip}):
                # 创建主机任务
                self.create_asset(aname=ip, asset_type='主机', ename=DB.db.asset.find_one({'aname': target})['ename'],
                                  objid=objid)
                DB.db.asset.update_one({'aname': ip}, {'$set': {'infostatus': '探测中(端口扫描)'}})
                portsinfo = NmapExt(hosts=ip, ports=ports).port_scan()
                DB.db.asset.update_one({'aname': ip},
                                       {'$set': {'ports': portsinfo, 'infostatus': '探测完成', 'vulnstatus': '未扫描'}})
        else:
            DB.db.asset.update_one({'aname': target}, {'$set': {'ip': 'None'}})


class VulnAPI(Resource):
    """漏洞扫描类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("asset_name", type=str, location='json')
        self.parser.add_argument("asset_type", type=str, location='json')
        self.parser.add_argument("asset_company", type=str, location='json')

    def post(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        asset_type = args.asset_type
        asset_name = args.asset_name
        company_name = args.asset_company
        if asset_type == 'WEB':
            XrayExt().scan_one(url=asset_name)
            DB.db.asset.update_one({'aname': asset_name},
                                   {'$set': {'vulndate': datetime.datetime.now(), 'vulnstatus': '扫描完成'}})
        elif asset_type == '主机':
            ports = DB.db.task.find_one({'aname': asset_name})['ports']
            # 根据端口进行弱口令探测
            pass


class FuncVulnAPI(Resource):
    """漏洞管理类"""

    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument("vuln_company", type=str, location='json')
        self.parser.add_argument("vuln_asset", type=str, location='json')
        self.parser.add_argument("page", type=int)
        self.parser.add_argument("limit", type=int)
        self.parser.add_argument("searchParams", type=str)

    def get(self):
        if not session.get('status'):
            return redirect(url_for('system_login'), 302)
        args = self.parser.parse_args()
        key_page = args.page
        key_limit = args.limit
        key_searchparams = args.searchParams
        count = DB.db.vuln.find().count()
        jsondata = {'code': 0, 'msg': '', 'count': count}
        if count == 0:  # 若没有数据返回空列表
            jsondata.update({'data': []})
            return jsondata
        if not key_searchparams:  # 若没有查询参数
            if not key_page or not key_limit:  # 判断是否有分页查询参数
                paginate = DB.db.vuln.find().limit(20).skip(0)
            else:
                paginate = DB.db.vuln.find().limit(key_limit).skip((key_page - 1) * key_limit)
        else:
            try:
                search_dict = json.loads(key_searchparams)  # 解析查询参数
            except:
                paginate = DB.db.vuln.find().limit(20).skip(0)
            else:
                if 'vuln_asset' not in search_dict or 'vuln_company' not in search_dict:  # 查询参数有误
                    paginate = DB.db.vuln.find().limit(20).skip(0)
                elif 'vuln_company' not in search_dict:
                    paginate1 = DB.db.vuln.find({'vasset': re.compile(search_dict['vuln_asset'])})
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
                elif 'vuln_asset' not in search_dict:
                    paginate1 = DB.db.vuln.find(
                        {'ename': re.compile(search_dict['vuln_company'])})
                    paginate = paginate1.limit(key_limit).skip((key_page - 1) * key_limit)
                    jsondata = {'code': 0, 'msg': '', 'count': paginate1.count()}
                else:
                    paginate1 = DB.db.asset.find({
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
                    'vuln_time': i['vdate']
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
        vuln_asset = args.vuln_asset
        searchdict = {'vasset': vuln_asset}
        asset_query = DB.db.vuln.find_one(searchdict)
        if not asset_query:  # 删除的资产不存在
            return {'status_code': 500, 'msg': '删除资产失败，此资产不存在'}
        DB.db.asset.delete_one(searchdict)
        return {'status_code': 200, 'msg': '删除资产成功'}
