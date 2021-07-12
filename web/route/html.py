import datetime
import re

import bson
from flask import request, session, redirect, url_for, render_template

from web import APP, DB
from web.utils.auxiliary import kill_process, get_yaml
from web.utils.auxiliary import login_required, admin_required


@APP.route('/func/company')
@admin_required
def html_func_company():
    """厂商页面"""
    return render_template('company.html')


@APP.route('/func/company_add')
@admin_required
def html_func_company_add():
    """厂商添加页面"""
    return render_template('company_add.html')


@APP.route('/func/task')
@admin_required
def html_func_task():
    """信息搜集页面"""
    return render_template('task.html')


@APP.route('/func/task_add/')
@admin_required
def html_func_task_add():
    """任务添加页面"""
    company = []
    company_search = DB.db.company.find()
    for c in company_search:
        company.append(c['ename'])
    return render_template('task_add.html', companylist=company)


@APP.route('/func/asset')
@login_required
def html_func_asset():
    """资产信息页面"""
    return render_template('asset.html')


@APP.route('/func/asset/<string:asset_name>')
@login_required
def html_func_assetinfo(asset_name):
    """资产详情页面"""
    asset = DB.db.asset.find_one({'aname': asset_name})
    if asset['type'] == 'WEB':
        return render_template('web_detail.html', asset=asset)
    elif asset['type'] == '主机':
        return render_template('host_detail.html', asset=asset)
    elif asset['type'] == '固件':
        return render_template('firm_detail.html', asset=asset)


@APP.route('/func/poc/task')
@admin_required
def html_func_poc_task():
    """POC任务页面"""
    return render_template('poc_task.html')


@APP.route('/func/poc/task_add')
@admin_required
def html_func_poc_task_add():
    """添加POC任务页面"""
    return render_template('poc_task_add.html')


@APP.route('/func/poc')
@admin_required
def html_func_poc():
    """POC信息页面"""
    return render_template('poc.html')


@APP.route('/func/poc/task/<string:objid>')
@login_required
def html_func_poc_task_detail(objid):
    """POC漏洞详情页面"""
    objid = bson.ObjectId(objid)
    try:
        results = DB.db.poc.find_one({'_id': objid})['result']
        return render_template('poc_task_detail.html', results=results)
    except:
        return render_template('poc_task_detail.html', results=None)


@APP.route('/func/vulns/<string:vuln_type>')
@login_required
def html_func_vulns(vuln_type):
    """漏洞信息页面"""
    if vuln_type == 'web':
        return render_template('web_vulns.html', vuln_type='WEB')
    elif vuln_type == 'host':
        return render_template('host_vulns.html', vuln_type='主机')


@APP.route('/func/vulns/host/<string:objid>')
@login_required
def html_func_host_vulninfo(objid):
    """主机漏洞详情页面"""
    objid = bson.ObjectId(objid)
    vuln = DB.db.vuln.find_one({'_id': objid})
    return render_template('host_vuln_detail.html', vuln=vuln)


@APP.route('/func/vulns/web/<string:objid>')
@login_required
def html_func_web_vulninfo(objid):
    """WEB漏洞详情页面"""
    objid = bson.ObjectId(objid)
    vuln = DB.db.vuln.find_one({'_id': objid})
    return render_template('web_vuln_detail.html', vuln=vuln)


@APP.route('/func/company/<string:company_name>')
@admin_required
def html_func_company_info(company_name):
    """厂商详情页面"""
    hostcount = DB.db.asset.find({'ename': company_name, 'type': '主机'}).count()
    webcount = DB.db.asset.find({'ename': company_name, 'type': 'WEB'}).count()
    appcount = DB.db.asset.find({'ename': company_name, 'type': 'APP'}).count()
    firmwarecount = DB.db.asset.find({'ename': company_name, 'type': '固件'}).count()
    DB.db.company.update_one({'ename': company_name}, {
        '$set': {'count.host': hostcount, 'count.web': webcount, 'count.app': appcount,
                 'count.firmware': firmwarecount}})
    company = DB.db.company.find_one({'ename': company_name})
    return render_template('company_detail.html', company=company)


@APP.route('/func/password')
@login_required
def html_func_password():
    """弱口令结果页面"""
    return render_template('password.html')


@APP.route('/func/webhook', methods=['POST'])
def xray_webhook():
    data = request.json
    data_type = data.get("type")
    if data_type == 'web_statistic':
        if data['data']['num_found_urls'] - data['data']['num_scanned_urls'] == 0:
            kill_process('xray.exe')
    if 'create_time' in data['data']:
        url = re.findall(r'//(.+?)/', data['data']["target"]["url"])[0]
        ename = DB.db.asset.find_one({'aname': url})['ename']
        DB.db.vuln.insert_one({
            'vasset': url,
            'vtype': data['data']["plugin"],
            'vdate': str(datetime.datetime.fromtimestamp(data['data']["create_time"] / 1000)).split('.')[0],
            'type': 'WEB',
            'vdetail': data['data']['detail'],
            'vstatus': '未修复',
            'ename': ename,
        })
        # 钉钉推送漏洞消息
        # content = """
        #             ## xray 发现了新漏洞
        #             url: {url}
        #
        #             漏洞类型: {plugin}
        #
        #             发现时间: {create_time}
        #
        #             请及时查看和处理
        #             """.format(url=url, plugin=vuln['data']["plugin"],
        #                        create_time=str(datetime.datetime.fromtimestamp(vuln['data']["create_time"] / 1000)))
        # try:
        #     push_dingding_group(content)
        # except Exception as e:
        #     logging.exception(e)
    return 'ok'


@APP.route('/')
def system_login():
    """用户登录页面"""
    if 'status' in session:
        return redirect(url_for('system_index'), 302)
    return render_template('login.html')


@APP.route('/index')
@login_required
def system_index():
    """框架首页"""
    return render_template('nav.html')


@APP.route('/api/user/logout')
@login_required
def api_user_logout():
    """用户注销"""
    session.pop('status')
    session.pop('username')
    return redirect(url_for('system_login'), 302)


@APP.route('/dashboard')
@login_required
def fetch_dashboard_page():
    return render_template('dashboard.html')


@APP.route('/extmanage')
@admin_required
def html_extensions_manage():
    """插件管理页面"""
    return render_template('ext_manage.html')


@APP.route('/extmanage/<string:name>')
@admin_required
def html_extensions_modify(name):
    """插件配置页面"""
    ext = get_yaml('extensions\\ext_config.yaml')[name]
    return render_template('ext_modify.html', ext=ext, name=name)


@APP.route('/user')
@admin_required
def html_users_manage():
    """用户管理页面"""
    return render_template('user.html')


@APP.route('/user/user_add')
@admin_required
def html_user_add():
    """用户添加页面"""
    return render_template('user_add.html')


@APP.route('/user/user_modify')
@login_required
def html_user_modify():
    """用户修改密码页面"""
    return render_template('user_modify.html')
