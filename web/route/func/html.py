from flask import render_template, redirect, url_for, request
from web.utils.auxiliary import login_required
from web import APP, DB
import datetime
import logging
from web.utils.auxiliary import push_dingding_group, kill_process
import re


@APP.route('/func/company')
@login_required
def html_func_company():
    """厂商页面"""
    return render_template('company.html')


@APP.route('/func/company_add')
@login_required
def html_func_company_add():
    """厂商添加页面"""
    return render_template('company_add.html')


@APP.route('/func/task')
@login_required
def html_func_task():
    """资产任务页面"""
    return render_template('task.html')


@APP.route('/func/task_add/')
@login_required
def html_func_task_add():
    """任务添加页面"""
    company = []
    company_search = DB.db.company.find()
    for c in company_search:
        company.append(c['ename'])
    return render_template('task_add.html', companylist=company)


@APP.route('/func/asset')
def html_func_asset():
    """资产信息页面"""
    return render_template('asset.html')


@APP.route('/func/vulns/<string:vuln_type>')
def html_func_vulns(vuln_type):
    """漏洞信息页面"""
    if vuln_type == 'web':
        return render_template('web_vulns.html', vuln_type='WEB')
    elif vuln_type == 'host':
        return render_template('host_vulns.html', vuln_type='主机')


@APP.route('/func/asset/<string:asset_name>')
def html_func_assetinfo(asset_name):
    """资产详情页面"""
    asset = DB.db.asset.find_one({'aname': asset_name})
    return render_template('asset_detail.html', asset=asset)


@APP.route('/func/test')
def html_func_newtask():
    """资产信息页面"""
    return render_template('newtask.html')


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
