from flask import render_template, redirect, url_for, request
from web.utils.auxiliary import login_required
from web import APP, DB
import datetime
import logging
from web.utils.auxiliary import push_dingding_group


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


@APP.route('/test')
def test():
    return render_template('test.html')


@APP.route('/func/asset')
def html_func_asset():
    """资产信息页面"""
    return render_template('asset.html')


@APP.route('/func/webhook', methods=['POST'])
def xray_webhook():
    vuln = request.json
    if 'create_time' in vuln['data']:
        print('YES')
        print(vuln['data'])
        content = """
                    ## xray 发现了新漏洞
                    url: {url}

                    漏洞类型: {plugin}

                    发现时间: {create_time}

                    请及时查看和处理
                    """.format(url=vuln['data']["target"]["url"], plugin=vuln['data']["plugin"],
                               create_time=str(datetime.datetime.fromtimestamp(vuln['data']["create_time"] / 1000)))
        try:
            push_dingding_group(content)
        except Exception as e:
            logging.exception(e)
    return 'ok'


## for debug or show temporary html file
@APP.route('/temp')
def temp():
    return render_template('temp.html')
