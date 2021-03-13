from flask import session, redirect, url_for, render_template, jsonify, request
from web.utils.auxiliary import login_required
from web import APP


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
def api_user_logout():
    '''用户注销'''
    session.pop('status')
    session.pop('username')
    return redirect(url_for('system_login'), 302)


@APP.route('/fetch/dashboard')
def fetch_dashboard_page():
    return render_template('dashboard.html')


@APP.route('/fetch/company')
def fetch_company_page():
    return render_template('company.html')


@APP.route('/fetch/task')
def fetch_task_page():
    return render_template('task.html')