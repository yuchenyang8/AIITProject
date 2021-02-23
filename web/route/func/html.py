from flask import render_template, redirect, url_for
from web.utils.auxiliary import login_required
from web import APP
from flask import session


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



