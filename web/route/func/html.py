from flask import render_template
from web.utils.auxiliary import login_required
from web import APP


@APP.route('/func/customer')
@login_required
def html_src_customer():
    """厂商页面"""
    return render_template('customer.html')


@APP.route('/func/customer_add')
@login_required
def html_src_customer_add():
    """厂商添加页面"""
    return render_template('customer_add.html')
