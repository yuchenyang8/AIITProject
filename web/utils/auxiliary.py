from functools import wraps
from flask import session, redirect, url_for, current_app


def login_required(func):
    """登录验证装饰器"""
    @wraps(func)
    def inner(*args, **kwargs):
        user = session.get('status')
        if not user:
            return redirect(url_for('system_login'), 302)
        return func(*args, **kwargs)
    return inner