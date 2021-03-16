from flask import Flask
from flask_restful import Api
from flask_pymongo import PyMongo
from web.config import Config

APP = Flask(__name__)
APP.config.from_object(Config)
DB = PyMongo(APP)
API = Api(APP)

from web.route.system import html
from web.route.func import html
from web.route.system.api import UserLogin, Dashboard_API
from web.route.func.api import FuncCompanyAPI, FuncTaskAPI
from web.route.func.api import ReconAPI

API.add_resource(UserLogin, '/api/user/login', endpoint='api_user_login')
API.add_resource(FuncCompanyAPI, '/api/func/company', endpoint='api_func_company')
API.add_resource(FuncTaskAPI, '/api/func/task', endpoint='api_func_task')
API.add_resource(ReconAPI, '/api/func/recon', endpoint='api_func_recon')
API.add_resource(Dashboard_API, '/api/dashboard_info', endpoint='dashboard_info')