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
from web.route.system.api import UserLoginAPI, DashBoardAPI
from web.route.func.api import FuncCompanyAPI, FuncTaskAPI, FuncAssetAPI, InfoAPI, VulnAPI, FuncVulnAPI, FuncInfoAPI, ChartAPI

API.add_resource(UserLoginAPI, '/api/user/login', endpoint='api_user_login')
API.add_resource(FuncCompanyAPI, '/api/func/company', endpoint='api_func_company')
API.add_resource(FuncTaskAPI, '/api/func/task', endpoint='api_func_task')
API.add_resource(FuncAssetAPI, '/api/func/asset', endpoint='api_func_asset')
API.add_resource(FuncVulnAPI, '/api/func/vulns', endpoint='api_func_vulns')
API.add_resource(InfoAPI, '/api/func/info', endpoint='api_func_info')
API.add_resource(FuncInfoAPI, '/api/func/infos', endpoint='api_func_infos')
API.add_resource(VulnAPI, '/api/func/vuln', endpoint='api_func_vuln')
API.add_resource(ChartAPI, '/api/func/chart', endpoint='api_func_chart')
API.add_resource(DashBoardAPI, '/api/dashboard', endpoint='api_dashboard')