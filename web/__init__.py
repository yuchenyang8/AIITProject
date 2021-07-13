from flask import Flask
from flask_pymongo import PyMongo
from flask_restful import Api

from web.config import Config

APP = Flask(__name__)
APP.config.from_object(Config)
DB = PyMongo(APP)
API = Api(APP)

from web.route import html
from web.route.api import *

API.add_resource(UserLoginAPI, '/api/user/login', endpoint='api_user_login')
API.add_resource(FuncCompanyAPI, '/api/func/company', endpoint='api_func_company')
API.add_resource(CompanyInfoAPI, '/api/func/company/<string:company>/<string:asset_type>',
                 endpoint='api_func_company_info')
API.add_resource(CompanyVulnTrendsAPI, '/api/func/company/trends/<string:company>', endpoint='api_func_company_trends')
API.add_resource(FuncTaskAPI, '/api/func/task', endpoint='api_func_task')
API.add_resource(PocTaskAPI, '/api/func/poc/task', endpoint='api_func_poc_task')
API.add_resource(PocAPI, '/api/func/poc', endpoint='api_func_poc')
API.add_resource(FuncAssetAPI, '/api/func/asset', endpoint='api_func_asset')
API.add_resource(FuncHostInfoAPI, '/api/func/asset/host', endpoint='api_func_asset_host')
API.add_resource(FuncWebInfoAPI, '/api/func/asset/web', endpoint='api_func_asset_web')
API.add_resource(FuncAppInfoAPI, '/api/func/asset/app', endpoint='api_func_asset_app')
API.add_resource(FuncFirmInfoAPI, '/api/func/asset/firm', endpoint='api_func_asset_firm')
API.add_resource(FuncVulnAPI, '/api/func/vulns', endpoint='api_func_vulns')
API.add_resource(InfoAPI, '/api/func/info', endpoint='api_func_info')
API.add_resource(FuncInfoAPI, '/api/func/infos', endpoint='api_func_infos')
API.add_resource(VulnAPI, '/api/func/vuln', endpoint='api_func_vuln')
API.add_resource(PasswordAPI, '/api/func/password', endpoint='api_func_password')
API.add_resource(ChartAPI, '/api/func/chart', endpoint='api_func_chart')
API.add_resource(DashBoardAPI, '/api/dashboard', endpoint='api_dashboard')
API.add_resource(ExtAPI, '/api/ext', endpoint='api_ext')
API.add_resource(UserAPI, '/api/user', endpoint='api_user')
API.add_resource(CaseAPI, '/api/case', endpoint='api_case')
API.add_resource(CaseTaskAPI, '/api/case/task', endpoint='api_case_task')

