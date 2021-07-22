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
API.add_resource(CompanyAPI, '/api/company', endpoint='api_company')
API.add_resource(InfoTaskAPI, '/api/task/info', endpoint='api_info_task')
API.add_resource(PocTaskAPI, '/api/task/poc', endpoint='api_poc_task')
API.add_resource(PocAPI, '/api/poc', endpoint='api_poc')
API.add_resource(AssetAPI, '/api/asset', endpoint='api_asset')
API.add_resource(AssetInfoAPI, '/api/asset/<string:company>/<string:asset_type>', endpoint='api_asset_info')
API.add_resource(InfoAPI, '/api/info', endpoint='api_info')
API.add_resource(InfoAPI, '/api/info/<string:asset_name>/<string:info_type>', endpoint='api_info_detail')
API.add_resource(PasswordAPI, '/api/password', endpoint='api_password')
API.add_resource(ExtAPI, '/api/ext', endpoint='api_ext')
API.add_resource(UserAPI, '/api/user', endpoint='api_user')
API.add_resource(CaseAPI, '/api/case', endpoint='api_case')
API.add_resource(CaseTaskAPI, '/api/task/case', endpoint='api_case_task')
API.add_resource(VulnAPI, '/api/vuln', endpoint='api_vuln')
API.add_resource(CompanyVulnAPI, '/api/vuln/<string:info_type>/<string:company>/<string:asset_type>',
                 endpoint='api_company_vuln')
