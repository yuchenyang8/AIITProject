from flask_restful import Api

from .api import UserLoginAPI, CompanyAPI, InfoTaskAPI, PocTaskAPI, PocAPI, AssetAPI, AssetInfoAPI, InfoAPI, \
    PasswordAPI, ExtAPI, UserAPI, CaseAPI, CaseTaskAPI, VulnAPI, CompanyVulnAPI


def init_app(app):
    uy_api = Api(app)
    uy_api.add_resource(UserLoginAPI, '/api/user/login', endpoint='api_user_login')
    uy_api.add_resource(CompanyAPI, '/api/company', endpoint='api_company')
    uy_api.add_resource(InfoTaskAPI, '/api/task/info', endpoint='api_info_task')
    uy_api.add_resource(PocTaskAPI, '/api/task/poc', endpoint='api_poc_task')
    uy_api.add_resource(PocAPI, '/api/poc', endpoint='api_poc')
    uy_api.add_resource(AssetAPI, '/api/asset', endpoint='api_asset')
    uy_api.add_resource(AssetInfoAPI, '/api/asset/<string:company>/<string:asset_type>', endpoint='api_asset_info')
    uy_api.add_resource(InfoAPI, '/api/info', endpoint='api_info')
    uy_api.add_resource(InfoAPI, '/api/info/<string:asset_name>/<string:info_type>', endpoint='api_info_detail')
    uy_api.add_resource(PasswordAPI, '/api/password', endpoint='api_password')
    uy_api.add_resource(ExtAPI, '/api/ext', endpoint='api_ext')
    uy_api.add_resource(UserAPI, '/api/user', endpoint='api_user')
    uy_api.add_resource(CaseAPI, '/api/case', endpoint='api_case')
    uy_api.add_resource(CaseTaskAPI, '/api/task/case', endpoint='api_case_task')
    uy_api.add_resource(VulnAPI, '/api/vuln', endpoint='api_vuln')
    uy_api.add_resource(CompanyVulnAPI, '/api/vuln/<string:info_type>/<string:company>/<string:asset_type>',
                        endpoint='api_company_vuln')
