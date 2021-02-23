from flask import Flask
from flask_restful import Api
from flask_pymongo import PyMongo
from web.config import Config


APP = Flask(__name__)
APP.config.from_object(Config)
DB = PyMongo(APP)
API = Api(APP)


from web.route import html
from web.route.api import UserLogin


API.add_resource(UserLogin, '/api/user/login', endpoint='api_user_login')
