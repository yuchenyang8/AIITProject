from flask import Flask


def create_app():
    from . import config
    from project import models, view, api
    app = Flask(__name__)
    app.config.from_object(config.Config)
    models.init_app(app)
    api.init_app(app)
    view.init_app(app)
    return app
