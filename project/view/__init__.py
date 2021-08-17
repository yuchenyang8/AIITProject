from .html import aiit


def init_app(app):
    app.register_blueprint(aiit)

