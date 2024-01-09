import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

db = SQLAlchemy()
bcrypt = Bcrypt()

DB_NAME = "database.db"


def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = "e36950a2ca15cc926bdc46bf7eb2874e"
    app.config["SQLALCHEMY_DATABASE_URI"] = 'postgresql://ttracker_user:0KULUSwMavDTSk0XqGNhDQw6KRac3f94@dpg-cmejukn109ks73c77k8g-a/ttracker'

    # app.config['SECRET_KEY'] = "SECRET_KEY"
    # app.config["SQLALCHEMY_DATABASE_URI"] = f'sqlite:///{DB_NAME}'

    db.init_app(app)
    bcrypt.init_app(app)

    from .views import views
    from .auth import auth


    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Report, Attendance

    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.sign_in'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app
