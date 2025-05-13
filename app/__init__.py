from flask import Flask
from markupsafe import escape
import os
from app.modules.index import index_bp
from app.modules.login import login_bp
from app.modules.signup import signup_bp
from app.modules.home import home_bp
from app.modules.admin import admin_bp

application = Flask(__name__)
    
def create_app():
    application = Flask(__name__)
    # application.secret_key = 'your-secret-key'  # Change this to a secure secret key
    
    # Register blueprints
    application.register_blueprint(index_bp)
    application.register_blueprint(login_bp)
    application.register_blueprint(signup_bp)
    application.register_blueprint(home_bp)
    application.register_blueprint(admin_bp)
    
    return application