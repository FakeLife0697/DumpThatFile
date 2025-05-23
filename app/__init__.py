from flask import Flask
from markupsafe import escape
import os
from datetime import timedelta
from app.modules.index import index_bp
from app.modules.login import login_bp
from app.modules.signup import signup_bp
from app.modules.home import home_bp
from app.modules.admin import admin_bp
from app.logger import setup_logger
    
def create_app():
    application = Flask(__name__)
    application.secret_key = os.urandom(24)
    
    logger = setup_logger()
    application.logger = logger
    
    # Session Security Configurations
    application.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
    application.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
    application.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
    application.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes = 30)  # Session timeout after 30 minutes
    application.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Rotate session ID on each request
    
    # Additional Security Headers
    @application.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    # Register blueprints
    application.register_blueprint(index_bp)
    application.register_blueprint(login_bp)
    application.register_blueprint(signup_bp)
    application.register_blueprint(home_bp)
    application.register_blueprint(admin_bp)
    
    return application