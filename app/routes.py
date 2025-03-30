from flask import Blueprint, Response, render_template, send_file, send_from_directory

# Blueprint named 'main'
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    return render_template('index.html')

# Login page
@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    
    error = None
    return render_template('login.html', error = error)
    pass