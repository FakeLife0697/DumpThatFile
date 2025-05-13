from flask import Flask, request, render_template, redirect, url_for
from markupsafe import escape
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        if username == 'admin':
            return redirect(url_for('admin'))
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

# route cho upload file
@app.route('/upload', methods=['POST'])
def upload():
    # get file from request
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)