from flask import Flask, request
from markupsafe import escape
import os

app = Flask(__name__)

@app.route("/")
def home():
    return "Hello World!"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        pass
    
if __name__ == "__main__":
    app.run()