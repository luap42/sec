import sys
sys.path.append("..")

import protocol.reference as sec
from flask import *

ui = Blueprint("ui", __name__)

@ui.route("/")
def index():
    return render_template("index.html")

@ui.route("/inbox")
def inbox():
    return render_template("inbox.html")

@ui.route("/write")
def write():
    return render_template("write.html")

@ui.route("/login")
def login():
    session['in'] = True
    session['user'] = "luap42"
    session['password'] = "1234"
    return redirect(url_for("ui.index"))

@ui.route("/logout")
def logout():
    session['in'] = False
    del session['user'], session['password']
    return redirect(url_for("ui.index"))