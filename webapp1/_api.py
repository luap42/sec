import sys
sys.path.append("..")

import protocol.reference as sec
from flask import *

api = Blueprint("api", __name__)

@api.route("/")
def index():
    return "SEC API"

@api.route("/certfile")
def certfile():
    return "Certfile comes here"

@api.route("/certfile/challenge")
def certfile_challenge():
    return "Challenge comes here"

@api.route("/user/<handle>/certfile")
def user_certfile(handle):
    return f"User Certfile for {handle} comes here"

@api.route("/user/<handle>/recv", methods=["POST"])
def user_recv(handle):
    return "REJECTED\nThis server is not ready to receive messages"