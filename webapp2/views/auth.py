from flask import *
from ..model import db, User

auth = Blueprint('auth', __name__)


@auth.route("/signin")
def signin():
    return render_template("auth/signin.html")
