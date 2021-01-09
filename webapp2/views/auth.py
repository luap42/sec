from flask import *
from ..model import db, User
from hashlib import sha256

auth = Blueprint('auth', __name__)


@auth.route("/signin", methods=["GET", "POST"])
def signin():
    errors = []
    if request.method == "POST":
        passwd_hash = sha256(request.form['password'].encode("utf-8")).digest()
        user = User.query.filter_by(username=request.form['username'].encode("utf-8"), password_hash=passwd_hash).first()
        if user is None:
            errors += ["Benutzerkonto nicht gefunden"]
        else:
            session["user_id"] = user.id
            return redirect(url_for("index"))
    return render_template("auth/signin.html", errors=errors)


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    errors = []
    if request.method == "POST":
        passwd_hash = sha256(request.form['password']).hexdigest()
    return render_template("auth/signup.html", errors=errors)
