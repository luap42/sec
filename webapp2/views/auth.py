from flask import *
from hashlib import sha256

from ..model import db, User, Certificate
from ..config import SETTINGS
from .. import sec

auth = Blueprint('auth', __name__)


@auth.route("/signoff")
def signoff():
    session["in"] = False
    del session["password"]
    del session["user_id"]
    return redirect(url_for('index'))

@auth.route("/signin", methods=["GET", "POST"])
def signin():
    errors = []
    if request.method == "POST":
        passwd_hash = sha256(request.form['password'].encode("utf-8")).digest()
        user = User.query.filter_by(username=request.form['username'].encode(
            "utf-8"), password_hash=passwd_hash).first()
        if user is None:
            errors += ["Benutzerkonto nicht gefunden"]
        else:
            session["in"] = True
            session["password"] = request.form['password']
            session["user_id"] = user.id
            return redirect(url_for("index"))

    return render_template("auth/signin.html", errors=errors)


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    errors = []
    if request.method == "POST":
        passwd_hash = sha256(
            request.form['password'].encode("utf-8")).digest()
        name, handle, pw = request.form["full_name"], request.form["username"], request.form["password"]
        if handle.isidentifier():
            data = _create_user(name, handle, pw, passwd_hash)
            errors += data["errors"]
        else:
            errors += ["Ungültige Kennung"]

        if len(errors) == 0:
            session['in'] = True
            session['user_id'] = data["id"]
            session['password'] = pw
            return redirect(url_for("index"))

    return render_template("auth/signup.html", errors=errors)


def _create_user(name, handle, pw, pw_hash):
    server_cert = sec.CertFile.load("cert/server_cert.certfile")
    if not server_cert.verify():
        return {"errors": ["Serverfehler. Ungültiges Service-Zertifikat."]}
    server_cert = server_cert.cert()
    server_privkey_sign = sec.loadPrivateKey(
        "cert/server_cert", "sign",
        passphrase=SETTINGS['CERTIFICATE_ENCRYPTION'])

    cert, privkey_sign, privkey_recv = sec.Certificate.newUser(
        name, handle + "@" + server_cert.Handle, [], server_cert)

    cert = cert.build_signed(server_privkey_sign)
    privkey_sign = sec.outputPrivateKey(privkey_sign, passphrase=pw)
    privkey_recv = sec.outputPrivateKey(privkey_recv, passphrase=pw)

    c = Certificate()
    c.name = name.encode('utf-8')
    c.full_handle = (handle + '@' + SETTINGS['SERVER_URL']).encode("utf-8")
    c.certfile_body = cert.encode('utf-8')
    c.is_validated = True


    u = User()
    u.username = handle.encode('utf-8')
    u.password_hash = pw_hash
    u.private_sign_key = privkey_sign
    u.private_recv_key = privkey_recv

    u.certificate = c

    db.session.add(c)
    db.session.add(u)
    db.session.commit()

    return {"id": u.id, "errors": []}