from flask import *
import protocol.reference as sec
from datetime import datetime
import sys
import os
import urllib
sys.path.append("..")


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


@ui.route("/write", methods=["POST"])
def write_do():
    to, subject, body = request.form["to"], request.form["subject"], request.form["body"]
    to_handle, to_server = to.split("@")

    user_cert = sec.CertFile.load(
        "storage/users/" + session['user'] + "/cert/user.certfile")
    user_cert = user_cert.cert()

    with urllib.request.urlopen("http://" + to_server + "/api/user/" + to_handle + "/certfile") as cf:
        cfc = cf.read().decode("utf-8")
    recipient_cert = sec.CertFile.parse(cfc)
    recipient_cert = recipient_cert.cert()

    user_privkey_sign = sec.loadPrivateKey(
        "storage/users/" + session["user"] + "/cert/user", "sign", passphrase=session["password"])

    m = sec.Message(subject, "text/raw", body.encode("utf-8"),
                    user_cert, recipient_cert, datetime.now())
    m = m.encrypt(recipient_cert)
    m_code = m.build_signed(user_privkey_sign)

    req = urllib.request.Request(
        "http://" + to_server + "/api/user/" + to_handle + "/recv")
    req.method = "POST"
    req.data = m_code.encode("utf-8")
    try:
        with urllib.request.urlopen(req) as res:
            response = res.read().decode("utf-8")
    except:
        response = "ERROR\nServer-Fehler"

    return render_template("write_done.html", response=response)


@ui.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        handle, pw = request.form["handle"], request.form["password"]
        if handle.isidentifier():
            if os.path.isdir(os.path.abspath("./storage/users/" + handle + "/")):
                try:
                    sec.loadPrivateKey(
                        "storage/users/"+handle+"/cert/user", "recv", passphrase=pw)
                except:
                    error = "Dieses Benutzerkonto existiert nicht."
            else:
                error = "Dieses Benutzerkonto existiert nicht."
        else:
            error = "Ungültige Kennung"

        if not error:
            session['in'] = True
            session['user'] = handle
            session['password'] = pw
            return redirect(url_for("ui.index"))

    return render_template("login.html", error=error)


@ui.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        name, handle, pw = request.form["name"], request.form["handle"], request.form["password"]
        if handle.isidentifier():
            if not os.path.isdir(os.path.abspath("./storage/users/" + handle + "/")):
                error = _generate_user_data(name, handle, pw)
            else:
                error = "Dieses Benutzerkonto existiert bereits."
        else:
            error = "Ungültige Kennung"

        if not error:
            session['in'] = True
            session['user'] = handle
            session['password'] = pw
            return redirect(url_for("ui.index"))
    return render_template("register.html", error=error)


@ui.route("/logout")
def logout():
    session['in'] = False
    del session['user'], session['password']
    return redirect(url_for("ui.index"))


def _generate_user_data(name, handle, pw):
    server_cert = sec.CertFile.load("storage/service_cert/service.certfile")
    if not server_cert.verify():
        return "Serverfehler. Ungültiges Service-Zertifikat."
    server_cert = server_cert.cert()
    f = open("storage/service_cert/passphrase", "r")
    server_passphrase = f.read()
    f.close()
    server_privkey_sign = sec.loadPrivateKey(
        "storage/service_cert/service", "sign", passphrase=server_passphrase)

    cert, privkey_sign, privkey_recv = sec.Certificate.newUser(
        name, handle + "@" + server_cert.Handle, [], server_cert)

    os.makedirs("storage/users/" + handle + "/cert")

    sec.storeCert(cert, privkey_sign, privkey_recv, to="storage/users/" +
                  handle + "/cert/user", sign=server_privkey_sign, passphrase=pw)

    open("storage/users/" + handle + "/inbox", "w").close()
