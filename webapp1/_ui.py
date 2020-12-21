import sys, os
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

@ui.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        handle, pw = request.form["handle"], request.form["password"]
        if handle.isidentifier():
            if os.path.isdir(os.path.abspath("./storage/users/" + handle + "/")):
                try:
                    sec.loadPrivateKey("storage/users/"+handle+"/cert/user", "recv", passphrase=pw)
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
    server_privkey_sign = sec.loadPrivateKey("storage/service_cert/service", "sign", passphrase=server_passphrase)

    cert, privkey_sign, privkey_recv = sec.Certificate.newUser(name, handle + "@" + server_cert.Handle, [], server_cert)

    os.makedirs("storage/users/" + handle + "/cert")

    sec.storeCert(cert, privkey_sign, privkey_recv, to="storage/users/" + handle + "/cert/user", sign=server_privkey_sign, passphrase=pw)

    open("storage/users/" + handle + "/inbox", "w").close()