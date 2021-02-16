from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from flask import *
import sys
import os
import uuid
import urllib
sys.path.append("..")
import protocol.reference as sec


api = Blueprint("api", __name__)


@api.after_request
def add_text_header(resp):
    resp.headers['Content-type'] = 'text/plain;charset=utf-8'
    return resp


@api.route("/")
def index():
    return "SEC API"


@api.route("/certfile")
def certfile():
    f = open("storage/service_cert/service.certfile", "r")
    certfile = f.read()
    f.close()
    return certfile


@api.route("/certfile/challenge")
def certfile_challenge():
    f = open("storage/service_cert/passphrase", "r")
    server_passphrase = f.read()
    f.close()

    server_privkey_sign = sec.loadPrivateKey(
        "storage/service_cert/service", "sign", passphrase=server_passphrase)

    number = request.values["task"]
    if len(number) > 20:
        abort(400)

    return b64encode(server_privkey_sign.sign(
        number.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )).decode("utf-8")


@api.route("/user/<handle>/certfile")
def user_certfile(handle):
    if handle.isidentifier():
        if os.path.isdir(os.path.abspath("./storage/users/" + handle + "/")):
            f = open("storage/users/" + handle + "/cert/user.certfile", "r")
            certfile = f.read()
            f.close()
            return certfile
        else:
            abort(404)
    else:
        abort(400)


@api.route("/user/<handle>/recv", methods=["POST"])
def user_recv(handle):
    try:
        if handle.isidentifier():
            if os.path.isdir(os.path.abspath(
                    "./storage/users/" + handle + "/")):
                message_id = str(uuid.uuid4())
                message = request.get_data().decode("utf-8")

                m = sec.MessageLoader.parse(message)
                from_server, from_handle = m.get_origin_untrusted()
                try:
                    with urllib.request.urlopen("http://" + from_server + "/api/user/" + from_handle + "/certfile") as oc:
                        origin_cert = oc.read().decode("utf-8")
                    origin_certfile = sec.CertFile.parse(origin_cert)
                    origin_cert = origin_certfile.cert()
                except SyntaxError:
                    return "REJECTED\nOrigin verification not possible."

                if not m.verify(origin_cert):
                    return "REJECTED\nOrigin verification failed."

                f = open("storage/trustlist", "r")
                trustlist = [i.strip() for i in f.readlines()]
                f.close()

                if from_server not in trustlist:
                    try:
                        with urllib.request.urlopen("http://" + from_server + "/api/certfile") as oc:
                            origin_service_cert = oc.read().decode("utf-8")
                        origin_service_certfile = sec.CertFile.parse(
                            origin_service_cert)
                        origin_service_cert = origin_service_certfile.cert()
                    except SyntaxError:
                        return "REJECTED\nOrigin Service verification not possible."

                    if not origin_service_certfile.verify():
                        return "REJECTED\nOrigin Service Certificate not self-signed."

                    if not origin_certfile.verify(origin_service_cert):
                        return "REJECTED\nOrigin verification failed due to invalid certification chain."

                f = open("storage/messages/" + message_id, "w")
                f.write(message)
                f.close()

                f = open("storage/users/" + handle + "/inbox", "a")
                f.write(message_id + " [noch nicht geöffnet]\n")
                f.close()
                return "OK\n" + message_id
            else:
                return "REJECTED\nUser doesn't exist"
        else:
            return "REJECTED\nUser Handle is invalid"
    except Exception as e:
        return "ERROR\n" + str(e)
