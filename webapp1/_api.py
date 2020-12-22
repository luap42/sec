from flask import *
import protocol.reference as sec
import sys
import os
import uuid, urllib
sys.path.append("..")


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
            if os.path.isdir(os.path.abspath("./storage/users/" + handle + "/")):
                message_id = str(uuid.uuid4())
                message = request.get_data().decode("utf-8")

                m = sec.MessageLoader.parse(message)
                from_server, from_handle = m.get_origin_untrusted()
                try:
                    with urllib.request.urlopen("http://" + from_server + "/api/user/" + from_handle + "/certfile") as oc:
                        origin_cert = oc.read().decode("utf-8")
                    origin_cert = sec.CertFile.parse(origin_cert)
                    origin_cert = origin_cert.cert()
                except SyntaxError:
                    return "REJECTED\nOrigin verification not possible."

                if not m.verify(origin_cert):
                    return "REJECTED\nOrigin verification failed."

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