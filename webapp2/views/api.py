from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from flask import *
import urllib

from ..model import db, User, Certificate, Message, validate_handle
from ..config import SETTINGS
from .. import sec


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
    f = open("cert/server_cert.certfile", "r")
    certfile = f.read()
    f.close()
    return certfile


@api.route("/certfile/challenge")
def certfile_challenge():
    server_privkey_sign = sec.loadPrivateKey(
        "cert/server_cert", "sign", passphrase=SETTINGS['CERTIFICATE_ENCRYPTION'])

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
    if validate_handle(handle):
        u = User.query.filter_by(username=handle).first_or_404()
        return u.certificate.certfile_body
    else:
        abort(400)


@api.route("/user/<handle>/recv", methods=["POST"])
def user_recv(handle):
    try:
        if validate_handle(handle):
            u = User.query.filter_by(username=handle).first_or_404()
            message = request.get_data().decode("utf-8")

            m = sec.MessageLoader.parse(message)
            from_server, from_handle = m.get_origin_untrusted()
            try:
                with urllib.request.urlopen("http://" + from_server + "/api/user/" + from_handle + "/certfile") as oc:
                    origin_cert = oc.read().decode("utf-8")
                original_cert = origin_cert
                origin_certfile = sec.CertFile.parse(origin_cert)
                origin_cert = origin_certfile.cert()
            except SyntaxError:
                return "REJECTED\nOrigin verification not possible."

            if not m.verify(origin_cert):
                return "REJECTED\nOrigin verification failed."

            trustlist = SETTINGS['trustlist']

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

            author = Certificate.query.filter_by(
                full_handle=from_handle + '@' + from_server).first()
            if author is None:
                author = Certificate()
                author.name = origin_cert.Name
                author.full_handle = from_handle + '@' + from_server
                author.certfile_body = original_cert
                author.is_validated = True
                db.session.add(author)

            message_date = m.date_untrusted()

            m = Message()
            m.postbox = 'inbox'
            m.author = author
            m.owner = u
            m.message_body = message
            m.subject = ''
            m.is_seen = m.is_opened = m.is_read = False
            m.sent_date = message_date
            db.session.add(m)
            db.session.commit()
            return "OK\n" + str(m.id)
        else:
            return "REJECTED\nUser Handle is invalid"
    except Exception as e:
        return "ERROR\n" + str(e)
