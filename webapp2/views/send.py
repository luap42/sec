from flask import *
from datetime import datetime
import urllib

from ..model import db, User, Certificate, Message
from ..config import SETTINGS
from .. import sec

send = Blueprint('send', __name__)


@send.before_request
def validate_user():
    if not session.get('in', False):
        return redirect(url_for('index'))

    request.user = User.query.filter_by(id=session['user_id']).first()


@send.route("/")
def index():
    return render_template("send/index.html")


@send.route("/forward/<id>")
def forward(id):
    m = Message.query.filter_by(owner=request.user, id=id).first_or_404()
    user_privkey_recv = sec.inputPrivateKey(
        request.user.private_recv_key.encode("utf-8"), session['password'])
    message_file = m.message_body

    message = sec.MessageLoader.parse(message_file)
    message = message.decrypt(user_privkey_recv)

    return render_template("send/forward.html", id=id, message=message, mobj=m)


@send.route("/", methods=["POST"])
def it():
    to, subject, content_type = request.form['recipient'], request.form['subject'], request.form['content-type']

    if content_type == 'text/raw':
        body = request.form['body_raw'].encode('utf-8')
    elif content_type == 'text/html':
        body = request.form['body_html'].encode('utf-8')
    elif content_type == 'application/pdf':
        body = request.files['body_pdf'].read()
    else:
        body = request.form['body'].encode('utf-8')

    c = Certificate.query.filter_by(full_handle=to).first()
    own_cert = sec.CertFile.parse(
        request.user.certificate.certfile_body).cert()
    to_handle, to_server = to.split('@')

    if c is None:
        try:
            with urllib.request.urlopen("http://" + to_server + "/api/user/" + to_handle + "/certfile") as tc:
                to_cert = tc.read().decode("utf-8")
            original_cert = origin_cert
            to_certfile = sec.CertFile.parse(to_cert)
            to_cert = to_certfile.cert()
        except SyntaxError:
            return render_template("send/done.html", code="ERROR",
                                   comment="Verschlüsselungszertifikat nicht erreichbar.")

        trustlist = SETTINGS['trustlist']

        if from_server not in trustlist:
            try:
                with urllib.request.urlopen("http://" + to_server + "/api/certfile") as tsc:
                    to_service_cert = tsc.read().decode("utf-8")
                to_service_certfile = sec.CertFile.parse(
                    to_service_cert)
                to_service_cert = to_service_certfile.cert()
            except SyntaxError:
                return render_template(
                    "send/done.html", code="ERROR", comment="Verschlüsselungszertifikat des Anbieters des Empfängers nicht erreichbar.")

            if not to_service_certfile.verify():
                return render_template(
                    "send/done.html", code="ERROR", comment="Verschlüsselungszertifikat des Anbieters des Empfängers spezifikationswidrig nicht eigensigniert.")

            if not to_certfile.verify(to_service_cert):
                return render_template(
                    "send/done.html", code="ERROR", comment="Verschlüsselungszertifikat Empfängers nicht ordnungsgemäß signiert.")

        c = Certificate()
        c.name = to_cert.Name
        c.full_handle = from_handle + '@' + from_server
        c.certfile_body = original_cert
        c.is_validated = True

        db.session.add(c)
        db.session.commit()

    user_privkey_sign = sec.inputPrivateKey(
        request.user.private_sign_key.encode("utf-8"), session['password'])

    recipient_cert = sec.CertFile.parse(c.certfile_body).cert()

    origm = sec.Message(subject, content_type, body,
                        own_cert, recipient_cert, datetime.now())
    m = origm.encrypt(recipient_cert)
    m_code = m.build_signed(user_privkey_sign)

    req = urllib.request.Request(
        "http://" + to_server + "/api/user/" + to_handle + "/recv")
    req.method = "POST"
    req.data = m_code.encode("utf-8")
    try:
        with urllib.request.urlopen(req) as res:
            response = res.read().decode("utf-8")
    except BaseException:
        response = "ERROR\nServer-Fehler"

    code, comment = response.split("\n", maxsplit=1)

    if code == 'OK':
        own_m = origm.encrypt(own_cert)
        own_m = own_m.build_signed(user_privkey_sign)

        m = Message()
        m.postbox = 'sent'
        m.author = c
        m.owner = request.user
        m.message_body = own_m
        m.subject = origm.Subject
        m.is_seen = m.is_read = False
        m.is_opened = True
        m.origin_id = comment
        m.sent_date = origm.MessageDate
        db.session.add(m)
        db.session.commit()

    return render_template("send/done.html", code=code, comment=comment)


@send.route("/forward/<id>", methods=["POST"])
def forward_it(id):
    m = Message.query.filter_by(owner=request.user, id=id).first_or_404()
    user_privkey_recv = sec.inputPrivateKey(
        request.user.private_recv_key.encode("utf-8"), session['password'])
    message_file = m.message_body

    message = sec.MessageLoader.parse(message_file)
    message = message.decrypt(user_privkey_recv)

    request.form = request.form.copy()

    request.form['body'] = request.form['body_html'] = request.form['body_raw'] = message.Body.decode(
        "utf-8")
    request.form['content-type'] = message.DataType

    return it()
