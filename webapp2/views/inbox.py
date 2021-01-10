from flask import *
from hashlib import sha256
import pdfkit

from ..model import db, User, Certificate, Message
from ..config import SETTINGS
from .. import sec

inbox = Blueprint('inbox', __name__)


@inbox.before_request
def validate_user():
    if not session.get('in', False):
        return redirect(url_for('index'))

    request.user = User.query.filter_by(id=session['user_id']).first()


@inbox.route("/")
def index():
    messages = Message.query.filter_by(
        owner=request.user, postbox='inbox').all()
    messages = sorted(messages, reverse=True, key=lambda m: m.sent_date)
    return render_template("inbox/index.html", messages=messages)


@inbox.route("/sent")
def sent():
    messages = Message.query.filter_by(
        owner=request.user, postbox='sent').all()
    messages = sorted(messages, reverse=True, key=lambda m: m.sent_date)
    return render_template("inbox/sent.html", messages=messages)


@inbox.route("/deleted")
def deleted():
    messages = Message.query.filter_by(owner=request.user, postbox='deleted_inbox').all() + \
        Message.query.filter_by(owner=request.user, postbox='deleted_sent').all()
    messages = sorted(messages, reverse=True, key=lambda m: m.sent_date)
    return render_template("inbox/deleted.html", messages=messages)

@inbox.route("/<id>")
def message(id):
    m = Message.query.filter_by(owner=request.user, id=id).first_or_404()
    user_privkey_recv = sec.inputPrivateKey(request.user.private_recv_key.encode("utf-8"), session['password'])
    message_file = m.message_body

    message = sec.MessageLoader.parse(message_file)
    message = message.decrypt(user_privkey_recv)

    m.is_seen = m.is_opened = m.is_read = True
    m.subject = message.Subject
    db.session.add(m)
    db.session.commit()
    return render_template("inbox/message.html", id=id, message=message, mobj = m)

@inbox.route("/<id>/pdf")
def message_pdf(id):
    m = Message.query.filter_by(owner=request.user, id=id).first_or_404()
    user_privkey_recv = sec.inputPrivateKey(request.user.private_recv_key.encode("utf-8"), session['password'])
    message_file = m.message_body

    message = sec.MessageLoader.parse(message_file)
    message = message.decrypt(user_privkey_recv)

    if message.DataType == "text/raw":
        html = render_template("content-types/text.html", message=message, safe_decode=safe_decode)
    elif message.DataType == "text/html":
        html = render_template("content-types/html.html", message=message)
    elif message.DataType == "application/pdf":
        http_response = make_response(message.Body)
        http_response.headers["Content-Type"] = "application/pdf"
        return http_response
    else:
        html = render_template("content-types/unknown.html", message=message)

    pdf = pdfkit.from_string(html, False, options={
        "title": message.Subject,
        'margin-top': '20mm',
        'margin-right': '25mm',
        'margin-bottom': '20mm',
        'margin-left': '25mm',
        'encoding': "UTF-8",
        'quiet': ''
    })

    http_response = make_response(pdf)
    http_response.headers["Content-Type"] = "application/pdf"
    return http_response

@inbox.route("/<id>/tds", methods=["GET", "POST"])
def tds(id):
    m = Message.query.filter_by(owner=request.user, id=id).first_or_404()

    if request.method == 'POST':
        CONVERSIONS = {
            'inbox': 'deleted_inbox',
            'deleted_inbox': 'inbox',
            'sent': 'deleted_sent',
            'deleted_sent': 'sent',
        }
        m.postbox = CONVERSIONS[m.postbox]
        db.session.add(m)
        db.session.commit()

        return redirect(url_for('inbox.message', id=id))

    return render_template('inbox/tds.html', m=m)
        

def safe_decode(txt):
    txt = txt.decode('utf-8').replace('<', '&lt;').replace('>', '&gt;')
    txt = txt.replace('&', '&quot;').replace("\r\n", "\n").replace("\n\r", "\n")
    txt = txt.replace("\r", "\n")
    while "\n\n\n" in txt:
        txt = txt.replace("\n\n\n", "\n\n")
    txt = txt.replace('\n\n', '</p><p>').replace('\n', '<br>')

    return txt