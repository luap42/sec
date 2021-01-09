from flask import *
from hashlib import sha256

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
    return render_template("inbox/index.html", messages=messages)


@inbox.route("/sent")
def sent():
    messages = Message.query.filter_by(
        owner=request.user, postbox='sent').all()
    return render_template("inbox/sent.html", messages=messages)


@inbox.route("/deleted")
def deleted():
    messages = Message.query.filter_by(owner=request.user, postbox='deleted_inbox').all() + \
        Message.query.filter_by(owner=request.user, postbox='deleted_sent').all()
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