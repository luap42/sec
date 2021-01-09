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
