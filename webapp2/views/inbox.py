from flask import *
from hashlib import sha256

from ..model import db, User, Certificate
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
    return render_template("inbox/index.html")

@inbox.route("/sent")
def sent():
    return render_template("inbox/sent.html")