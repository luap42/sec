from .views.api import api
from .views.send import send
from .views.inbox import inbox
from .views.auth import auth
from .views.contact import contact
from flask import *

from .config import SETTINGS
from .model import db

app = Flask(__name__)
app.config['SECRET_KEY'] = SETTINGS['SESSION_SECRET_KEY']

app.config['SQLALCHEMY_DATABASE_URI'] = SETTINGS['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)


app.register_blueprint(auth, url_prefix="/auth")
app.register_blueprint(inbox, url_prefix="/inbox")
app.register_blueprint(api, url_prefix="/api")
app.register_blueprint(send, url_prefix="/send")
app.register_blueprint(contact, url_prefix="/contact")


@app.route("/")
def index():
    if not session.get('in', False):
        return redirect(url_for('auth.signin'))
    else:
        return redirect(url_for('inbox.index'))
