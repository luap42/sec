from flask import *

from .config import SETTINGS
from .model import db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SETTINGS['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

from .views.auth import auth

app.register_blueprint(auth, url_prefix="/auth")


@app.route("/")
def index():
    return redirect(url_for('auth.signin'))
