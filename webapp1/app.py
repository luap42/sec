import _ui
import _api
from flask import *
import sys
import os
sys.path.append("..")


app = Flask(__name__)
app.config['SECRET_KEY'] = "aaaaaaaaaaaa"  # os.urandom(12)

app.register_blueprint(_api.api, url_prefix="/api")
app.register_blueprint(_ui.ui)
