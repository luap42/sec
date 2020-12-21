import sys, os
sys.path.append("..")

from flask import *

import _api, _ui

app = Flask(__name__)
app.config['SECRET_KEY'] = "aaaaaaaaaaaa" # os.urandom(12)

@app.route("/")
def index():
    return redirect("/ui")

app.register_blueprint(_api.api, url_prefix="/api")
app.register_blueprint(_ui.ui, url_prefix="/ui")