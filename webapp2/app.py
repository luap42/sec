from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from config import SETTINGS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SETTINGS['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)