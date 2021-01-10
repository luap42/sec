from . import sec
from .config import SETTINGS
from .model import db
from .app import app

import sys
import os
sys.path.append("..")


with app.app_context():
    db.drop_all()
    db.create_all()

# cert, privkey_sign, privkey_recv = sec.Certificate.newService(
#     SETTINGS['SERVICE_NAME'], SETTINGS['SERVER_URL'])
# sec.storeCert(cert, privkey_sign, privkey_recv, to=os.path.dirname(__file__) + "/cert/server_cert",
#               passphrase=SETTINGS['CERTIFICATE_ENCRYPTION'])
