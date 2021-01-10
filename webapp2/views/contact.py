from flask import *
from datetime import datetime
import urllib

from ..model import db, User, Certificate
from ..config import SETTINGS
from .. import sec

contact = Blueprint('contact', __name__)


@contact.before_request
def validate_user():
    if not session.get('in', False):
        return redirect(url_for('index'))

    request.user = User.query.filter_by(id=session['user_id']).first()


@contact.route("/<handle>")
def user(handle):
    cert = Certificate.query.filter_by(full_handle=handle).first_or_404()

    cert_handle, cert_server = handle.split('@')

    trust_status = 'neither_nor'

    try:
        with urllib.request.urlopen("http://" + cert_server + "/api/user/" +
                                    cert_handle + "/certfile") as tc:
            the_cert = tc.read().decode("utf-8")
        original_cert = the_cert
        the_certfile = sec.CertFile.parse(the_cert)
        the_cert = the_certfile.cert()
    except:
        print("TC not fetchable")
        trust_status = 'broken'

    if trust_status != 'broken':
        try:
            with urllib.request.urlopen("http://" + cert_server + "/api/certfile") as oc:
                origin_service_cert = oc.read().decode("utf-8")
                print('***'*50)
            origin_service_certfile = sec.CertFile.parse(
                origin_service_cert)
            origin_service_cert = origin_service_certfile.cert()
        except:
            print("OSC not fetchable")
            trust_status = 'broken'

    if trust_status != 'broken':
        if not origin_service_certfile.verify():
            print("OSC not self-signed")
            trust_status = 'broken'

    if trust_status != 'broken':
        if not the_certfile.verify(origin_service_cert):
            trust_status = 'broken'
            print("TC not properly signed")
        else:
            trustlist = SETTINGS['trustlist']
            if cert_server == SETTINGS['SERVER_URL']:
                trust_status = 'local'
            elif cert_server in trustlist:
                trust_status = 'trustworthy_service'

    cf = sec.CertFile.parse(cert.certfile_body)
    sec_cert = cf.cert()

    if cert.certfile_body != original_cert:
        cert.certfile_body = original_cert
        db.session.add(cert)
        db.session.commit()

    return render_template("contact/user.html", cert=cert, sec_cert=sec_cert, trust_status=trust_status)
