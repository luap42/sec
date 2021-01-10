from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    full_handle = db.Column(db.String(255), unique=True, nullable=False)
    certfile_body = db.Column(db.Text)
    is_validated = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return '<Certificate %r>' % self.full_handle


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(75), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    private_recv_key = db.Column(db.Text, nullable=False)
    private_sign_key = db.Column(db.Text, nullable=False)
    certificate_id = db.Column(db.Integer, db.ForeignKey(
        'certificate.id'), nullable=False)
    certificate = db.relationship('Certificate',
                                  backref='user', lazy=True)

    def __repr__(self):
        return '<User %r>' % self.username


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    postbox = db.Column(db.String(30), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey(
        'certificate.id'), nullable=False)
    author = db.relationship('Certificate',
                             backref='message', lazy=True)

    owner_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False)
    owner = db.relationship('User', backref='message', lazy=True)

    message_body = db.Column(db.Text, nullable=False)
    subject = db.Column(db.String(255))

    is_seen = db.Column(db.Boolean, nullable=False)
    is_opened = db.Column(db.Boolean, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False)
    sent_date = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return '<Certificate %r>' % self.full_handle


def validate_handle(handle):
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                    "0123456789._-"
    handle = [*handle]
    return False not in [i in allowed_chars for i in handle]
