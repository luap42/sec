from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    full_handle = db.Column(db.String(255), unique=True, nullable=False)
    public_recv_key = db.Column(db.Text, nullable=False)
    public_sign_key = db.Column(db.Text, nullable=False)
    flags = db.Column(db.Text, nullable=False)
    is_validated = db.Column(db.Boolean, nullable=False)
    authorized_by = db.Column(db.String(255), nullable=False)
    authorized_signature = db.Column(db.String(255), nullable=False)
    local_user = db.relationship(
        'User', backref=db.backref('certificate', uselist=False), lazy=True)

    def __repr__(self):
        return '<Certificate %r>' % self.full_handle


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(75), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    private_recv_key = db.Column(db.Text, nullable=False)
    private_sign_key = db.Column(db.Text, nullable=False)
    certificate_id = db.Column(db.Integer, db.ForeignKey(
        'certificate.id'), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username
