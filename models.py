from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import base64

db = SQLAlchemy()

# Model untuk pengguna


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Model untuk file yang diunggah dan terenkripsi


class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    file_size = db.Column(db.Integer, nullable=True)
    encryption_method = db.Column(db.String(50), nullable=False)
    encryption_key = db.Column(db.LargeBinary, nullable=True)
    iv = db.Column(db.LargeBinary, nullable=True)
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    encryption_time = db.Column(db.Float, nullable=True)
    decryption_time = db.Column(db.Float, nullable=True)
    user = db.relationship('User', backref='files')

    def store_key_iv(key, iv):
        return base64.b64encode(key).decode('utf-8'), base64.b64encode(iv).decode('utf-8') if iv else None

    # Contoh pengambilan
    def retrieve_key_iv(encoded_key, encoded_iv):
        return base64.b64decode(encoded_key), base64.b64decode(encoded_iv) if encoded_iv else None
