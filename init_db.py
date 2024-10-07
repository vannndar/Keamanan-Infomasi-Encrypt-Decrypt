from models import User, UploadedFile, EncryptionKey
from app import db, app

# Menggunakan application context
with app.app_context():
    db.create_all()

print("Database tables created successfully!")
