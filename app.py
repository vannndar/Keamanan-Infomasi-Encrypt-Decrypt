from flask import Flask, abort, render_template, redirect, url_for, request, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, UploadedFile
from encryption import encrypt_file, decrypt_file
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from io import BytesIO
from models import UploadedFile
import time
import os

app = Flask(__name__)
migrate = Migrate(app, db)

# Konfigurasi PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://flaskuser:123@localhost:1500/flaskapp_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@login_required
def index():
    # Ambil semua file yang diunggah oleh user yang sedang login
    user_files = UploadedFile.query.filter_by(user_id=current_user.id).all()

    return render_template('index.html', files=user_files)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Cari user berdasarkan username
        user = User.query.filter_by(username=username).first()

        # Cek apakah user ada dan passwordnya benar
        if user and user.check_password(password):
            login_user(user)  # Login pengguna
            # Arahkan ke halaman utama setelah login
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Mengambil data dari form
        username = request.form['username']
        password = request.form['password']

        # Cek apakah username sudah digunakan
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Membuat user baru
        new_user = User(username=username)
        # Hashing password menggunakan set_password()
        new_user.set_password(password)

        try:
            # Simpan user ke database
            db.session.add(new_user)
            db.session.commit()

            flash('Account created successfully! Please log in.', 'success')
            # Arahkan ke halaman login setelah berhasil
            return redirect(url_for('login'))
        except:
            db.session.rollback()  # Jika terjadi error, rollback transaksi
            flash(
                'An error occurred while creating the account. Please try again.', 'danger')
            return redirect(url_for('register'))

    # Jika metode GET, tampilkan halaman registrasi
    return render_template('register.html')


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))

    file = request.files['file']

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))

    if file:
        filename = secure_filename(file.filename)
        file_data = file.read()  # Baca data file sebagai biner
        file_size = len(file_data)  # Menghitung ukuran file dalam bytes

        method = request.form['encryption_method']

        start_time = time.time()
        encrypted_data, key, iv = encrypt_file(
            file_data, method)
        encryption_time = time.time() - start_time

        start_time = time.time()
        decrypted_data = decrypt_file(
            encrypted_data, method, key, iv)
        decryption_time = time.time() - start_time

        uploaded_file = UploadedFile(
            user_id=current_user.id,
            filename=filename,
            file_data=encrypted_data,
            file_size=file_size,
            encryption_method=request.form['encryption_method'],
            encryption_key=key,
            iv=iv,
            encryption_time=encryption_time,
            decryption_time=decryption_time
        )

        db.session.add(uploaded_file)
        db.session.commit()

        flash(
            f'File encrypted with {method} and uploaded successfully!', 'success')
        return redirect(url_for('index'))


@app.route('/download/<int:file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    # Ambil file dari database berdasarkan file_id
    file_record = UploadedFile.query.get_or_404(file_id)

    # Baca data biner terenkripsi dari kolom file_data
    encrypted_data = file_record.file_data
    filename = file_record.filename
    encryption_method = file_record.encryption_method

    # Dekripsi file sebelum mengirim ke pengguna
    decrypted_data = decrypt_file(
        encrypted_data, algorithm=encryption_method, key=file_record.encryption_key, iv=file_record.iv)

    # Kirim file ke pengguna sebagai attachment untuk diunduh
    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename,
        mimetype='application/octet-stream'
    )


@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_to_delete = UploadedFile.query.get_or_404(file_id)
    if file_to_delete.user_id != current_user.id:
        abort(403)  # Hanya pemilik file yang bisa menghapus file

    db.session.delete(file_to_delete)
    db.session.commit()
    flash('File deleted successfully!', 'info')
    return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
