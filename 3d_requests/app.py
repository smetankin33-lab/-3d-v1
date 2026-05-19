from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
import os
import uuid
import re

app = Flask(__name__)

# ─── КОНФИГУРАЦИЯ ───────────────────────────────────────────────────────────
app.config['SECRET_KEY'] = os.urandom(32).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///requests.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB

ALLOWED_PHOTOS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_MODELS = {'stl', 'obj', 'fbx', '3mf', 'step', 'stp', 'iges', 'igs'}

db = SQLAlchemy(app)

# Создаём папки для загрузок если их нет
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'photos'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'models'), exist_ok=True)


# ─── МОДЕЛИ БАЗЫ ДАННЫХ ─────────────────────────────────────────────────────
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class PrintRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_number = db.Column(db.String(20), unique=True, nullable=False)
    # Личные данные (зашифрованы в отображении)
    last_name = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    # Параметры детали
    length = db.Column(db.Float, nullable=True)
    width = db.Column(db.Float, nullable=True)
    height = db.Column(db.Float, nullable=True)
    material = db.Column(db.String(100), nullable=True)
    color = db.Column(db.String(50), nullable=True)
    quantity = db.Column(db.Integer, default=1)
    description = db.Column(db.Text, nullable=True)
    # Метаданные
    status = db.Column(db.String(30), default='Новая')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Файлы
    files = db.relationship('UploadedFile', backref='request', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Request {self.ticket_number}>'


class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('print_request.id'), nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    original_name = db.Column(db.String(300), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)  # 'photo' or 'model'
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


# ─── ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ────────────────────────────────────────────────
def allowed_photo(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_PHOTOS

def allowed_model(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_MODELS

def generate_ticket():
    now = datetime.now()
    return f"3D-{now.strftime('%Y%m')}-{str(uuid.uuid4())[:6].upper()}"

def mask_phone(phone):
    """Маскируем телефон для защиты ПДн"""
    if len(phone) >= 4:
        return phone[:3] + '*' * (len(phone) - 5) + phone[-2:]
    return '***'

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

STATUS_COLORS = {
    'Новая': '#6C63FF',
    'В работе': '#F59E0B',
    'Готово': '#10B981',
    'Отменена': '#EF4444',
}

# ─── МАРШРУТЫ — ПУБЛИЧНАЯ ЧАСТЬ ─────────────────────────────────────────────
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/submit', methods=['POST'])
def submit():
    # Валидация
    last_name = request.form.get('last_name', '').strip()
    first_name = request.form.get('first_name', '').strip()
    phone = request.form.get('phone', '').strip()

    if not all([last_name, first_name, phone]):
        flash('Пожалуйста, заполните все обязательные поля.', 'error')
        return redirect(url_for('index'))

    # Очищаем телефон от лишних символов
    phone_clean = re.sub(r'[^\d+\-\(\) ]', '', phone)

    ticket = generate_ticket()

    new_req = PrintRequest(
        ticket_number=ticket,
        last_name=last_name,
        first_name=first_name,
        phone=phone_clean,
        length=request.form.get('length') or None,
        width=request.form.get('width') or None,
        height=request.form.get('height') or None,
        material=request.form.get('material', '').strip() or None,
        color=request.form.get('color', '').strip() or None,
        quantity=int(request.form.get('quantity') or 1),
        description=request.form.get('description', '').strip() or None,
    )
    db.session.add(new_req)
    db.session.flush()  # получаем ID до коммита

    # Сохраняем фотографии
    photos = request.files.getlist('photos')
    for photo in photos:
        if photo and photo.filename and allowed_photo(photo.filename):
            ext = photo.filename.rsplit('.', 1)[1].lower()
            safe_name = f"{uuid.uuid4().hex}.{ext}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], 'photos', safe_name)
            photo.save(save_path)
            db.session.add(UploadedFile(
                request_id=new_req.id,
                filename=safe_name,
                original_name=secure_filename(photo.filename),
                file_type='photo'
            ))

    # Сохраняем 3D модели
    models = request.files.getlist('models')
    for model in models:
        if model and model.filename and allowed_model(model.filename):
            ext = model.filename.rsplit('.', 1)[1].lower()
            safe_name = f"{uuid.uuid4().hex}.{ext}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], 'models', safe_name)
            model.save(save_path)
            db.session.add(UploadedFile(
                request_id=new_req.id,
                filename=safe_name,
                original_name=secure_filename(model.filename),
                file_type='model'
            ))

    db.session.commit()
    return redirect(url_for('success', ticket=ticket))


@app.route('/success/<ticket>')
def success(ticket):
    req = PrintRequest.query.filter_by(ticket_number=ticket).first_or_404()
    return render_template('success.html', req=req)


@app.route('/track', methods=['GET', 'POST'])
def track():
    req = None
    if request.method == 'POST':
        ticket = request.form.get('ticket', '').strip()
        req = PrintRequest.query.filter_by(ticket_number=ticket).first()
        if not req:
            flash('Заявка не найдена. Проверьте номер.', 'error')
    return render_template('track.html', req=req, mask_phone=mask_phone)


# ─── МАРШРУТЫ — ПАНЕЛЬ АДМИНИСТРАТОРА ───────────────────────────────────────
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_logged_in'] = True
            session['admin_name'] = admin.username
            return redirect(url_for('admin_dashboard'))
        flash('Неверный логин или пароль', 'error')
    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))


@app.route('/admin')
@login_required
def admin_dashboard():
    status_filter = request.args.get('status', '')
    query = PrintRequest.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    requests = query.order_by(PrintRequest.created_at.desc()).all()

    stats = {
        'total': PrintRequest.query.count(),
        'new': PrintRequest.query.filter_by(status='Новая').count(),
        'in_progress': PrintRequest.query.filter_by(status='В работе').count(),
        'done': PrintRequest.query.filter_by(status='Готово').count(),
    }
    return render_template('admin_dashboard.html', requests=requests, stats=stats,
                           status_filter=status_filter, status_colors=STATUS_COLORS)


@app.route('/admin/request/<int:req_id>')
@login_required
def admin_view_request(req_id):
    req = PrintRequest.query.get_or_404(req_id)
    photos = [f for f in req.files if f.file_type == 'photo']
    models = [f for f in req.files if f.file_type == 'model']
    return render_template('admin_view_request.html', req=req, photos=photos,
                           models=models, status_colors=STATUS_COLORS)


@app.route('/admin/request/<int:req_id>/status', methods=['POST'])
@login_required
def update_status(req_id):
    req = PrintRequest.query.get_or_404(req_id)
    new_status = request.form.get('status')
    if new_status in STATUS_COLORS:
        req.status = new_status
        req.updated_at = datetime.utcnow()
        db.session.commit()
        flash(f'Статус обновлён: {new_status}', 'success')
    return redirect(url_for('admin_view_request', req_id=req_id))


@app.route('/admin/request/<int:req_id>/delete', methods=['POST'])
@login_required
def delete_request(req_id):
    req = PrintRequest.query.get_or_404(req_id)
    # Удаляем файлы с диска
    for f in req.files:
        folder = 'photos' if f.file_type == 'photo' else 'models'
        path = os.path.join(app.config['UPLOAD_FOLDER'], folder, f.filename)
        if os.path.exists(path):
            os.remove(path)
    db.session.delete(req)
    db.session.commit()
    flash('Заявка удалена.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/print/<int:req_id>')
@login_required
def print_request(req_id):
    req = PrintRequest.query.get_or_404(req_id)
    photos = [f for f in req.files if f.file_type == 'photo']
    return render_template('print_view.html', req=req, photos=photos)


@app.route('/uploads/<path:filepath>')
@login_required
def serve_upload(filepath):
    """Защищённая отдача файлов — только для авторизованных"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filepath)


# ─── ИНИЦИАЛИЗАЦИЯ ──────────────────────────────────────────────────────────
def init_db():
    with app.app_context():
        db.create_all()
        # Создаём администратора по умолчанию если нет
        if not Admin.query.first():
            admin = Admin(username='admin')
            admin.set_password('Admin123!')
            db.session.add(admin)
            db.session.commit()
            print("=" * 50)
            print("  Администратор создан:")
            print("  Логин:   admin")
            print("  Пароль:  Admin123!")
            print("  СМЕНИТЕ ПАРОЛЬ ПОСЛЕ ПЕРВОГО ВХОДА!")
            print("=" * 50)


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
