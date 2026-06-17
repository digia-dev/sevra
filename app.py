import os
import uuid
from datetime import datetime, timezone

from flask import (Flask, render_template, redirect, url_for, flash,
                   request, abort, send_from_directory)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from werkzeug.utils import secure_filename

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

from config import Config
from models import db, User, AccessRequest, Photo, ConsoleLog

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def save_photo(file):
    ext = file.filename.rsplit('.', 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
    file.save(filepath)

    if HAS_PIL:
        try:
            img = Image.open(filepath)
            img.thumbnail((1200, 1200))
            img.save(filepath)
        except Exception:
            pass

    return unique_name


def log_action(user_id, action, details=None, request_id=None, ip=None):
    log = ConsoleLog(
        user_id=user_id,
        request_id=request_id,
        action=action,
        details=details,
        ip_address=ip or request.remote_addr
    )
    db.session.add(log)
    db.session.commit()


@app.context_processor
def inject_now():
    return {'current_year': datetime.now(timezone.utc).year}


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.cli.command('init-db')
def init_db():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@system.local',
            full_name='System Administrator',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print('Admin user created (admin / admin123)')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not all([username, email, full_name, password]):
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')

        user = User(username=username, email=email, full_name=full_name)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        log_action(user.id, 'REGISTER', 'User registered successfully')
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember')

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

        if not user.is_active:
            flash('Account is deactivated.', 'danger')
            return render_template('login.html')

        login_user(user, remember=bool(remember))
        log_action(user.id, 'LOGIN', 'User logged in')

        next_page = request.args.get('next')
        if user.is_admin:
            return redirect(next_page or url_for('admin_dashboard'))
        return redirect(next_page or url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_action(current_user.id, 'LOGOUT', 'User logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    requests = current_user.requests.order_by(
        AccessRequest.created_at.desc()).all()
    return render_template('dashboard.html', requests=requests)


@app.route('/request/new', methods=['GET', 'POST'])
@login_required
def new_request():
    if current_user.is_admin:
        abort(403)

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        server_name = request.form.get('server_name', '').strip()
        access_duration = request.form.get('access_duration', '').strip()

        if not all([title, description, server_name, access_duration]):
            flash('All fields are required.', 'danger')
            return render_template('request_form.html')

        req = AccessRequest(
            user_id=current_user.id,
            title=title,
            description=description,
            server_name=server_name,
            access_duration=access_duration
        )
        db.session.add(req)
        db.session.commit()

        log_action(current_user.id, 'SUBMIT_REQUEST',
                   f'Submitted request: {title}',
                   request_id=req.id)
        flash('Access request submitted successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('request_form.html')


@app.route('/request/<int:req_id>')
@login_required
def view_request(req_id):
    req = db.session.get(AccessRequest, req_id)
    if not req:
        abort(404)
    if not current_user.is_admin and req.user_id != current_user.id:
        abort(403)
    return render_template('view_request.html', req=req)


@app.route('/request/<int:req_id>/photos', methods=['GET', 'POST'])
@login_required
def upload_photos(req_id):
    req = db.session.get(AccessRequest, req_id)
    if not req:
        abort(404)
    if req.user_id != current_user.id:
        abort(403)
    if req.status != 'approved':
        flash('Photos can only be uploaded for approved requests.', 'warning')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        before_file = request.files.get('before_photo')
        after_file = request.files.get('after_photo')
        before_desc = request.form.get('before_description', '').strip()
        after_desc = request.form.get('after_description', '').strip()

        if not before_file or not after_file:
            flash('Both before and after photos are required.', 'danger')
            return render_template('upload_photos.html', req=req)

        if not (allowed_file(before_file.filename) and
                allowed_file(after_file.filename)):
            flash('Only PNG, JPG, JPEG, GIF files are allowed.', 'danger')
            return render_template('upload_photos.html', req=req)

        before_name = save_photo(before_file)
        after_name = save_photo(after_file)

        photo_before = Photo(
            request_id=req.id, photo_type='before',
            filename=before_name, description=before_desc
        )
        photo_after = Photo(
            request_id=req.id, photo_type='after',
            filename=after_name, description=after_desc
        )
        db.session.add_all([photo_before, photo_after])
        req.status = 'completed'
        db.session.commit()

        log_action(current_user.id, 'UPLOAD_PHOTOS',
                   f'Uploaded photos for request: {req.title}',
                   request_id=req.id)
        flash('Photos uploaded successfully. Request completed.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('upload_photos.html', req=req)


@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)

    pending = AccessRequest.query.filter_by(status='pending').order_by(
        AccessRequest.created_at.desc()).all()
    approved = AccessRequest.query.filter_by(status='approved').order_by(
        AccessRequest.created_at.desc()).all()
    completed = AccessRequest.query.filter_by(status='completed').order_by(
        AccessRequest.created_at.desc()).all()
    rejected = AccessRequest.query.filter_by(status='rejected').order_by(
        AccessRequest.created_at.desc()).all()

    return render_template('admin_dashboard.html',
                           pending=pending, approved=approved,
                           completed=completed, rejected=rejected)


@app.route('/admin/request/<int:req_id>/review', methods=['POST'])
@login_required
def review_request(req_id):
    if not current_user.is_admin:
        abort(403)

    req = db.session.get(AccessRequest, req_id)
    if not req:
        abort(404)

    action = request.form.get('action')
    notes = request.form.get('notes', '').strip()

    if action == 'approve':
        req.status = 'approved'
        req.reviewed_by = current_user.id
        req.review_notes = notes
        db.session.commit()
        log_action(current_user.id, 'APPROVE_REQUEST',
                   f'Approved request: {req.title}',
                   request_id=req.id)
        log_action(req.user_id, 'REQUEST_APPROVED',
                   f'Your request has been approved: {req.title}',
                   request_id=req.id)
        flash(f'Request #{req.id} approved.', 'success')

    elif action == 'reject':
        req.status = 'rejected'
        req.reviewed_by = current_user.id
        req.review_notes = notes
        db.session.commit()
        log_action(current_user.id, 'REJECT_REQUEST',
                   f'Rejected request: {req.title}. Reason: {notes}',
                   request_id=req.id)
        log_action(req.user_id, 'REQUEST_REJECTED',
                   f'Your request has been rejected: {req.title}. Reason: {notes}',
                   request_id=req.id)
        flash(f'Request #{req.id} rejected.', 'warning')

    else:
        flash('Invalid action.', 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def toggle_user(user_id):
    if not current_user.is_admin:
        abort(403)
    if user_id == current_user.id:
        flash('You cannot deactivate yourself.', 'danger')
        return redirect(url_for('admin_users'))

    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    user.is_active = not user.is_active
    db.session.commit()
    status = 'activated' if user.is_active else 'deactivated'
    log_action(current_user.id, f'USER_{status.upper()}',
               f'{status} user: {user.username}')
    flash(f'User {user.username} {status}.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/history')
@login_required
def history():
    if current_user.is_admin:
        requests_all = AccessRequest.query.order_by(
            AccessRequest.created_at.desc()).all()
    else:
        requests_all = current_user.requests.order_by(
            AccessRequest.created_at.desc()).all()
    return render_template('history.html', requests=requests_all)


@app.route('/logs')
@login_required
def console_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50

    if current_user.is_admin:
        query = ConsoleLog.query.order_by(ConsoleLog.created_at.desc())
    else:
        query = ConsoleLog.query.filter_by(user_id=current_user.id).order_by(
            ConsoleLog.created_at.desc())

    logs = query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('logs.html', logs=logs)


@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
