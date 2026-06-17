import os
import uuid
import hashlib
import hmac
from datetime import datetime, timezone

from flask import (Flask, render_template, redirect, url_for, flash,
                   request, abort, send_from_directory, session, jsonify)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from werkzeug.utils import secure_filename

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

from config import Config
from models import db, User, AccessRequest, Photo, ConsoleLog, Notification

app = Flask(__name__)
app.config.from_object(Config)
if os.environ.get('VERCEL'):
    app.instance_path = '/tmp/instance'

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


def notify(user_id, title, message, type='info', request_id=None):
    notif = Notification(
        user_id=user_id, title=title, message=message,
        type=type, request_id=request_id
    )
    db.session.add(notif)


def csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = hashlib.sha256(os.urandom(32)).hexdigest()
    return session['_csrf_token']


def validate_csrf():
    token = request.form.get('_csrf_token')
    if not token or token != session.get('_csrf_token'):
        abort(403)


def superadmin_required():
    if not current_user.is_admin:
        abort(403)
    if current_user.id != 1 and getattr(current_user, 'is_superadmin', False):
        return
    if current_user.id == 1:
        return


def superadmin_only():
    if current_user.id != 1:
        abort(403)


@app.context_processor
def inject_now():
    ctx = {'current_year': datetime.now(timezone.utc).year}
    if current_user.is_authenticated and getattr(app, '_db_initialized', False):
        try:
            ctx['unread_count'] = Notification.query.filter_by(
                user_id=current_user.id, is_read=False).count()
        except Exception:
            ctx['unread_count'] = 0
    ctx['csrf_token'] = csrf_token
    return ctx


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


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


@app.before_request
def init_db_once():
    if not getattr(app, '_db_initialized', False) and not request.path.startswith('/static/'):
        with app.app_context():
            db.create_all()
            seed_default_users()
        app._db_initialized = True


def seed_default_users():
    existing = {u.username for u in User.query.all()}
    for u in [
        ('superadmin', 'superadmin@system.local', 'Super Administrator', True, 'SuperAdmin123!'),
        ('admin', 'admin@system.local', 'System Administrator', True, 'Admin123!'),
        ('user', 'user@system.local', 'Regular User', False, 'User123!'),
    ]:
        if u[0] not in existing:
            user = User(username=u[0], email=u[1], full_name=u[2], is_admin=u[3])
            user.set_password(u[4])
            db.session.add(user)
    db.session.commit()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        validate_csrf()
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

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
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
        log_action(user.id, 'REGISTER', 'User registered successfully')
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        validate_csrf()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember')

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')

        if not user.is_active:
            flash('Account is deactivated.', 'danger')
            return render_template('login.html')

        login_user(user, remember=bool(remember))
        log_action(user.id, 'LOGIN', 'User logged in')
        db.session.commit()

        next_page = request.args.get('next')
        if user.is_admin:
            return redirect(next_page or url_for('admin_dashboard'))
        return redirect(next_page or url_for('dashboard'))

    return render_template('login.html')


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        validate_csrf()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        curr_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not all([full_name, email]):
            flash('Full name and email are required.', 'danger')
            return render_template('profile.html')

        existing = User.query.filter(User.email == email, User.id != current_user.id).first()
        if existing:
            flash('Email already in use.', 'danger')
            return render_template('profile.html')

        if new_password or curr_password:
            if not current_user.check_password(curr_password):
                flash('Current password is incorrect.', 'danger')
                return render_template('profile.html')
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return render_template('profile.html')
            if len(new_password) < 6:
                flash('Password must be at least 6 characters.', 'danger')
                return render_template('profile.html')
            current_user.set_password(new_password)

        current_user.full_name = full_name
        current_user.email = email
        log_action(current_user.id, 'PROFILE_UPDATED', 'Profile updated')
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html')


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


@app.route('/user/dashboard')
@login_required
def user_dashboard():
    requests = current_user.requests.order_by(
        AccessRequest.created_at.desc()).all()
    return render_template('dashboard.html', requests=requests)


@app.route('/request/new', methods=['GET', 'POST'])
@login_required
def new_request():
    if request.method == 'POST':
        validate_csrf()
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
        log_action(current_user.id, 'SUBMIT_REQUEST',
                   f'Submitted request: {title}',
                   request_id=req.id)
        for admin in User.query.filter_by(is_admin=True).all():
            notify(admin.id, 'New Access Request',
                   f'{current_user.full_name} submitted a new request: "{title}"',
                   'info', request_id=req.id)
        db.session.commit()
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
        validate_csrf()
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
        log_action(current_user.id, 'UPLOAD_PHOTOS',
                   f'Uploaded photos for request: {req.title}',
                   request_id=req.id)
        for admin in User.query.filter_by(is_admin=True).all():
            notify(admin.id, 'Photos Uploaded',
                   f'{current_user.full_name} uploaded photos for request: "{req.title}"',
                   'info', request_id=req.id)
        db.session.commit()
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
    validate_csrf()

    req = db.session.get(AccessRequest, req_id)
    if not req:
        abort(404)

    if req.status not in ('pending',):
        flash('Request is no longer pending.', 'warning')
        return redirect(url_for('admin_dashboard'))

    action = request.form.get('action')
    notes = request.form.get('notes', '').strip()

    if action == 'approve':
        req.status = 'approved'
        req.reviewed_by = current_user.id
        req.review_notes = notes
        log_action(current_user.id, 'APPROVE_REQUEST',
                   f'Approved request: {req.title}',
                   request_id=req.id)
        log_action(req.user_id, 'REQUEST_APPROVED',
                   f'Your request has been approved: {req.title}',
                   request_id=req.id)
        notify(req.user_id, 'Request Approved',
               f'Your request "{req.title}" has been approved by {current_user.full_name}.',
               'success', request_id=req.id)
        db.session.commit()
        flash(f'Request #{req.id} approved.', 'success')

    elif action == 'reject':
        req.status = 'rejected'
        req.reviewed_by = current_user.id
        req.review_notes = notes
        log_action(current_user.id, 'REJECT_REQUEST',
                   f'Rejected request: {req.title}. Reason: {notes}',
                   request_id=req.id)
        log_action(req.user_id, 'REQUEST_REJECTED',
                   f'Your request has been rejected: {req.title}. Reason: {notes}',
                   request_id=req.id)
        notify(req.user_id, 'Request Rejected',
               f'Your request "{req.title}" was rejected. Reason: {notes}',
               'danger', request_id=req.id)
        db.session.commit()
        flash(f'Request #{req.id} rejected.', 'warning')

    else:
        flash('Invalid action.', 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    page = request.args.get('page', 1, type=int)
    users_paged = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=50, error_out=False)
    return render_template('admin_users.html', users=users_paged)


@app.route('/admin/user/<int:user_id>/edit', methods=['POST'])
@login_required
def admin_edit_user(user_id):
    if not current_user.is_admin:
        abort(403)
    validate_csrf()
    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    if user_id == 1 and current_user.id != 1:
        flash('You cannot edit the superadmin.', 'danger')
        return redirect(url_for('admin_users'))

    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    full_name = request.form.get('full_name', '').strip()
    is_admin = request.form.get('is_admin') == 'on'

    if not all([username, email, full_name]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('admin_users'))

    existing = User.query.filter(User.username == username, User.id != user.id).first()
    if existing:
        flash('Username already taken.', 'danger')
        return redirect(url_for('admin_users'))

    existing = User.query.filter(User.email == email, User.id != user.id).first()
    if existing:
        flash('Email already taken.', 'danger')
        return redirect(url_for('admin_users'))

    user.username = username
    user.email = email
    user.full_name = full_name
    user.is_admin = is_admin
    password = request.form.get('password', '')
    if password:
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return redirect(url_for('admin_users'))
        user.set_password(password)

    log_action(current_user.id, 'USER_UPDATED', f'Updated user: {user.username}')
    db.session.commit()
    flash(f'User {user.username} updated.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    validate_csrf()
    if user_id == 1:
        flash('You cannot delete the superadmin.', 'danger')
        return redirect(url_for('admin_users'))
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))

    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    AccessRequest.query.filter_by(reviewed_by=user_id).update(
        {AccessRequest.reviewed_by: None})
    Notification.query.filter_by(user_id=user_id).delete()
    username = user.username
    db.session.delete(user)
    log_action(current_user.id, 'USER_DELETED', f'Deleted user: {username}')
    db.session.commit()
    flash(f'User {username} and all their data deleted.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/request/<int:req_id>/delete', methods=['POST'])
@login_required
def admin_delete_request(req_id):
    if not current_user.is_admin:
        abort(403)
    validate_csrf()
    req = db.session.get(AccessRequest, req_id)
    if not req:
        abort(404)

    title = req.title
    ConsoleLog.query.filter_by(request_id=req.id).update(
        {ConsoleLog.request_id: None})
    Notification.query.filter_by(request_id=req.id).update(
        {Notification.request_id: None})
    db.session.delete(req)
    log_action(current_user.id, 'REQUEST_DELETED', f'Deleted request: {title}')
    db.session.commit()
    flash(f'Request #{req_id} deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/log/<int:log_id>/delete', methods=['POST'])
@login_required
def admin_delete_log(log_id):
    if not current_user.is_admin:
        abort(403)
    validate_csrf()
    log = db.session.get(ConsoleLog, log_id)
    if not log:
        abort(404)
    db.session.delete(log)
    db.session.commit()
    flash('Log entry deleted.', 'success')
    return redirect(url_for('console_logs'))


@app.route('/admin/logs/clear', methods=['POST'])
@login_required
def admin_clear_logs():
    if not current_user.is_admin:
        abort(403)
    validate_csrf()
    count = ConsoleLog.query.count()
    ConsoleLog.query.delete()
    log_action(current_user.id, 'LOGS_CLEARED', f'Cleared {count} log entries')
    db.session.commit()
    flash(f'{count} log entries cleared.', 'success')
    return redirect(url_for('console_logs'))


@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def toggle_user(user_id):
    if not current_user.is_admin:
        abort(403)
    validate_csrf()
    if user_id == 1:
        flash('You cannot deactivate the superadmin.', 'danger')
        return redirect(url_for('admin_users'))
    if user_id == current_user.id:
        flash('You cannot deactivate yourself.', 'danger')
        return redirect(url_for('admin_users'))

    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    user.is_active = not user.is_active
    status = 'activated' if user.is_active else 'deactivated'
    log_action(current_user.id, f'USER_{status.upper()}',
               f'{status} user: {user.username}')
    db.session.commit()
    flash(f'User {user.username} {status}.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip()

    query = AccessRequest.query
    if not current_user.is_admin:
        query = query.filter_by(user_id=current_user.id)

    if search:
        like = f'%{search}%'
        query = query.filter(
            db.or_(
                AccessRequest.title.ilike(like),
                AccessRequest.server_name.ilike(like),
                AccessRequest.description.ilike(like)
            )
        )
    if status_filter:
        query = query.filter_by(status=status_filter)

    query = query.order_by(AccessRequest.created_at.desc())
    requests_paged = query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('history.html', requests=requests_paged, search=search, status_filter=status_filter)


@app.route('/logs')
@login_required
def console_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    search = request.args.get('search', '').strip()

    query = ConsoleLog.query
    if not current_user.is_admin:
        query = query.filter_by(user_id=current_user.id)

    if search:
        like = f'%{search}%'
        query = query.filter(
            db.or_(
                ConsoleLog.action.ilike(like),
                ConsoleLog.details.ilike(like),
                ConsoleLog.ip_address.ilike(like)
            )
        )

    query = query.order_by(ConsoleLog.created_at.desc())
    logs = query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('logs.html', logs=logs, search=search)


@app.route('/dashboard/data')
@login_required
def dashboard_data():
    from sqlalchemy import func

    if current_user.is_admin:
        base_reqs = AccessRequest.query
    else:
        base_reqs = AccessRequest.query.filter_by(user_id=current_user.id)

    total = base_reqs.count()
    pending = base_reqs.filter_by(status='pending').count()
    approved = base_reqs.filter_by(status='approved').count()
    completed = base_reqs.filter_by(status='completed').count()
    rejected = base_reqs.filter_by(status='rejected').count()

    six_months_ago = datetime.now(timezone.utc).replace(day=1)
    m = six_months_ago.month - 5
    y = six_months_ago.year
    if m < 1:
        m += 12
        y -= 1
    six_months_ago = six_months_ago.replace(year=y, month=m)

    # PostgreSQL-compatible month truncation
    is_pg = app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql')
    if is_pg:
        month_col = func.to_char(AccessRequest.created_at, 'YYYY-MM').label('month')
    else:
        month_col = func.strftime('%Y-%m', AccessRequest.created_at).label('month')

    monthly_query = db.session.query(
        month_col,
        func.count(AccessRequest.id).label('count')
    ).filter(AccessRequest.created_at >= six_months_ago)
    if not current_user.is_admin:
        monthly_query = monthly_query.filter(AccessRequest.user_id == current_user.id)
    monthly = monthly_query.group_by('month').order_by('month').all()

    months_map = {row.month: row.count for row in monthly}
    months_arr = []
    counts_arr = []
    for i in range(6):
        target_month = six_months_ago.month + i
        y_offset = (target_month - 1) // 12
        m_final = ((target_month - 1) % 12) + 1
        d = six_months_ago.replace(year=six_months_ago.year + y_offset, month=m_final)
        label = d.strftime('%Y-%m')
        months_arr.append(label)
        counts_arr.append(months_map.get(label, 0))

    servers = db.session.query(
        AccessRequest.server_name,
        func.count(AccessRequest.id).label('count')
    )
    if not current_user.is_admin:
        servers = servers.filter(AccessRequest.user_id == current_user.id)
    servers = servers.group_by(AccessRequest.server_name).order_by(
        func.count(AccessRequest.id).desc()).limit(8).all()

    server_labels = [s.server_name for s in servers]
    server_counts = [s.count for s in servers]

    recent = base_reqs.order_by(AccessRequest.created_at.desc()).limit(10).all()
    recent_data = [{
        'id': r.id,
        'title': r.title[:30],
        'server': r.server_name,
        'status': r.status,
        'badge': r.status_badge,
        'created': r.created_at.strftime('%Y-%m-%d %H:%M'),
        'user': r.user.full_name if current_user.is_admin else None
    } for r in recent]

    return {
        'stats': {
            'total': total, 'pending': pending,
            'approved': approved, 'completed': completed,
            'rejected': rejected
        },
        'monthly': {'labels': months_arr, 'counts': counts_arr},
        'servers': {'labels': server_labels, 'counts': server_counts},
        'recent': recent_data
    }


@app.route('/notifications/data')
@login_required
def notifications_data():
    limit = request.args.get('limit', 5, type=int)
    notifs = Notification.query.filter_by(user_id=current_user.id).order_by(
        Notification.created_at.desc()).limit(limit).all()
    return [{
        'id': n.id,
        'title': n.title,
        'message': n.message[:100],
        'type': n.type,
        'is_read': n.is_read,
        'request_id': n.request_id,
        'time': n.created_at.strftime('%Y-%m-%d %H:%M')
    } for n in notifs]


@app.route('/notifications')
@login_required
def notifications_page():
    page = request.args.get('page', 1, type=int)
    notifs = Notification.query.filter_by(user_id=current_user.id).order_by(
        Notification.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    return render_template('notifications.html', notifs=notifs)


@app.route('/notifications/read/<int:notif_id>', methods=['POST'])
@login_required
def mark_notification_read(notif_id):
    notif = db.session.get(Notification, notif_id)
    if not notif or notif.user_id != current_user.id:
        abort(404)
    validate_csrf()
    notif.is_read = True
    db.session.commit()
    return '', 204


@app.route('/notifications/read-all', methods=['POST'])
@login_required
def mark_all_read():
    validate_csrf()
    Notification.query.filter_by(
        user_id=current_user.id, is_read=False).update(
        {Notification.is_read: True})
    db.session.commit()
    flash('All notifications marked as read.', 'success')
    return redirect(request.referrer or url_for('notifications_page'))


@app.route('/static/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_default_users()
    app.run(debug=True)
