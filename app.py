"""
WebSecure360 - Web Security Assessment Platform
Author: Md Mahmudul Hasan
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import os, json, io, threading, uuid
import stripe

# ── App Config ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY']              = os.environ.get('SECRET_KEY', 'ws360-dev-secret-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///websecure360.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Stripe — set your keys in environment variables
stripe.api_key                   = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_your_key_here')
STRIPE_PUBLISHABLE_KEY           = os.environ.get('STRIPE_PUBLISHABLE_KEY', 'pk_test_your_key_here')
STRIPE_WEBHOOK_SECRET            = os.environ.get('STRIPE_WEBHOOK_SECRET', '')

# Plan config
PLANS = {
    'free': {
        'name':           'Free',
        'price':          0,
        'scans':          5,       # scans per month
        'projects':       2,
        'pdf_report':     False,
        'api_access':     False,
        'priority_support': False,
        'modules':        ['whois', 'ssl', 'headers', 'dns'],
        'stripe_price_id': None,
    },
    'pro': {
        'name':           'Pro',
        'price':          15,      # USD/month
        'scans':          100,
        'projects':       20,
        'pdf_report':     True,
        'api_access':     True,
        'priority_support': False,
        'modules':        ['whois', 'ssl', 'headers', 'dns', 'subdomains',
                           'ports', 'fuzzer', 'xss', 'sqli', 'tech',
                           'admin_finder', 'swagger', 'sql_backup', 'yaml_config',
                           'json_secrets', 'tomcat', 'wp_vulns', 'jk_nginx',
                           'env_exposure', 'git_exposure', 'sensitive_config',
                           'js_secrets', 'xml_config', 'graphql', 'dir_listing',
                           'log_exposure', 'ftp_config', 'ssh_keys', 'backup_files',
                           'php_backup', 'php_info', 'file_manager', 'laravel_vulns',
                           'django_debug', 'spring_boot', 'ruby_config', 'jenkins',
                           'iis_telerik', 'wp_setup'],
        'stripe_price_id': os.environ.get('STRIPE_PRO_PRICE_ID', 'price_your_id_here'),
    },
    'enterprise': {
        'name':           'Enterprise',
        'price':          49,      # USD/month
        'scans':          1000,
        'projects':       100,
        'pdf_report':     True,
        'api_access':     True,
        'priority_support': True,
        'modules':        ['whois', 'ssl', 'headers', 'dns', 'subdomains',
                           'ports', 'fuzzer', 'xss', 'sqli', 'tech',
                           'admin_finder', 'swagger', 'sql_backup', 'yaml_config',
                           'json_secrets', 'tomcat', 'wp_vulns', 'jk_nginx',
                           'env_exposure', 'git_exposure', 'sensitive_config',
                           'js_secrets', 'xml_config', 'graphql', 'dir_listing',
                           'log_exposure', 'ftp_config', 'ssh_keys', 'backup_files',
                           'php_backup', 'php_info', 'file_manager', 'laravel_vulns',
                           'django_debug', 'spring_boot', 'ruby_config', 'jenkins',
                           'iis_telerik', 'wp_setup'],
        'stripe_price_id': os.environ.get('STRIPE_ENTERPRISE_PRICE_ID', 'price_your_enterprise_id_here'),
    },
}

db           = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ── Scan progress store (in-memory) ──────────────────────────────────────────
scan_progress = {}   # { scan_id: { 'progress': 0-100, 'status': '...' } }

# ── Models ────────────────────────────────────────────────────────────────────
class User(db.Model):
    id             = db.Column(db.Integer, primary_key=True)
    name           = db.Column(db.String(100), nullable=False)
    email          = db.Column(db.String(120), unique=True, nullable=False)
    password_hash  = db.Column(db.String(256), nullable=False)
    plan           = db.Column(db.String(20), default='free')
    scans_used     = db.Column(db.Integer, default=0)
    scan_reset_date = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=30))
    stripe_customer_id    = db.Column(db.String(100))
    stripe_subscription_id = db.Column(db.String(100))
    api_key        = db.Column(db.String(64), unique=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    projects       = db.relationship('Project', backref='owner', lazy=True, cascade='all,delete')

    def set_password(self, pw):   self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)
    def generate_api_key(self):
        import secrets
        self.api_key = 'ws360_' + secrets.token_hex(28)

    @property
    def is_authenticated(self): return True
    @property
    def is_active(self): return True
    @property
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)

    def plan_config(self):   return PLANS.get(self.plan, PLANS['free'])
    def scans_left(self):    return max(0, self.plan_config()['scans'] - self.scans_used)
    def can_scan(self):      return self.scans_left() > 0
    def can_add_project(self): return len(self.projects) < self.plan_config()['projects']
    def has_api_access(self):  return self.plan_config().get('api_access', False)

    def reset_scans_if_needed(self):
        if datetime.utcnow() >= self.scan_reset_date:
            self.scans_used = 0
            self.scan_reset_date = datetime.utcnow() + timedelta(days=30)
            db.session.commit()


class Project(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300), default='')
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    scans       = db.relationship('Scan', backref='project', lazy=True, cascade='all,delete',
                                  order_by='Scan.created_at.desc()')


class Scan(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    scan_id     = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    project_id  = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    target      = db.Column(db.String(300), nullable=False)
    status      = db.Column(db.String(20), default='pending')   # pending/running/done/failed
    results_json = db.Column(db.Text, default='{}')
    modules     = db.Column(db.String(500), default='')
    risk_score  = db.Column(db.Integer, default=0)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    def results(self):
        try:   return json.loads(self.results_json)
        except: return {}

    def modules_list(self):
        return [m.strip() for m in self.modules.split(',') if m.strip()]


@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))


# ── Decorators ────────────────────────────────────────────────────────────────
def pro_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.plan != 'pro':
            flash('This feature requires a Pro plan.', 'warning')
            return redirect(url_for('pricing'))
        return f(*args, **kwargs)
    return decorated


# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name     = request.form.get('name', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm', '')

        if not all([name, email, password]):
            flash('All fields are required.', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        elif User.query.filter_by(email=email).first():
            flash('An account with this email already exists.', 'error')
        else:
            user = User(name=name, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash(f'Welcome, {name}!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'
        user     = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            user.reset_scans_if_needed()
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid email or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# ── Public Routes ─────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html', plans=PLANS)


@app.route('/pricing')
def pricing():
    return render_template('pricing.html', plans=PLANS,
                           stripe_pub=STRIPE_PUBLISHABLE_KEY)


# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    current_user.reset_scans_if_needed()
    recent_scans = Scan.query.join(Project).filter(
        Project.user_id == current_user.id
    ).order_by(Scan.created_at.desc()).limit(5).all()
    return render_template('dashboard.html', plans=PLANS, recent_scans=recent_scans)


# ── Projects ──────────────────────────────────────────────────────────────────
@app.route('/projects')
@login_required
def projects():
    return render_template('projects.html', plans=PLANS)


@app.route('/projects/new', methods=['POST'])
@login_required
def new_project():
    if not current_user.can_add_project():
        flash(f'You have reached the project limit for your plan ({current_user.plan_config()["projects"]} projects). Upgrade to Pro.', 'warning')
        return redirect(url_for('projects'))

    name = request.form.get('name', '').strip()
    desc = request.form.get('description', '').strip()
    if not name:
        flash('Project name is required.', 'error')
        return redirect(url_for('projects'))

    project = Project(name=name, description=desc, user_id=current_user.id)
    db.session.add(project)
    db.session.commit()
    flash(f'Project "{name}" created.', 'success')
    return redirect(url_for('project_detail', project_id=project.id))


@app.route('/projects/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    return render_template('project_detail.html', project=project, plans=PLANS)


@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    name = project.name
    db.session.delete(project)
    db.session.commit()
    flash(f'Project "{name}" deleted.', 'success')
    return redirect(url_for('projects'))


# ── Scanning ──────────────────────────────────────────────────────────────────
@app.route('/projects/<int:project_id>/scan', methods=['GET', 'POST'])
@login_required
def new_scan(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    current_user.reset_scans_if_needed()

    if request.method == 'POST':
        if not current_user.can_scan():
            flash(f'You have used all {current_user.plan_config()["scans"]} scans this month. Upgrade to Pro for more.', 'warning')
            return redirect(url_for('pricing'))

        target  = request.form.get('target', '').strip()
        modules = request.form.getlist('modules')

        if not target:
            flash('Target URL is required.', 'error')
            return redirect(url_for('new_scan', project_id=project_id))

        # Filter modules by plan
        allowed = current_user.plan_config()['modules']
        modules = [m for m in modules if m in allowed]
        if not modules:
            modules = ['whois', 'ssl', 'headers', 'dns']

        scan = Scan(
            project_id=project.id,
            target=target,
            status='running',
            modules=','.join(modules),
        )
        db.session.add(scan)
        current_user.scans_used += 1
        db.session.commit()

        # Init progress
        scan_progress[scan.scan_id] = {'progress': 0, 'status': 'Starting scan...'}

        # Run scan in background thread
        t = threading.Thread(target=run_scan_background, args=(app, scan.id))
        t.daemon = True
        t.start()

        return redirect(url_for('scan_running', scan_id=scan.scan_id))

    return render_template('new_scan.html', project=project,
                           plan_modules=current_user.plan_config()['modules'],
                           all_modules=PLANS['pro']['modules'])


def run_scan_background(app, scan_db_id):
    """Run scan in background thread and save results to DB."""
    with app.app_context():
        scan = Scan.query.get(scan_db_id)
        if not scan:
            return
        sid = scan.scan_id
        try:
            from web_scanner import WebScanner
            scanner = WebScanner(scan.target, scan.modules_list(),
                                 progress_callback=lambda p, s: update_progress(sid, p, s))
            results = scanner.run_scan()
            risk    = calculate_risk_score(results)
            scan.results_json  = json.dumps(results)
            scan.status        = 'done'
            scan.risk_score    = risk
            scan.completed_at  = datetime.utcnow()
            db.session.commit()
            scan_progress[sid] = {'progress': 100, 'status': 'Complete'}
        except Exception as e:
            scan.status = 'failed'
            scan.results_json = json.dumps({'error': str(e)})
            db.session.commit()
            scan_progress[sid] = {'progress': 100, 'status': 'Failed'}


def update_progress(sid, progress, status):
    scan_progress[sid] = {'progress': progress, 'status': status}


def calculate_risk_score(results):
    score = 0
    if results.get('ssl', {}).get('valid') is False: score += 30
    if results.get('headers', {}).get('missing'):
        score += len(results['headers']['missing']) * 5
    if results.get('xss', {}).get('found'): score += 25
    if results.get('sqli', {}).get('found'): score += 30
    if results.get('ports', {}).get('open'):
        score += min(len(results['ports']['open']) * 3, 20)
    return min(score, 100)


@app.route('/scan/<scan_id>/running')
@login_required
def scan_running(scan_id):
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    project = Project.query.filter_by(id=scan.project_id, user_id=current_user.id).first_or_404()
    return render_template('scan_running.html', scan=scan, project=project)


@app.route('/scan/<scan_id>/progress')
@login_required
def scan_progress_api(scan_id):
    prog = scan_progress.get(scan_id, {'progress': 0, 'status': 'Queued...'})
    scan = Scan.query.filter_by(scan_id=scan_id).first()
    if scan and scan.status == 'done':
        prog = {'progress': 100, 'status': 'Complete', 'done': True,
                'redirect': url_for('scan_results', scan_id=scan_id)}
    elif scan and scan.status == 'failed':
        prog = {'progress': 100, 'status': 'Failed', 'done': True, 'error': True}
    return jsonify(prog)


@app.route('/scan/<scan_id>/results')
@login_required
def scan_results(scan_id):
    scan    = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    project = Project.query.filter_by(id=scan.project_id, user_id=current_user.id).first_or_404()
    results = scan.results()
    return render_template('scan_results.html', scan=scan, project=project,
                           results=results, plans=PLANS)


@app.route('/scan/<scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan    = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    project = Project.query.filter_by(id=scan.project_id, user_id=current_user.id).first_or_404()
    pid = project.id
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return redirect(url_for('project_detail', project_id=pid))


@app.route('/scan/<scan_id>/report')
@login_required
def download_report(scan_id):
    if not current_user.plan_config()['pdf_report']:
        flash('Reports are available on Pro/Enterprise plans.', 'warning')
        return redirect(url_for('pricing'))
    scan    = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    project = Project.query.filter_by(id=scan.project_id, user_id=current_user.id).first_or_404()
    results = scan.results()
    html = render_template('report_pdf.html', scan=scan, project=project, results=results)
    return send_file(
        io.BytesIO(html.encode('utf-8')),
        download_name=f'ws360-report-{scan_id[:8]}.html',
        as_attachment=True,
        mimetype='text/html'
    )


# ── Billing / Stripe ──────────────────────────────────────────────────────────
@app.route('/billing/checkout', methods=['POST'])
@login_required
def checkout():
    plan = request.form.get('plan')
    if plan not in ('pro', 'enterprise'):
        flash('Invalid plan.', 'error')
        return redirect(url_for('pricing'))
    try:
        if not current_user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=current_user.email,
                name=current_user.name,
                metadata={'user_id': current_user.id}
            )
            current_user.stripe_customer_id = customer.id
            db.session.commit()

        session_obj = stripe.checkout.Session.create(
            customer=current_user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{'price': PLANS[plan]['stripe_price_id'], 'quantity': 1}],
            mode='subscription',
            success_url=url_for('billing_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}&plan=' + plan,
            cancel_url=url_for('pricing', _external=True),
        )
        return redirect(session_obj.url, code=303)
    except stripe.error.StripeError as e:
        flash(f'Payment error: {e.user_message}', 'error')
        return redirect(url_for('pricing'))


@app.route('/billing/success')
@login_required
def billing_success():
    session_id = request.args.get('session_id')
    plan       = request.args.get('plan', 'pro')
    if session_id and plan in ('pro', 'enterprise'):
        try:
            checkout_session = stripe.checkout.Session.retrieve(session_id)
            current_user.plan = plan
            current_user.stripe_subscription_id = checkout_session.subscription
            db.session.commit()
            flash(f'🎉 Welcome to {PLANS[plan]["name"]}! Your plan has been upgraded.', 'success')
        except Exception:
            flash('Could not verify payment. Contact support.', 'error')
    return redirect(url_for('dashboard'))


@app.route('/billing/cancel', methods=['POST'])
@login_required
def cancel_subscription():
    if current_user.stripe_subscription_id:
        try:
            stripe.Subscription.modify(current_user.stripe_subscription_id,
                                       cancel_at_period_end=True)
            flash('Your subscription will cancel at the end of the billing period.', 'info')
        except stripe.error.StripeError as e:
            flash(f'Error: {e.user_message}', 'error')
    return redirect(url_for('account'))


@app.route('/billing/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig     = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return '', 400

    if event['type'] == 'customer.subscription.deleted':
        customer_id = event['data']['object']['customer']
        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if user:
            user.plan = 'free'
            user.stripe_subscription_id = None
            db.session.commit()

    return '', 200


# ── Account ───────────────────────────────────────────────────────────────────
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_name':
            name = request.form.get('name', '').strip()
            if name:
                current_user.name = name
                db.session.commit()
                flash('Name updated.', 'success')
        elif action == 'change_password':
            current_pw = request.form.get('current_password', '')
            new_pw     = request.form.get('new_password', '')
            if not current_user.check_password(current_pw):
                flash('Current password is incorrect.', 'error')
            elif len(new_pw) < 8:
                flash('New password must be at least 8 characters.', 'error')
            else:
                current_user.set_password(new_pw)
                db.session.commit()
                flash('Password changed successfully.', 'success')

    return render_template('account.html', plans=PLANS)


ADMIN_EMAIL = 'admin@websecure360.local'

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.email != ADMIN_EMAIL:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    users = User.query.order_by(User.created_at.desc()).all()
    total_scans = Scan.query.count()
    total_projects = Project.query.count()
    return render_template('admin.html',
                           users=users,
                           total_scans=total_scans,
                           total_projects=total_projects,
                           plans=PLANS)


@app.route('/admin/user/<int:user_id>/plan', methods=['POST'])
@login_required
@admin_required
def admin_change_plan(user_id):
    user = User.query.get_or_404(user_id)
    new_plan = request.form.get('plan')
    if new_plan in PLANS:
        user.plan = new_plan
        db.session.commit()
        flash(f'{user.name} upgraded to {new_plan.upper()}.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.email == ADMIN_EMAIL:
        flash('Cannot delete admin account.', 'error')
        return redirect(url_for('admin_panel'))
    name = user.name
    db.session.delete(user)
    db.session.commit()
    flash(f'User {name} deleted.', 'success')
    return redirect(url_for('admin_panel'))


# ── API Key Management ────────────────────────────────────────────────────────
@app.route('/account/api-key/generate', methods=['POST'])
@login_required
def generate_api_key():
    if not current_user.has_api_access():
        flash('API access requires Pro or Enterprise plan.', 'warning')
        return redirect(url_for('pricing'))
    current_user.generate_api_key()
    db.session.commit()
    flash('New API key generated.', 'success')
    return redirect(url_for('account'))


@app.route('/account/api-key/revoke', methods=['POST'])
@login_required
def revoke_api_key():
    current_user.api_key = None
    db.session.commit()
    flash('API key revoked.', 'info')
    return redirect(url_for('account'))


# ── REST API ──────────────────────────────────────────────────────────────────
def api_auth():
    """Validate API key from Authorization header. Returns user or None."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    key  = auth[7:].strip()
    user = User.query.filter_by(api_key=key).first()
    if not user or not user.has_api_access():
        return None
    return user


def api_error(msg, code=400):
    return jsonify({'error': msg}), code


@app.route('/api/v1/me')
def api_me():
    user = api_auth()
    if not user: return api_error('Unauthorized — provide a valid Bearer token', 401)
    return jsonify({
        'name':        user.name,
        'email':       user.email,
        'plan':        user.plan,
        'scans_used':  user.scans_used,
        'scans_left':  user.scans_left(),
        'projects':    len(user.projects),
    })


@app.route('/api/v1/projects')
def api_projects():
    user = api_auth()
    if not user: return api_error('Unauthorized', 401)
    return jsonify([{
        'id':          p.id,
        'name':        p.name,
        'description': p.description,
        'scans':       len(p.scans),
        'created_at':  p.created_at.isoformat(),
    } for p in user.projects])


@app.route('/api/v1/projects/<int:project_id>/scans')
def api_project_scans(project_id):
    user = api_auth()
    if not user: return api_error('Unauthorized', 401)
    project = Project.query.filter_by(id=project_id, user_id=user.id).first()
    if not project: return api_error('Project not found', 404)
    return jsonify([{
        'scan_id':    s.scan_id,
        'target':     s.target,
        'status':     s.status,
        'risk_score': s.risk_score,
        'modules':    s.modules_list(),
        'created_at': s.created_at.isoformat(),
    } for s in project.scans])


@app.route('/api/v1/scans/<scan_id>')
def api_scan_results(scan_id):
    user = api_auth()
    if not user: return api_error('Unauthorized', 401)
    scan    = Scan.query.filter_by(scan_id=scan_id).first()
    if not scan: return api_error('Scan not found', 404)
    project = Project.query.filter_by(id=scan.project_id, user_id=user.id).first()
    if not project: return api_error('Access denied', 403)
    return jsonify({
        'scan_id':    scan.scan_id,
        'target':     scan.target,
        'status':     scan.status,
        'risk_score': scan.risk_score,
        'modules':    scan.modules_list(),
        'created_at': scan.created_at.isoformat(),
        'results':    scan.results(),
    })


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e): return render_template('error.html', code=404, message='Page not found'), 404

@app.errorhandler(500)
def server_error(e): return render_template('error.html', code=500, message='Server error'), 500


# ── Init ──────────────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
