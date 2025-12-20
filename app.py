from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, Response
from models import db, MasterCategory, MasterTask, DailyEntry, HistoryEntry, User, ProRequest
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime, timedelta, date
from dateutil.relativedelta import relativedelta
import os






app = Flask(__name__)
# Using SQLite locally to mirror your MSSQL structure for rapid prototyping
# Database Configuration
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # Fix for Render's postgres:// URI which SQLAlchemy removed support for
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Fallback to local SQLite
    basedir = os.path.abspath(os.path.dirname(__file__))
    if not os.path.exists(os.path.join(basedir, 'data')):
        os.makedirs(os.path.join(basedir, 'data'))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data', 'daily_task_app_v4_pro.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#app.secret_key = 'Ameno123' # Added for session security
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key") #pour le prod
#cde: cf5b2a725f4501b10f264fde3ff684de1cfe1d0b57726b133f3323c29f9b2935



# --- Mail Configuration REMOVED ---
import csv
import io

# Upload configuration
UPLOAD_FOLDER = 'uploads/payment_proofs'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# --- INITIALISATION DE LA BASE ---
db.init_app(app)

with app.app_context():
    try:
        db.create_all()
        print("✅ DB OK - tables created or already exist")
    except Exception as e:
        print("❌ DB ERROR:", e)

# --- routes etc. ---

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access that page.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_tables():
    with app.app_context():
        db.create_all()
        # Seed initial category if empty
        db.create_all()
        # Seed initial category if empty AND we have a user? 
        # Actually, seeding should happen per-user now or not at all?
        # Let's Seed an Admin User if none exists
        if not User.query.filter_by(role='admin').first():
             # Create default admin for testing
             # You should change this password in production
             admin = User(username='admin', email='admin@example.com', role='admin', 
                          password_hash=generate_password_hash('admin123', method='pbkdf2:sha256'))
             db.session.add(admin)
             db.session.commit()
             print("Created default admin user: admin / admin123")

# --- Auth Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            flash('Please check your login details and try again.', 'danger')
            return redirect(url_for('login'))
            
        login_user(user, remember=remember)
        return redirect(url_for('index'))
        
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists', 'warning')
            return redirect(url_for('signup'))
            
        new_user = User(email=email, username=username, 
                        password_hash=generate_password_hash(password, method='pbkdf2:sha256'),
                        role='trial') # Default to trial
        
        db.session.add(new_user)
        db.session.commit()
        
        # Seed basic categories for new user?
        # Optional: Add "Personal" category
        default_cat = MasterCategory(name="Personal", owner=new_user)
        db.session.add(default_cat)
        db.session.commit()
        db.session.add(MasterTask(name="My First Task", category=default_cat))
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('index'))
        
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    users = User.query.all()
    stats = {}
    for u in users:
        stats[u.id] = {
            'categories': MasterCategory.query.filter_by(user_id=u.id).count(),
            'tasks': DailyEntry.query.filter_by(user_id=u.id).count(),
            'history': HistoryEntry.query.filter_by(user_id=u.id).count(),
            'pro_requests': ProRequest.query.filter_by(user_id=u.id).count(),
            'role': u.role
        }
    return render_template('admin.html', users=users, stats=stats)

# Admin Actions
@app.route('/admin/block-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_block_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash("Cannot block admin users", "danger")
        return redirect(url_for('admin_panel'))
    
    user.is_active = False
    db.session.commit()
    flash(f"User {user.email} has been blocked", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/activate-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_activate_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = True
    db.session.commit()
    flash(f"User {user.email} has been activated", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash("Cannot delete admin users", "danger")
        return redirect(url_for('admin_panel'))
    
    email = user.email
    db.session.delete(user)  # Cascade will delete all related data
    db.session.commit()
    flash(f"User {email} and all associated data have been deleted", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/upgrade-to-pro/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_upgrade_to_pro(user_id):
    user = User.query.get_or_404(user_id)
    
    # Upgrade to PRO for 1 year
    expiration = date.today() + relativedelta(years=1)
    user.role = 'pro'
    user.pro_expiration_date = expiration
    db.session.commit()
    
    flash(f"User {user.email} upgraded to PRO until {expiration.strftime('%d/%m/%Y')}", "success")
    return redirect(url_for('admin_panel'))

# --- PRO Upgrade Routes ---

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upgrade-to-pro', methods=['GET', 'POST'])
@login_required
def upgrade_to_pro():
    # Vérifier si l'utilisateur est déjà PRO
    if current_user.role == 'pro':
        flash("Vous êtes déjà PRO!", "info")
        return redirect(url_for('index'))
    
    # Vérifier demande en cours (ANTI-SPAM)
    active_statuses = ['EN_ATTENTE_PAIEMENT', 'PAIEMENT_EN_VERIFICATION', 'APPROUVEE']
    existing_request = ProRequest.query.filter_by(user_id=current_user.id)\
        .filter(ProRequest.status.in_(active_statuses)).first()
    
    if request.method == 'POST':
        # Bloquer si demande active
        if existing_request:
            flash("Vous avez déjà une demande PRO en cours. Veuillez patienter.", "warning")
            return redirect(url_for('upgrade_to_pro'))
        
        duration = int(request.form.get('duration'))
        payment_method = request.form.get('payment_method')
        
        # Validation
        if duration not in [1, 5]:
            flash("Durée invalide", "danger")
            return redirect(url_for('upgrade_to_pro'))
        
        if payment_method not in ['virement', 'd17', 'flouci']:
            flash("Moyen de paiement invalide", "danger")
            return redirect(url_for('upgrade_to_pro'))
        
        # Créer demande
        new_request = ProRequest(
            user_id=current_user.id,
            duration_years=duration,
            payment_method=payment_method,
            status='EN_ATTENTE_PAIEMENT'
        )
        db.session.add(new_request)
        db.session.commit()
        
        flash("Demande PRO créée! Veuillez téléverser votre justificatif de paiement.", "success")
        return redirect(url_for('upload_proof', request_id=new_request.id))
    
    return render_template('upgrade_to_pro.html', existing_request=existing_request)

@app.route('/upload-proof/<int:request_id>', methods=['GET', 'POST'])
@login_required
def upload_proof(request_id):
    pro_request = ProRequest.query.get_or_404(request_id)
    
    # Vérifier propriété
    if pro_request.user_id != current_user.id:
        flash("Accès non autorisé", "danger")
        return redirect(url_for('index'))
    
    # Vérifier statut
    if pro_request.status not in ['EN_ATTENTE_PAIEMENT', 'PAIEMENT_EN_VERIFICATION']:
        flash("Cette demande ne peut plus être modifiée", "warning")
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        if 'proof_file' not in request.files:
            flash("Aucun fichier sélectionné", "danger")
            return redirect(request.url)
        
        file = request.files['proof_file']
        
        if file.filename == '':
            flash("Aucun fichier sélectionné", "danger")
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # Nom sécurisé
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"proof_{current_user.id}_{request_id}_{int(datetime.utcnow().timestamp())}.{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Sauvegarder
            file.save(filepath)
            
            # Mettre à jour DB
            pro_request.proof_filename = filename
            pro_request.status = 'PAIEMENT_EN_VERIFICATION'
            db.session.commit()
            
            flash("Justificatif téléversé avec succès! Votre demande est en cours de vérification.", "success")
            return redirect(url_for('index'))
        else:
            flash("Type de fichier non autorisé. Utilisez PNG, JPG ou PDF.", "danger")
    
    return render_template('upload_proof.html', pro_request=pro_request)

@app.route('/admin/pro-requests')
@login_required
@admin_required
def admin_pro_requests():
    requests = ProRequest.query.order_by(ProRequest.created_at.desc()).all()
    return render_template('admin/pro_requests.html', requests=requests)

@app.route('/admin/approve-pro/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def approve_pro_request(request_id):
    pro_req = ProRequest.query.get_or_404(request_id)
    user = User.query.get(pro_req.user_id)
    
    # Calculer date expiration
    expiration = date.today() + relativedelta(years=pro_req.duration_years)
    
    # Upgrade user
    user.role = 'pro'
    user.pro_expiration_date = expiration
    
    # Update request
    pro_req.status = 'APPROUVEE'
    pro_req.validated_at = datetime.utcnow()
    pro_req.validated_by_admin_id = current_user.id
    
    db.session.commit()
    
    flash(f"✅ Utilisateur {user.email} est maintenant PRO jusqu'au {expiration.strftime('%d/%m/%Y')}", "success")
    return redirect(url_for('admin_pro_requests'))

@app.route('/admin/reject-pro/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def reject_pro_request(request_id):
    pro_req = ProRequest.query.get_or_404(request_id)
    
    pro_req.status = 'REFUSEE'
    pro_req.validated_at = datetime.utcnow()
    pro_req.validated_by_admin_id = current_user.id
    
    db.session.commit()
    
    flash(f"❌ Demande refusée. L'utilisateur peut créer une nouvelle demande.", "info")
    return redirect(url_for('admin_pro_requests'))

@app.route('/uploads/payment_proofs/<filename>')
@login_required
@admin_required
def serve_proof(filename):
    from flask import send_from_directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Routes ---

@app.route('/')
@login_required
def index():
    # Trial Expiry Check
    if current_user.role == 'trial':
        cutoff = datetime.utcnow() - timedelta(days=14)
        if current_user.created_at < cutoff:
            flash("Your free trial has expired. Please upgrade to Pro to continue.", "warning")
            return redirect(url_for('info')) # Or an upgrade page
            
    # Fetch all daily entries for CURRENT USER
    daily_entries = DailyEntry.query.filter_by(user_id=current_user.id).all()
    
    # Calculate unfinished tasks (proceed_rate < 100)
    unfinished_count = sum(1 for entry in daily_entries if entry.proceed_rate < 100)
    
    # Determine greeting based on current hour
    current_hour = datetime.now().hour
    if current_hour < 12:
        greeting = "Good Morning"
    elif current_hour < 18:
        greeting = "Good Afternoon"
    else:
        greeting = "Good Evening"
    
    # Fetch categories/tasks for the dropdowns owned by USER
    categories = MasterCategory.query.filter_by(user_id=current_user.id).all()
    all_tasks = MasterTask.query.join(MasterCategory).filter(MasterCategory.user_id==current_user.id).all()
    
    # Serialize categories for JS
    categories_data = [{'id': c.id, 'name': c.name} for c in categories]
    
    # Pass data for dropdowns
    return render_template('index.html', 
                           daily_entries=daily_entries, 
                           categories=categories,
                           categories_data=categories_data,
                           today=date.today(),
                           greeting=greeting,
                           unfinished_count=unfinished_count)

@app.route('/categories', methods=['GET', 'POST'])
@login_required
def manage_categories():
    if request.method == 'POST':
        # Simple handler for adding Category OR Task based on form data
        if 'new_category_name' in request.form:
            cat_name = request.form.get('new_category_name')
            if cat_name:
                # Check duplicate for THIS user
                if not MasterCategory.query.filter_by(user_id=current_user.id, name=cat_name).first():
                    db.session.add(MasterCategory(name=cat_name, owner=current_user))
                    db.session.commit()
        elif 'new_task_name' in request.form:
            task_name = request.form.get('new_task_name')
            cat_id = request.form.get('category_id')
            if task_name and cat_id:
                # Security Check: Ensure Category belongs to User
                cat = MasterCategory.query.get(cat_id)
                if not cat or cat.user_id != current_user.id:
                    flash("Unauthorized Access", "danger")
                    return redirect(url_for('manage_categories'))

                # Prevent Duplicates
                existing = MasterTask.query.filter(
                    MasterTask.category_id == cat_id,
                    MasterTask.name.ilike(task_name) # Case insensitive check
                ).first()
                if not existing:
                    db.session.add(MasterTask(name=task_name, category_id=cat_id))
                    db.session.commit()
        elif 'delete_category_id' in request.form:
             cat = MasterCategory.query.get(request.form.get('delete_category_id'))
             if cat and cat.user_id == current_user.id: 
                 db.session.delete(cat)
                 db.session.commit()
        elif 'delete_task_id' in request.form:
             tsk = MasterTask.query.get(request.form.get('delete_task_id'))
             # Check ownership via category
             if tsk and tsk.category.user_id == current_user.id: 
                 db.session.delete(tsk)
                 db.session.commit()
             
        return redirect(url_for('manage_categories'))

    categories = MasterCategory.query.filter_by(user_id=current_user.id).all()
    return render_template('categories.html', categories=categories)

@app.route('/get_tasks/<int:category_id>')
@login_required
def get_tasks(category_id):
    # Authenticate ownership
    cat = MasterCategory.query.get(category_id)
    if not cat or cat.user_id != current_user.id:
        return jsonify([])
        
    tasks = MasterTask.query.filter_by(category_id=category_id).all()
    return jsonify([{'id': t.id, 'name': t.name} for t in tasks])

def upsert_daily_entries(user, form_data):
    # Clear and rewrite approach (For THIS user only)
    DailyEntry.query.filter_by(user_id=user.id).delete()
    
    # Form data
    categories = form_data.getlist('category_name')
    tasks = form_data.getlist('task_name')
    impacts = form_data.getlist('impact_score')
    risks = form_data.getlist('risk_score')
    p_dates = form_data.getlist('planified_date')
    f_dates = form_data.getlist('finish_date')
    rates = form_data.getlist('proceed_rate')
    mins = form_data.getlist('numb_minutes')
    comments = form_data.getlist('comment')
    pin_modes = form_data.getlist('pin_mode')

    for i in range(len(categories)):
        if not categories[i]: continue # Skip empty rows
        
        try:
             imp = int(impacts[i]) if impacts[i] else 0
             rsk = int(risks[i]) if risks[i] else 0
             total = imp + rsk
             
             p_date_obj = datetime.strptime(p_dates[i], '%Y-%m-%d').date() if p_dates[i] else None
             f_date_obj = datetime.strptime(f_dates[i], '%Y-%m-%d').date() if f_dates[i] else None
             
             pm = pin_modes[i] if i < len(pin_modes) else 'none'

             entry = DailyEntry(
                 owner=user,
                 category_name=categories[i],
                 task_name=tasks[i],
                 impact_score=imp,
                 risk_score=rsk,
                 total_score=total,
                 planified_date=p_date_obj,
                 finish_date=f_date_obj,
                 proceed_rate=int(rates[i]) if rates[i] else 0,
                 numb_minutes=int(mins[i]) if mins[i] else 0,
                 comment=comments[i],
                 pin_mode=pm
             )
             db.session.add(entry)
        except ValueError:
            continue

    db.session.commit()

@app.route('/save_daily', methods=['POST'])
@login_required
def save_daily():
    upsert_daily_entries(current_user, request.form)
    return redirect(url_for('index'))

@app.route('/end_day', methods=['POST'])
@login_required
def end_day():
    # 1. Auto-Save current form data before archiving
    # This prevents "empty history" if user forgot to click Save
    if 'category_name' in request.form:
        upsert_daily_entries(current_user, request.form)

    dailies = DailyEntry.query.filter_by(user_id=current_user.id).all()
    
    for d in dailies:
        # 1. Archive to History (Always)
        h = HistoryEntry(
            owner=current_user,
            category_name=d.category_name,
            task_name=d.task_name,
            impact_score=d.impact_score,
            risk_score=d.risk_score,
            total_score=d.total_score,
            planified_date=d.planified_date,
            finish_date=d.finish_date,
            proceed_rate=d.proceed_rate,
            numb_minutes=d.numb_minutes,
            comment=d.comment,
            # Pin boolean for history? History table has is_pinned (bool). 
            # Let's say 'recurring' or 'continue' means pinned=True in history context.
            is_pinned=(d.pin_mode != 'none'),
            date_of_the_day=date.today()
        )
        db.session.add(h)
        
        # 2. Logic for Home Page (Delete or Keep)
        
        # Rule: Proceed < 100% -> Auto Pin (Continue Mode)
        if d.proceed_rate < 100:
            # KEEP (Continue mode: don't touch anything)
            pass
            
        # Rule: Pin Mode == 'continue' -> Keep
        elif d.pin_mode == 'continue':
            # KEEP (Don't touch)
            pass
            
        # Rule: Pin Mode == 'recurring' -> Keep but Reset Progress
        elif d.pin_mode == 'recurring':
            # Keep Category, Task, Scores. Reset others.
            # d.impact_score = d.impact_score # Keep
            # d.risk_score = d.risk_score # Keep
            d.proceed_rate = 0
            d.numb_minutes = 0
            d.comment = ""
            d.finish_date = None
            db.session.add(d) # Update
            
        # Rule: Unpinned and 100% -> Delete
        else:
            db.session.delete(d)
    
    db.session.commit()
    return redirect(url_for('history'))

@app.route('/history')
@login_required
def history():
    # Filter Logic
    cat_filter = request.args.get('category_filter')
    d_start = request.args.get('date_start')
    d_end = request.args.get('date_end')
    task_search = request.args.get('task_search')
    status_filter = request.args.get('status_filter') # completed, pending
    
    query = HistoryEntry.query.filter_by(user_id=current_user.id)
    
    if cat_filter:
        query = query.filter_by(category_name=cat_filter)
    
    if task_search:
        query = query.filter(HistoryEntry.task_name.ilike(f'%{task_search}%'))

    if status_filter == 'completed':
        query = query.filter(HistoryEntry.proceed_rate == 100)
    elif status_filter == 'pending':
        query = query.filter(HistoryEntry.proceed_rate < 100)

    if d_start:
        query = query.filter(HistoryEntry.date_of_the_day >= datetime.strptime(d_start, '%Y-%m-%d').date())
        
    if d_end:
        query = query.filter(HistoryEntry.date_of_the_day <= datetime.strptime(d_end, '%Y-%m-%d').date())
        
    entries = query.order_by(HistoryEntry.date_of_the_day.desc()).all()
    categories = MasterCategory.query.filter_by(user_id=current_user.id).all()
    
    return render_template('history.html', entries=entries, categories=categories)

@app.route('/export_history_csv')
@login_required
def export_history_csv():
    # Filter Logic (Duplicated from history)
    cat_filter = request.args.get('category_filter')
    d_start = request.args.get('date_start')
    d_end = request.args.get('date_end')
    task_search = request.args.get('task_search')
    status_filter = request.args.get('status_filter')

    query = HistoryEntry.query.filter_by(user_id=current_user.id)
    if cat_filter:
        query = query.filter_by(category_name=cat_filter)
    if task_search:
        query = query.filter(HistoryEntry.task_name.ilike(f'%{task_search}%'))
    if status_filter == 'completed':
        query = query.filter(HistoryEntry.proceed_rate == 100)
    elif status_filter == 'pending':
        query = query.filter(HistoryEntry.proceed_rate < 100)
    if d_start:
        query = query.filter(HistoryEntry.date_of_the_day >= datetime.strptime(d_start, '%Y-%m-%d').date())
    if d_end:
        query = query.filter(HistoryEntry.date_of_the_day <= datetime.strptime(d_end, '%Y-%m-%d').date())
    
    entries = query.order_by(HistoryEntry.date_of_the_day.desc()).all()
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['Date', 'Category', 'Task', 'Impact', 'Risk', 'Total', 'Plan Date', 'Finish Date', 'Progress', 'Minutes', 'Comment'])
    
    for e in entries:
        writer.writerow([
            e.date_of_the_day.strftime('%Y-%m-%d') if e.date_of_the_day else '',
            e.category_name,
            e.task_name,
            e.impact_score,
            e.risk_score,
            e.total_score,
            e.planified_date.strftime('%Y-%m-%d') if e.planified_date else '',
            e.finish_date.strftime('%Y-%m-%d') if e.finish_date else '',
            f"{e.proceed_rate}%",
            e.numb_minutes,
            e.comment
        ])
    
    output.seek(0)
    
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=history_export_{date.today()}.csv"}
    )


@app.route('/info')
def info():
    return render_template('info.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Filter Logic
    d_start = request.args.get('date_start')
    d_end = request.args.get('date_end')
    
    # Dynamic Thresholds (Defaults: 10, 5)
    try:
        imp_thresh = int(request.args.get('importance_threshold', 10))
    except: imp_thresh = 10
    
    try:
        waste_thresh = int(request.args.get('waster_threshold', 5))
    except: waste_thresh = 5
    
    query = HistoryEntry.query.filter_by(user_id=current_user.id)
    
    if d_start:
        query = query.filter(HistoryEntry.date_of_the_day >= datetime.strptime(d_start, '%Y-%m-%d').date())
    if d_end:
        query = query.filter(HistoryEntry.date_of_the_day <= datetime.strptime(d_end, '%Y-%m-%d').date())
        
    entries = query.order_by(HistoryEntry.date_of_the_day.asc()).all()
    
    # --- Metrics ---
    total_tasks = len(entries)
    avg_score = 0
    avg_rate = 0
    completion_rate = 0
    today_count = DailyEntry.query.filter_by(user_id=current_user.id).count()
    
    if total_tasks > 0:
        avg_score = sum([e.total_score for e in entries if e.total_score]) / total_tasks
        completed_count = sum([1 for e in entries if e.proceed_rate == 100])
        completion_rate = (completed_count / total_tasks) * 100
        avg_rate = sum([e.proceed_rate for e in entries if e.proceed_rate]) / total_tasks

    # --- Chart Data Aggregation ---
    
    timeline_map = {}
    cat_minutes = {}
    
    # Task Breakdown: { 'Category': { 'Task': minutes } }
    task_breakdown = {}
    
    waster_count = 0
    problem_tasks = []
    
    for e in entries:
        d_key = e.date_of_the_day.strftime('%Y-%m-%d')
        if d_key not in timeline_map:
            timeline_map[d_key] = {'minutes': 0, 'important': 0}
            
        mins = e.numb_minutes if e.numb_minutes else 0
        timeline_map[d_key]['minutes'] += mins
        
        # Dynamic Importance
        if e.total_score and e.total_score > imp_thresh:
             timeline_map[d_key]['important'] += 1
             
        # Repartition (Category)
        c_name = e.category_name
        if c_name not in cat_minutes: cat_minutes[c_name] = 0
        cat_minutes[c_name] += mins
        
        # Repartition (Task Breakdown)
        t_name = e.task_name
        if c_name not in task_breakdown: task_breakdown[c_name] = {}
        if t_name not in task_breakdown[c_name]: task_breakdown[c_name][t_name] = 0
        task_breakdown[c_name][t_name] += mins
        
        # Dynamic Time Wasters
        if e.total_score is not None and e.total_score < waste_thresh:
            waster_count += 1
            # Add to problem list
            problem_tasks.append({
                'date': e.date_of_the_day,
                'category': e.category_name,
                'task': e.task_name,
                'score': e.total_score,
                'minutes': mins
            })

    # Weekday Aggregation
    week_stats = {i: {'total': 0, 'count': 0} for i in range(7)}
    for e in entries:
        wd = e.date_of_the_day.weekday() # 0=Mon, 6=Sun
        if e.total_score:
            week_stats[wd]['total'] += e.total_score
            week_stats[wd]['count'] += 1
            
    week_data = []
    for i in range(7):
        if week_stats[i]['count'] > 0:
            week_data.append(round(week_stats[i]['total'] / week_stats[i]['count'], 1))
        else:
            week_data.append(0)
            
    week_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            
    # Sort problems by lowest score, then highest minutes
    problem_tasks.sort(key=lambda x: (x['score'], -x['minutes']))
    # Take top 10
    top_problems = problem_tasks[:10]
            
    # Serialize
    labels = sorted(timeline_map.keys())
    occupancy_data = [timeline_map[d]['minutes'] for d in labels]
    importance_data = [timeline_map[d]['important'] for d in labels]
    
    cat_labels = list(cat_minutes.keys())
    cat_data = list(cat_minutes.values())
        
    return render_template('dashboard.html',
                           metrics={
                               'total': total_tasks,
                               'avg_score': round(avg_score, 1),
                               'completion_rate': round(completion_rate, 1),
                               'avg_rate': round(avg_rate, 1),
                               'live_tasks': today_count,
                               'waster_count': waster_count,
                               'waster_pct': round((waster_count/total_tasks)*100, 1) if total_tasks else 0
                           },
                           thresholds={
                               'importance': imp_thresh,
                               'waste': waste_thresh
                           },
                           charts={
                               'labels': labels,
                               'occupancy': occupancy_data,
                               'importance': importance_data,
                               'cat_labels': cat_labels,
                               'cat_data': cat_data,
                               'task_breakdown': task_breakdown,
                               'week_labels': week_names,
                               'week_data': week_data
                           },
                           problems=top_problems)

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
