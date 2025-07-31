from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import secrets
import json

# Import models and utilities
from models import (
    db, User, DoctorProfile, PatientProfile, MedicalFile, 
    FileAccess, Appointment, Prescription, AuditLog, EmergencyAccess
)
from utils.encryption import encrypt_file, decrypt_file, derive_key_from_password
from utils.auth_helpers import create_audit_log, check_permission, generate_emergency_code
from config import Config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Import and register the analytics blueprint
try:
    from analytics import analytics
    app.register_blueprint(analytics)
    print("Analytics blueprint registered successfully")
except ImportError as e:
    print(f"Warning: Could not import analytics blueprint: {e}")
    print("Make sure analytics.py exists in your project directory")

# ============= AUTHENTICATION ROUTES =============

@app.route('/')
def home():
    """Landing page with role-based navigation"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/login')
@app.route('/login/<role>')
def login(role=None):
    """Multi-role login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Validate role
    valid_roles = ['admin', 'doctor', 'patient']
    if role and role not in valid_roles:
        flash('Invalid login type selected.', 'error')
        return redirect(url_for('login'))
    
    return render_template('auth/login.html', selected_role=role)

@app.route('/login', methods=['POST'])
def login_post():
    """Handle login form submission"""
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    role = request.form.get('role', '')
    remember_me = bool(request.form.get('remember_me'))
    
    # Validation
    if not all([email, password, role]):
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('login', role=role))
    
    if role not in ['admin', 'doctor', 'patient']:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('login'))
    
    # Find user
    user = User.query.filter_by(email=email, role=role, is_active=True).first()
    
    if not user:
        create_audit_log('login_failed', f'User not found: {email} ({role})', request.remote_addr)
        flash('Invalid credentials or account not found.', 'error')
        return redirect(url_for('login', role=role))
    
    # Check if account is locked
    if user.is_locked():
        create_audit_log('login_blocked', f'Account locked: {email}', request.remote_addr, user.id)
        flash('Account is temporarily locked due to multiple failed login attempts.', 'error')
        return redirect(url_for('login', role=role))
    
    # Verify password
    if not user.check_password(password):
        create_audit_log('login_failed', f'Wrong password: {email}', request.remote_addr, user.id)
        flash('Invalid credentials.', 'error')
        return redirect(url_for('login', role=role))
    
    # Additional verification for doctors
    if role == 'doctor' and hasattr(user, 'doctor_profile'):
        if not user.doctor_profile or not user.doctor_profile.is_verified:
            flash('Your doctor account is pending verification. Please contact support.', 'warning')
            return redirect(url_for('login', role=role))
    
    # Successful login
    login_user(user, remember=remember_me)
    user.last_login = datetime.datetime.utcnow()
    db.session.commit()
    
    create_audit_log('login_success', f'User logged in: {email}', request.remote_addr, user.id)
    
    flash(f'Welcome back, {user.full_name}!', 'success')
    
    # Redirect to intended page or dashboard
    next_page = request.args.get('next')
    if next_page:
        return redirect(next_page)
    
    return redirect(url_for('dashboard'))

@app.route('/register')
@app.route('/register/<role>')
def register(role=None):
    """Multi-role registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    valid_roles = ['doctor', 'patient']  # Admin accounts created manually
    if role and role not in valid_roles:
        flash('Invalid registration type selected.', 'error')
        return redirect(url_for('register'))
    
    return render_template('auth/register.html', selected_role=role)

@app.route('/register', methods=['POST'])
def register_post():
    """Handle registration form submission"""
    # Get form data
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    role = request.form.get('role', '')
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    phone = request.form.get('phone', '').strip()
    
    # Validation
    if not all([email, password, confirm_password, role, first_name, last_name]):
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('register', role=role))
    
    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('register', role=role))
    
    if len(password) < 8:
        flash('Password must be at least 8 characters long.', 'error')
        return redirect(url_for('register', role=role))
    
    if role not in ['doctor', 'patient']:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('register'))
    
    # Check if user already exists
    if User.query.filter_by(email=email).first():
        flash('An account with this email already exists.', 'error')
        return redirect(url_for('register', role=role))
    
    try:
        # Create user account
        username = f"{first_name.lower()}.{last_name.lower()}"
        
        # Ensure unique username
        counter = 1
        original_username = username
        while User.query.filter_by(username=username).first():
            username = f"{original_username}{counter}"
            counter += 1
        
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            role=role,
            is_verified=(role == 'patient')  # Patients auto-verified, doctors need manual verification
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.flush()  # Get user ID
        
        # Create role-specific profile
        if role == 'doctor':
            doctor_profile = DoctorProfile(
                user_id=user.id,
                medical_license=request.form.get('medical_license', ''),
                specialization=request.form.get('specialization', ''),
                qualification=request.form.get('qualification', ''),
                experience_years=int(request.form.get('experience_years', 0)) or None,
                hospital_name=request.form.get('hospital_name', ''),
                bio=request.form.get('bio', ''),
                is_verified=False  # Requires admin approval
            )
            db.session.add(doctor_profile)
            
        elif role == 'patient':
            patient_profile = PatientProfile(
                user_id=user.id,
                blood_group=request.form.get('blood_group', ''),
                emergency_contact_name=request.form.get('emergency_contact_name', ''),
                emergency_contact_phone=request.form.get('emergency_contact_phone', ''),
                emergency_contact_relation=request.form.get('emergency_contact_relation', '')
            )
            db.session.add(patient_profile)
        
        db.session.commit()
        
        create_audit_log('user_registered', f'New {role} registered: {email}', request.remote_addr, user.id)
        
        if role == 'doctor':
            flash('Registration successful! Your account is pending verification by our medical team.', 'info')
        else:
            flash('Registration successful! You can now log in.', 'success')
        
        return redirect(url_for('login', role=role))
        
    except Exception as e:
        db.session.rollback()
        flash('Registration failed. Please try again.', 'error')
        create_audit_log('registration_failed', f'Registration error: {str(e)}', request.remote_addr)
        return redirect(url_for('register', role=role))

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    create_audit_log('logout', f'User logged out: {current_user.email}', request.remote_addr, current_user.id)
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

# ============= DASHBOARD ROUTES =============

@app.route('/dashboard')
@login_required
def dashboard():
    """Role-based dashboard"""
    user = current_user
    
    if user.role == 'admin':
        return render_template('dashboards/admin_dashboard.html', user=user)
    elif user.role == 'doctor':
        return render_template('dashboards/doctor_dashboard.html', user=user)
    elif user.role == 'patient':
        # Get patient's medical files
        files = MedicalFile.query.filter_by(patient_id=user.id).order_by(MedicalFile.uploaded_at.desc()).all()
        return render_template('dashboards/patient_dashboard.html', user=user, files=files)
    
    flash('Invalid user role.', 'error')
    return redirect(url_for('logout'))

# ============= ANALYTICS ROUTES =============

@app.route('/analytics')
@login_required
def analytics_redirect():
    """Redirect to role-specific analytics dashboard"""
    try:
        if current_user.role == 'admin':
            return redirect(url_for('analytics.admin_analytics_dashboard'))
        elif current_user.role == 'doctor':
            return redirect(url_for('analytics.doctor_analytics_dashboard'))
        elif current_user.role == 'patient':
            return redirect(url_for('analytics.patient_analytics_dashboard'))
        else:
            flash('Analytics not available for your role.', 'info')
            return redirect(url_for('dashboard'))
    except Exception as e:
        flash('Analytics feature is currently unavailable.', 'warning')
        print(f"Analytics error: {e}")
        return redirect(url_for('dashboard'))

# ============= ADMIN ROUTES =============

@app.route('/admin/users')
@login_required
def admin_users():
    """Admin: Manage all users"""
    if not current_user.has_role('admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    role_filter = request.args.get('role', '')
    search_query = request.args.get('search', '')
    
    query = User.query
    
    if role_filter:
        query = query.filter(User.role == role_filter)
    
    if search_query:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search_query}%'),
                User.email.ilike(f'%{search_query}%'),
                User.first_name.ilike(f'%{search_query}%'),
                User.last_name.ilike(f'%{search_query}%')
            )
        )
    
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template('admin/users.html', users=users, role_filter=role_filter, search_query=search_query)

@app.route('/admin/verify-doctor/<int:doctor_id>')
@login_required
def admin_verify_doctor(doctor_id):
    """Admin: Verify doctor account"""
    if not current_user.has_role('admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    doctor = db.session.get(User, doctor_id)
    if not doctor or doctor.role != 'doctor':
        flash('Doctor not found.', 'error')
        return redirect(url_for('admin_users'))
    
    if hasattr(doctor, 'doctor_profile') and doctor.doctor_profile:
        doctor.doctor_profile.is_verified = True
        doctor.is_verified = True
        db.session.commit()
        
        create_audit_log('doctor_verified', f'Doctor verified: {doctor.email}', request.remote_addr, current_user.id)
        flash(f'Dr. {doctor.full_name} has been verified successfully.', 'success')
    else:
        flash('Doctor profile not found.', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/audit-logs')
@login_required
def admin_audit_logs():
    """Admin: View audit logs"""
    if not current_user.has_role('admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    
    query = AuditLog.query
    
    if action_filter:
        query = query.filter(AuditLog.action.ilike(f'%{action_filter}%'))
    
    if user_filter:
        query = query.join(User).filter(User.username.ilike(f'%{user_filter}%'))
    
    logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    
    return render_template('admin/audit_logs.html', logs=logs, action_filter=action_filter, user_filter=user_filter)

# ============= DOCTOR ROUTES =============

@app.route('/doctor/patients')
@login_required
def doctor_patients():
    """Doctor: View accessible patients"""
    if not current_user.has_role('doctor'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get patients who have shared files with this doctor
    accessible_files = FileAccess.query.filter_by(doctor_id=current_user.id, is_active=True).all()
    patient_ids = list(set([access.patient_id for access in accessible_files]))
    patients = User.query.filter(User.id.in_(patient_ids)).all() if patient_ids else []
    
    # Get upcoming appointments
    upcoming_appointments = Appointment.query.filter_by(
        doctor_id=current_user.id,
        status='scheduled'
    ).filter(Appointment.appointment_date >= datetime.utcnow()).order_by(Appointment.appointment_date).limit(5).all()
    
    return render_template('doctor/patients.html', patients=patients, upcoming_appointments=upcoming_appointments)

@app.route('/doctor/appointments')
@login_required
def doctor_appointments():
    """Doctor: Manage appointments"""
    if not current_user.has_role('doctor'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    
    query = Appointment.query.filter_by(doctor_id=current_user.id)
    
    if status_filter:
        query = query.filter(Appointment.status == status_filter)
    
    appointments = query.order_by(Appointment.appointment_date.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template('doctor/appointments.html', appointments=appointments, status_filter=status_filter)

@app.route('/doctor/shared-files')
@login_required
def doctor_shared_files():
    """Doctor: View files shared by patients"""
    if not current_user.has_role('doctor'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get files shared with this doctor
    access_entries = FileAccess.query.filter_by(doctor_id=current_user.id, is_active=True).all()
    files_data = []
    
    for access in access_entries:
        if access.file:
            files_data.append({
                'file': access.file,
                'patient': access.patient,
                'access_granted': access.granted_at,
                'access_type': access.access_type
            })
    
    return render_template('doctor/shared_files.html', files_data=files_data)

# ============= PATIENT ROUTES =============

@app.route('/patient/upload', methods=['GET', 'POST'])
@login_required
def patient_upload():
    """Patient: Upload medical files"""
    if not current_user.has_role('patient'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        file = request.files.get('file')
        category = request.form.get('category', '')
        description = request.form.get('description', '')
        tags = request.form.get('tags', '')
        
        if not file or file.filename == '':
            flash('Please select a file to upload.', 'error')
            return redirect(url_for('patient_upload'))
        
        if not category:
            flash('Please select a file category.', 'error')
            return redirect(url_for('patient_upload'))
        
        try:
            # Secure filename
            filename = secure_filename(file.filename)
            if not filename:
                flash('Invalid filename.', 'error')
                return redirect(url_for('patient_upload'))
            
            # Create unique filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{current_user.id}_{timestamp}_{filename}"
            
            # Ensure upload directory exists
            upload_folder = app.config.get('UPLOAD_FOLDER', 'uploads/medical_files')
            os.makedirs(upload_folder, exist_ok=True)
            
            file_path = os.path.join(upload_folder, unique_filename)
            
            # Encrypt and save file
            file_content = file.read()
            key = derive_key_from_password(current_user.password_hash, current_user.salt)
            encrypted_data = encrypt_file(file_content, key)
            
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save file record
            medical_file = MedicalFile(
                patient_id=current_user.id,
                uploaded_by_id=current_user.id,
                file_name=unique_filename,
                original_filename=filename,
                file_path=file_path,
                file_size=len(file_content),
                file_type=file.content_type,
                category=category,
                description=description,
                tags=tags,
                is_encrypted=True
            )
            
            db.session.add(medical_file)
            db.session.commit()
            
            create_audit_log('file_uploaded', f'File uploaded: {filename}', request.remote_addr, current_user.id)
            flash('File uploaded successfully!', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Upload failed: {str(e)}', 'error')
            create_audit_log('file_upload_failed', f'Upload error: {str(e)}', request.remote_addr, current_user.id)
        
        return redirect(url_for('dashboard'))
    
    categories = [
        ('lab_report', 'Lab Report'),
        ('prescription', 'Prescription'),
        ('scan', 'Medical Scan/X-Ray'),
        ('consultation', 'Consultation Notes'),
        ('insurance', 'Insurance Document'),
        ('other', 'Other')
    ]
    
    return render_template('patient/upload.html', categories=categories)

@app.route('/patient/share-file/<int:file_id>', methods=['GET', 'POST'])
@login_required
def patient_share_file(file_id):
    """Patient: Share file with doctor"""
    if not current_user.has_role('patient'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    medical_file = db.session.get(MedicalFile, file_id)
    if not medical_file or medical_file.patient_id != current_user.id:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        access_type = request.form.get('access_type', 'read')
        expires_days = int(request.form.get('expires_days', 30))
        
        if not doctor_id:
            flash('Please select a doctor.', 'error')
            return render_template('patient/share_file.html', file=medical_file, doctors=[])
        
        doctor = db.session.get(User, doctor_id)
        if not doctor or doctor.role != 'doctor':
            flash('Invalid doctor selected.', 'error')
            return render_template('patient/share_file.html', file=medical_file, doctors=[])
        
        # Check if already shared
        existing_access = FileAccess.query.filter_by(
            file_id=file_id,
            doctor_id=doctor_id,
            is_active=True
        ).first()
        
        if existing_access:
            flash('File is already shared with this doctor.', 'info')
        else:
            # Create new access record
            expires_at = datetime.utcnow() + timedelta(days=expires_days) if expires_days > 0 else None
            
            file_access = FileAccess(
                file_id=file_id,
                doctor_id=doctor_id,
                patient_id=current_user.id,
                granted_by_id=current_user.id,
                access_type=access_type,
                expires_at=expires_at
            )
            
            db.session.add(file_access)
            db.session.commit()
            
            create_audit_log('file_shared', f'File shared with Dr. {doctor.full_name}', request.remote_addr, current_user.id)
            flash(f'File shared successfully with Dr. {doctor.full_name}!', 'success')
        
        return redirect(url_for('dashboard'))
    
    # Get verified doctors
    doctors = User.query.filter_by(role='doctor', is_active=True, is_verified=True).all()
    
    return render_template('patient/share_file.html', file=medical_file, doctors=doctors)

@app.route('/patient/appointments')
@login_required
def patient_appointments():
    """Patient: View appointments"""
    if not current_user.has_role('patient'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    appointments = Appointment.query.filter_by(patient_id=current_user.id).order_by(
        Appointment.appointment_date.desc()
    ).paginate(page=page, per_page=10, error_out=False)
    
    return render_template('patient/appointments.html', appointments=appointments)

# ============= FILE MANAGEMENT ROUTES =============

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """Download medical file with permission check"""
    medical_file = db.session.get(MedicalFile, file_id)
    if not medical_file:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard'))
    
    # Permission check
    can_access = False
    
    if current_user.has_role('admin'):
        can_access = True
    elif current_user.has_role('patient') and medical_file.patient_id == current_user.id:
        can_access = True
    elif current_user.has_role('doctor'):
        # Check if doctor has access to this file
        access = FileAccess.query.filter_by(
            file_id=file_id,
            doctor_id=current_user.id,
            is_active=True
        ).first()
        if access and (not access.expires_at or access.expires_at > datetime.utcnow()):
            can_access = True
            # Update last accessed time
            access.last_accessed = datetime.utcnow()
            db.session.commit()
    
    if not can_access:
        create_audit_log('unauthorized_file_access', f'Unauthorized access attempt: {medical_file.file_name}', request.remote_addr, current_user.id)
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Read and decrypt file
        with open(medical_file.file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Get patient's key for decryption
        patient = db.session.get(User, medical_file.patient_id)
        key = derive_key_from_password(patient.password_hash, patient.salt)
        decrypted_data = decrypt_file(encrypted_data, key)
        
        create_audit_log('file_downloaded', f'File downloaded: {medical_file.file_name}', request.remote_addr, current_user.id)
        
        from flask import send_file
        from io import BytesIO
        
        return send_file(
            BytesIO(decrypted_data),
            as_attachment=True,
            download_name=medical_file.original_filename,
            mimetype=medical_file.file_type
        )
        
    except Exception as e:
        create_audit_log('file_download_failed', f'Download error: {str(e)}', request.remote_addr, current_user.id)
        flash(f'Download failed: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete-file/<int:file_id>')
@login_required
def delete_file(file_id):
    """Delete medical file (patient only)"""
    if not current_user.has_role('patient'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    medical_file = db.session.get(MedicalFile, file_id)
    if not medical_file or medical_file.patient_id != current_user.id:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Delete physical file
        if os.path.exists(medical_file.file_path):
            os.remove(medical_file.file_path)
        
        # Delete file access records
        FileAccess.query.filter_by(file_id=file_id).delete()
        
        # Delete file record
        db.session.delete(medical_file)
        db.session.commit()
        
        create_audit_log('file_deleted', f'File deleted: {medical_file.file_name}', request.remote_addr, current_user.id)
        flash('File deleted successfully.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Delete failed: {str(e)}', 'error')
        create_audit_log('file_delete_failed', f'Delete error: {str(e)}', request.remote_addr, current_user.id)
    
    return redirect(url_for('dashboard'))

# ============= API ROUTES =============

@app.route('/api/doctors')
@login_required
def api_doctors():
    """API: Get list of verified doctors"""
    if not current_user.has_role('patient'):
        return jsonify({'error': 'Access denied'}), 403
    
    doctors = User.query.filter_by(role='doctor', is_active=True, is_verified=True).all()
    doctors_data = []
    
    for doctor in doctors:
        doctor_data = {
            'id': doctor.id,
            'name': doctor.full_name,
            'specialization': doctor.doctor_profile.specialization if doctor.doctor_profile else 'General',
            'hospital': doctor.doctor_profile.hospital_name if doctor.doctor_profile else '',
            'experience': doctor.doctor_profile.experience_years if doctor.doctor_profile else 0,
            'rating': doctor.doctor_profile.average_rating if doctor.doctor_profile else 0
        }
        doctors_data.append(doctor_data)
    
    return jsonify({'doctors': doctors_data})

# ============= ERROR HANDLERS =============

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# ============= UTILITY FUNCTIONS =============

@app.context_processor
def utility_processor():
    """Make utility functions available in templates"""
    return {
        'current_time': datetime.utcnow,
        'format_datetime': lambda dt: dt.strftime('%Y-%m-%d %H:%M') if dt else '',
        'format_date': lambda dt: dt.strftime('%Y-%m-%d') if dt else '',
        'file_size_format': lambda size: f"{size / 1024 / 1024:.2f} MB" if size else "0 MB"
    }

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        admin = User.query.filter_by(email='admin@medivault.com').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@medivault.com',
                first_name='System',
                last_name='Administrator',
                role='admin',
                is_active=True,
                is_verified=True
            )
            admin.set_password('admin123')  # Change this in production!
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created: admin@medivault.com / admin123")
    
    app.run(debug=True)