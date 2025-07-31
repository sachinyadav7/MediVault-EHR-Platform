from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import base64

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """Enhanced User model with comprehensive profile management"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True, index=True)
    email = db.Column(db.String(150), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(64), nullable=True)
    
    # Role Management
    role = db.Column(db.String(20), nullable=False, index=True)  # 'admin', 'doctor', 'patient'
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Profile Information
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    date_of_birth = db.Column(db.Date)
    gender = db.Column(db.String(10))
    address = db.Column(db.Text)
    profile_picture = db.Column(db.String(255))
    
    # Security & Timestamps
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    medical_files = db.relationship('MedicalFile', foreign_keys='MedicalFile.patient_id', backref='patient')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')

    def set_password(self, password):
        """Set password with salt"""
        if not self.salt:
            self.salt = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password and handle failed attempts"""
        if self.is_locked():
            return False
        
        is_valid = check_password_hash(self.password_hash, password)
        
        if is_valid:
            self.failed_login_attempts = 0
            self.last_login = datetime.utcnow()
            self.locked_until = None
        else:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.locked_until = datetime.utcnow() + timedelta(minutes=30)
        
        db.session.commit()
        return is_valid

    def is_locked(self):
        """Check if account is locked"""
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False

    @property
    def full_name(self):
        """Get full name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username

    def has_role(self, role):
        """Check if user has specific role"""
        return self.role == role

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class DoctorProfile(db.Model):
    """Additional profile information for doctors"""
    __tablename__ = 'doctor_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    
    # Professional Information
    medical_license = db.Column(db.String(100), unique=True)
    specialization = db.Column(db.String(200))
    qualification = db.Column(db.String(500))
    experience_years = db.Column(db.Integer)
    consultation_fee = db.Column(db.Float)
    
    # Hospital/Clinic Information
    hospital_name = db.Column(db.String(200))
    clinic_address = db.Column(db.Text)
    working_hours = db.Column(db.String(200))
    
    # Verification
    is_verified = db.Column(db.Boolean, default=False)
    verification_documents = db.Column(db.Text)  # JSON string of document paths
    
    # Professional Bio
    bio = db.Column(db.Text)
    languages = db.Column(db.String(200))  # Comma-separated
    
    # Ratings & Reviews
    average_rating = db.Column(db.Float, default=0.0)
    total_reviews = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('doctor_profile', uselist=False))

class PatientProfile(db.Model):
    """Additional profile information for patients"""
    __tablename__ = 'patient_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    
    # Health Information
    blood_group = db.Column(db.String(5))
    height = db.Column(db.Float)  # in cm
    weight = db.Column(db.Float)  # in kg
    emergency_contact_name = db.Column(db.String(100))
    emergency_contact_phone = db.Column(db.String(20))
    emergency_contact_relation = db.Column(db.String(50))
    
    # Medical History
    allergies = db.Column(db.Text)
    chronic_conditions = db.Column(db.Text)
    current_medications = db.Column(db.Text)
    insurance_provider = db.Column(db.String(200))
    insurance_number = db.Column(db.String(100))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('patient_profile', uselist=False))

class MedicalFile(db.Model):
    """Enhanced medical file management"""
    __tablename__ = 'medical_files'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # Could be doctor or patient
    
    # File Information
    file_name = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(100))
    
    # Medical Classification
    category = db.Column(db.String(100))  # 'lab_report', 'prescription', 'scan', 'consultation'
    description = db.Column(db.Text)
    tags = db.Column(db.String(500))  # Comma-separated tags
    
    # Security
    is_encrypted = db.Column(db.Boolean, default=True)
    encryption_key_id = db.Column(db.String(100))
    
    # Access Control
    is_shared = db.Column(db.Boolean, default=False)
    is_emergency_accessible = db.Column(db.Boolean, default=False)
    
    # Timestamps
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    uploaded_by = db.relationship('User', foreign_keys=[uploaded_by_id])
    
    @property
    def upload_date(self):
        """Alias for uploaded_at to maintain compatibility"""
        return self.uploaded_at

class FileAccess(db.Model):
    """File sharing and access control"""
    __tablename__ = 'file_access'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('medical_files.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Access Control
    granted_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    access_type = db.Column(db.String(50), default='read')  # 'read', 'write', 'download'
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Timestamps
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    
    # Relationships
    file = db.relationship('MedicalFile', backref='access_permissions')
    doctor = db.relationship('User', foreign_keys=[doctor_id])
    patient = db.relationship('User', foreign_keys=[patient_id])
    granted_by = db.relationship('User', foreign_keys=[granted_by_id])

class Appointment(db.Model):
    """Appointment scheduling system"""
    __tablename__ = 'appointments'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Appointment Details
    appointment_date = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, default=30)  # minutes
    appointment_type = db.Column(db.String(50))  # 'consultation', 'follow_up', 'emergency'
    consultation_mode = db.Column(db.String(50))  # 'video', 'in_person', 'phone'
    
    # Status
    status = db.Column(db.String(50), default='scheduled')  # 'scheduled', 'completed', 'cancelled', 'no_show'
    symptoms = db.Column(db.Text)
    diagnosis = db.Column(db.Text)
    prescription = db.Column(db.Text)
    notes = db.Column(db.Text)
    
    # Video Call Information
    meeting_id = db.Column(db.String(100))
    meeting_password = db.Column(db.String(100))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    patient = db.relationship('User', foreign_keys=[patient_id], backref='patient_appointments')
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='doctor_appointments')

class Prescription(db.Model):
    """Digital prescription management"""
    __tablename__ = 'prescriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'))
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Prescription Details
    medicines = db.Column(db.Text, nullable=False)  # JSON string
    instructions = db.Column(db.Text)
    duration = db.Column(db.String(100))
    
    # Status
    status = db.Column(db.String(50), default='active')  # 'active', 'completed', 'cancelled'
    is_digital_signature = db.Column(db.Boolean, default=True)
    
    # Timestamps
    prescribed_date = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    # Relationships
    appointment = db.relationship('Appointment', backref='prescriptions')
    patient = db.relationship('User', foreign_keys=[patient_id])
    doctor = db.relationship('User', foreign_keys=[doctor_id])

class AuditLog(db.Model):
    """Comprehensive audit logging for HIPAA compliance"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Action Details
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))  # 'file', 'user', 'appointment', etc.
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)  # JSON string with additional details
    
    # Request Information
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    session_id = db.Column(db.String(100))
    
    # Status
    status = db.Column(db.String(50))  # 'success', 'failed', 'unauthorized'
    error_message = db.Column(db.Text)
    
    # Timestamp
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class SystemSettings(db.Model):
    """System configuration and settings"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text)
    setting_type = db.Column(db.String(50))  # 'string', 'integer', 'boolean', 'json'
    description = db.Column(db.Text)
    is_public = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Emergency Access System
class EmergencyAccess(db.Model):
    """Emergency access to patient files"""
    __tablename__ = 'emergency_access'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    accessed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Emergency Details
    emergency_code = db.Column(db.String(20), unique=True)
    reason = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200))
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verified_at = db.Column(db.DateTime)
    
    # Relationships
    patient = db.relationship('User', foreign_keys=[patient_id])
    accessed_by = db.relationship('User', foreign_keys=[accessed_by_id])