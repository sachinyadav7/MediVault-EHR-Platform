"""
Authentication and authorization helper functions
"""
from datetime import datetime
import secrets
import string
from flask import request
from flask_login import current_user

def create_audit_log(action, details, ip_address=None, user_id=None):
    """Create an audit log entry"""
    from models import AuditLog, db
    
    log_entry = AuditLog(
        user_id=user_id or (current_user.id if current_user.is_authenticated else None),
        action=action,
        details=details,
        ip_address=ip_address or request.remote_addr,
        timestamp=datetime.utcnow()
    )
    
    db.session.add(log_entry)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Failed to create audit log: {e}")

def check_permission(user, resource_type, resource_id, action='read'):
    """Check if user has permission to perform action on resource"""
    if not user or not user.is_authenticated:
        return False
    
    # Admin has access to everything
    if user.role == 'admin':
        return True
    
    # Role-specific permission checks
    if resource_type == 'medical_file':
        from models import MedicalFile, FileAccess
        
        medical_file = MedicalFile.query.get(resource_id)
        if not medical_file:
            return False
        
        # Patient can access their own files
        if user.role == 'patient' and medical_file.patient_id == user.id:
            return True
        
        # Doctor can access files shared with them
        if user.role == 'doctor':
            access = FileAccess.query.filter_by(
                file_id=resource_id,
                doctor_id=user.id,
                is_active=True
            ).first()
            
            if access and (not access.expires_at or access.expires_at > datetime.utcnow()):
                return True
    
    return False

def generate_emergency_code():
    """Generate a secure emergency access code"""
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

def generate_secure_token(length=32):
    """Generate a secure random token"""
    return secrets.token_urlsafe(length)

def validate_password_strength(password):
    """Validate password strength"""
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    special_chars = "!@#$%^&*(),.?\":{}|<>"
    if not any(c in special_chars for c in password):
        errors.append("Password must contain at least one special character")
    
    return errors

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def get_user_display_name(user):
    """Get user's display name"""
    if user.first_name and user.last_name:
        return f"{user.first_name} {user.last_name}"
    return user.username

def is_medical_file_type(filename):
    """Check if file is a valid medical file type"""
    allowed_extensions = {
        'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'gif', 
        'tiff', 'bmp', 'dcm', 'xml', 'txt', 'rtf'
    }
    
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions