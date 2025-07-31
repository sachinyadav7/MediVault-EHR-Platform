# MediVault EHR Platform - Complete Setup Guide

## 🏥 **MediVault: Secure Electronic Health Records Platform**

A comprehensive, HIPAA-compliant Electronic Health Record (EHR) system with multi-role authentication, AES-256 encryption, and advanced healthcare management features.

---

## 🚀 **Quick Start**

### **Prerequisites**
- Python 3.8+ 
- pip (Python package manager)
- Git
- SQLite (for development) or PostgreSQL (for production)

### **1. Clone & Setup Project**

```bash
# Clone the repository
git clone <your-repo-url>
cd medivault

# Create virtual environment
python -m venv medivault_env

# Activate virtual environment
# On Windows:
medivault_env\Scripts\activate
# On macOS/Linux:
source medivault_env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### **2. Environment Configuration**

Create a `.env` file in the root directory:

```env
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-super-secret-key-change-this-in-production

# Database Configuration
DATABASE_URL=sqlite:///medivault.db
# For PostgreSQL: postgresql://username:password@localhost/medivault

# Upload Configuration
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=50485760  # 50MB

# Email Configuration (Optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=noreply@medivault.com

# Security Configuration
PASSWORD_MIN_LENGTH=8
MAX_LOGIN_ATTEMPTS=5
```

### **3. Database Setup**

```bash
# Initialize database migrations
flask db init

# Create migration
flask db migrate -m "Initial migration"

# Apply migrations
flask db upgrade
```

### **4. Create Required Directories**

```bash
# Create upload directories
mkdir -p uploads/medical_files
mkdir -p uploads/profile_pictures
mkdir -p uploads/temp
mkdir -p static/css
mkdir -p templates/auth
mkdir -p templates/dashboards
mkdir -p templates/admin
mkdir -p templates/doctor
mkdir -p templates/patient
mkdir -p templates/errors
mkdir -p utils
```

### **5. Run the Application**

```bash
# Development server
python app.py

# Or using Flask CLI
flask run

# Access the application at: http://127.0.0.1:5000
```

---

## 🔐 **Default Admin Account**

The system automatically creates a default admin account:

```
Email: admin@medivault.com
Password: admin123
Role: Admin
```

**⚠️ Important: Change this password immediately in production!**

---

## 👥 **User Roles & Features**

### **🏥 Admin Dashboard**
- **User Management**: Create, edit, deactivate users
- **Doctor Verification**: Approve/reject doctor registrations
- **System Analytics**: User statistics, file uploads, system health
- **Audit Logs**: Complete HIPAA-compliant activity tracking
- **Security Monitoring**: Failed login attempts, suspicious activities
- **System Configuration**: Settings, backup management

### **👩‍⚕️ Doctor Dashboard**
- **Patient Management**: View assigned patients and their files
- **File Access**: Secure access to patient-shared medical records
- **Telemedicine**: Video consultation capabilities
- **Digital Prescriptions**: Create and manage prescriptions
- **Appointment Management**: Schedule and manage patient appointments
- **Analytics**: Patient health trends and insights

### **🤵 Patient Dashboard**
- **Medical Records**: Upload, organize, and manage health files
- **File Sharing**: Grant selective access to doctors
- **Appointments**: Book and manage appointments with verified doctors
- **Prescriptions**: View and manage digital prescriptions
- **Health Tracking**: Monitor health metrics over time
- **Emergency Access**: QR codes for emergency situations

---

## 🗂️ **Project Structure**

```
medivault/
├── app.py                     # Main Flask application
├── config.py                  # Configuration settings
├── models.py                  # Database models
├── requirements.txt           # Python dependencies
├── .env                       # Environment variables
├── migrations/                # Database migrations
├── static/
│   ├── css/
│   │   └── style.css         # Enhanced CSS styling
│   ├── js/                   # JavaScript files
│   └── images/               # Static images
├── templates/
│   ├── landing.html          # Landing page
│   ├── auth/                 # Authentication templates
│   │   ├── login.html        # Multi-role login
│   │   └── register.html     # Multi-role registration
│   ├── dashboards/           # Role-specific dashboards
│   │   ├── admin_dashboard.html
│   │   ├── doctor_dashboard.html
│   │   └── patient_dashboard.html
│   ├── admin/                # Admin-specific pages
│   ├── doctor/               # Doctor-specific pages
│   ├── patient/              # Patient-specific pages
│   └── errors/               # Error pages
├── utils/                    # Utility modules
│   ├── encryption.py         # Advanced encryption utilities
│   └── auth_helpers.py       # Authentication helpers
└── uploads/                  # File storage
    ├── medical_files/        # Encrypted medical files
    ├── profile_pictures/     # User profile images
    └── temp/                 # Temporary files
```

---

## 🔒 **Security Features**

### **Data Encryption**
- **AES-256 Encryption**: All medical files encrypted at rest
- **PBKDF2 Key Derivation**: 200,000 iterations for password-based keys
- **Salt-based Hashing**: Unique salt for each user account
- **Digital Signatures**: File integrity verification

### **Authentication Security**
- **Multi-Factor Authentication**: Email verification required
- **Account Lockout**: Automatic lockout after 5 failed attempts
- **Session Management**: Secure session handling with timeout
- **Password Policies**: Strong password requirements enforced

### **HIPAA Compliance**
- **Audit Logging**: Complete activity tracking with timestamps
- **Access Controls**: Role-based permissions and file access
- **Data Minimization**: Only necessary data collection
- **Secure Communication**: All data transmitted over HTTPS

---

## 📱 **API Endpoints**

### **Authentication**
```
POST /login                    # Multi-role login
POST /register                 # Multi-role registration
GET  /logout                   # User logout
```

### **File Management**
```
POST /patient/upload           # Upload medical file
GET  /download/<file_id>       # Download file (with permissions)
POST /patient/share-file/<id>  # Share file with doctor
DELETE /delete-file/<id>       # Delete file (patient only)
```

### **User Management**
```
GET  /admin/users              # List all users (admin only)
POST /admin/verify-doctor/<id> # Verify doctor account
GET  /admin/audit-logs         # View audit logs
```

### **API Endpoints**
```
GET  /api/doctors              # Get verified doctors list
GET  /api/appointments         # Get appointment data
POST /api/emergency-access     # Emergency file access
```

---

## 🔧 **Configuration Options**

### **Database Configuration**
```python
# SQLite (Development)
SQLALCHEMY_DATABASE_URI = 'sqlite:///medivault.db'

# PostgreSQL (Production)
SQLALCHEMY_DATABASE_URI = 'postgresql://user:password@localhost/medivault'

# MySQL (Alternative)
SQLALCHEMY_DATABASE_URI = 'mysql://user:password@localhost/medivault'
```

### **File Upload Limits**
```python
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 
    'gif', 'tiff', 'bmp', 'dcm', 'xml', 'txt', 'rtf'
}
```

### **Security Settings**
```python
# Password Requirements
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_NUMBERS = True
PASSWORD_REQUIRE_SPECIAL = True

# Account Security
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=30)
SESSION_LIFETIME = timedelta(hours=8)
```

---

## 🚀 **Production Deployment**

### **Using Gunicorn**
```bash
# Install production server
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

### **Using Docker**
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]
```

### **Environment Variables for Production**
```env
FLASK_ENV=production
DATABASE_URL=postgresql://username:password@localhost/medivault
SECRET_KEY=your-production-secret-key
SESSION_COOKIE_SECURE=true
```

---

## 🧪 **Testing**

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_auth.py
```

---

## 📚 **Additional Features**

### **Upcoming Features**
- [ ] **Real-time Chat**: WebSocket-based doctor-patient communication
- [ ] **Video Calls**: Integrated telemedicine platform
- [ ] **Mobile App**: React Native mobile application
- [ ] **AI Insights**: Machine learning health predictions
- [ ] **Wearable Integration**: Connect fitness trackers and health devices
- [ ] **Blockchain**: Immutable audit trail using blockchain

### **Integration Options**
- **Payment Gateway**: Stripe, PayPal integration for consultations
- **SMS Notifications**: Twilio integration for appointment reminders
- **Cloud Storage**: AWS S3, Azure Blob Storage for file storage
- **Email Service**: SendGrid, Mailgun for transactional emails

---

## 🆘 **Troubleshooting**

### **Common Issues**

1. **Database Connection Error**
   ```bash
   # Reset database
   flask db downgrade
   flask db upgrade
   ```

2. **File Upload Issues**
   ```bash
   # Check upload directory permissions
   chmod 755 uploads/
   chmod 755 uploads/medical_files/
   ```

3. **Encryption Key Errors**
   ```bash
   # Generate new secret key
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

4. **Permission Denied**
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER uploads/
   ```

---

## 🤝 **Contributing**

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 **License**

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 📞 **Support**

- **Documentation**: [Coming Soon]
- **Issues**: Create GitHub issues for bugs
- **Email**: support@medivault.com
- **Community**: [Discord/Slack Channel Coming Soon]

---

## 🏆 **Acknowledgments**

- Flask community for the excellent framework
- Cryptography library for robust encryption
- Healthcare professionals for requirements and feedback
- Open source community for inspiration and tools

---

**🏥 MediVault - Securing Healthcare Data, One Record at a Time** 

**Built with ❤️ for Healthcare Professionals and Patients**