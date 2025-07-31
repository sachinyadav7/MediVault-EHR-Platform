from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from sqlalchemy import func, extract, desc
from datetime import datetime, timedelta
from models import (
    db, User, MedicalFile, FileAccess, Appointment, 
    Prescription, AuditLog, DoctorProfile, PatientProfile
)
import json

analytics = Blueprint('analytics', __name__, url_prefix='/analytics')

# ============= ADMIN ANALYTICS =============

@analytics.route('/admin/dashboard')
@login_required
def admin_analytics_dashboard():
    """Admin analytics dashboard with comprehensive system metrics"""
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    # Basic metrics
    total_users = User.query.filter_by(is_active=True).count()
    total_patients = User.query.filter_by(role='patient', is_active=True).count()
    total_doctors = User.query.filter_by(role='doctor', is_active=True).count()
    verified_doctors = User.query.filter_by(role='doctor', is_active=True, is_verified=True).count()
    
    total_files = MedicalFile.query.count()
    total_appointments = Appointment.query.count()
    total_prescriptions = Prescription.query.count()
    
    # Growth metrics (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    new_users_30d = User.query.filter(User.created_at >= thirty_days_ago).count()
    new_files_30d = MedicalFile.query.filter(MedicalFile.uploaded_at >= thirty_days_ago).count()
    new_appointments_30d = Appointment.query.filter(Appointment.created_at >= thirty_days_ago).count()
    
    # File storage metrics
    total_storage = db.session.query(func.sum(MedicalFile.file_size)).scalar() or 0
    avg_file_size = db.session.query(func.avg(MedicalFile.file_size)).scalar() or 0
    
    # Most active patients (by file uploads)
    active_patients = db.session.query(
        User.id, User.first_name, User.last_name, func.count(MedicalFile.id).label('file_count')
    ).join(MedicalFile, User.id == MedicalFile.patient_id)\
     .group_by(User.id)\
     .order_by(desc('file_count'))\
     .limit(10).all()
    
    # Doctor verification status
    pending_doctors = User.query.filter_by(role='doctor', is_verified=False, is_active=True).count()
    
    metrics = {
        'total_users': total_users,
        'total_patients': total_patients,
        'total_doctors': total_doctors,
        'verified_doctors': verified_doctors,
        'pending_doctors': pending_doctors,
        'total_files': total_files,
        'total_appointments': total_appointments,
        'total_prescriptions': total_prescriptions,
        'new_users_30d': new_users_30d,
        'new_files_30d': new_files_30d,
        'new_appointments_30d': new_appointments_30d,
        'total_storage_mb': round(total_storage / (1024 * 1024), 2),
        'avg_file_size_mb': round(avg_file_size / (1024 * 1024), 2),
        'active_patients': [
            {
                'name': f"{p.first_name} {p.last_name}",
                'file_count': p.file_count
            } for p in active_patients
        ]
    }
    
    return render_template('analytics/admin_dashboard.html', metrics=metrics)

@analytics.route('/admin/api/user-growth')
@login_required
def admin_user_growth_api():
    """API endpoint for user growth chart data"""
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    days = request.args.get('days', 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Group by date and role
    growth_data = db.session.query(
        func.date(User.created_at).label('date'),
        User.role,
        func.count(User.id).label('count')
    ).filter(User.created_at >= start_date)\
     .group_by(func.date(User.created_at), User.role)\
     .order_by('date').all()
    
    # Format data for chart
    chart_data = {}
    for row in growth_data:
        date_str = row.date.strftime('%Y-%m-%d')
        if date_str not in chart_data:
            chart_data[date_str] = {'patient': 0, 'doctor': 0, 'admin': 0}
        chart_data[date_str][row.role] = row.count
    
    return jsonify({
        'labels': list(chart_data.keys()),
        'datasets': [
            {
                'label': 'Patients',
                'data': [data.get('patient', 0) for data in chart_data.values()],
                'borderColor': 'rgb(75, 192, 192)',
                'backgroundColor': 'rgba(75, 192, 192, 0.2)'
            },
            {
                'label': 'Doctors',
                'data': [data.get('doctor', 0) for data in chart_data.values()],
                'borderColor': 'rgb(255, 99, 132)',
                'backgroundColor': 'rgba(255, 99, 132, 0.2)'
            }
        ]
    })

@analytics.route('/admin/api/file-categories')
@login_required
def admin_file_categories_api():
    """API endpoint for file category distribution"""
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    categories = db.session.query(
        MedicalFile.category,
        func.count(MedicalFile.id).label('count')
    ).group_by(MedicalFile.category).all()
    
    category_labels = {
        'lab_report': 'Lab Reports',
        'prescription': 'Prescriptions',
        'scan': 'Medical Scans',
        'consultation': 'Consultation Notes',
        'insurance': 'Insurance Documents',
        'other': 'Other'
    }
    
    return jsonify({
        'labels': [category_labels.get(cat.category, cat.category) for cat in categories],
        'data': [cat.count for cat in categories],
        'backgroundColor': [
            '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40'
        ]
    })

# ============= DOCTOR ANALYTICS =============

@analytics.route('/doctor/dashboard')
@login_required
def doctor_analytics_dashboard():
    """Doctor analytics dashboard with patient and appointment metrics"""
    if not current_user.has_role('doctor'):
        return jsonify({'error': 'Access denied'}), 403
    
    # Basic metrics
    total_patients = db.session.query(func.count(func.distinct(FileAccess.patient_id)))\
                              .filter_by(doctor_id=current_user.id, is_active=True).scalar()
    
    total_appointments = Appointment.query.filter_by(doctor_id=current_user.id).count()
    completed_appointments = Appointment.query.filter_by(
        doctor_id=current_user.id, status='completed'
    ).count()
    
    upcoming_appointments = Appointment.query.filter_by(
        doctor_id=current_user.id, status='scheduled'
    ).filter(Appointment.appointment_date >= datetime.utcnow()).count()
    
    accessible_files = FileAccess.query.filter_by(
        doctor_id=current_user.id, is_active=True
    ).count()
    
    # This month's appointments
    current_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_appointments = Appointment.query.filter_by(doctor_id=current_user.id)\
                                           .filter(Appointment.appointment_date >= current_month).count()
    
    # Recent patient interactions
    recent_files = db.session.query(FileAccess, MedicalFile, User)\
                             .join(MedicalFile, FileAccess.file_id == MedicalFile.id)\
                             .join(User, FileAccess.patient_id == User.id)\
                             .filter(FileAccess.doctor_id == current_user.id, FileAccess.is_active == True)\
                             .order_by(FileAccess.granted_at.desc())\
                             .limit(5).all()
    
    # Appointment completion rate
    completion_rate = 0
    if total_appointments > 0:
        completion_rate = round((completed_appointments / total_appointments) * 100, 1)
    
    metrics = {
        'total_patients': total_patients,
        'total_appointments': total_appointments,
        'completed_appointments': completed_appointments,
        'upcoming_appointments': upcoming_appointments,
        'accessible_files': accessible_files,
        'monthly_appointments': monthly_appointments,
        'completion_rate': completion_rate,
        'recent_files': [
            {
                'patient_name': f"{r.User.first_name} {r.User.last_name}",
                'file_name': r.MedicalFile.original_filename,
                'category': r.MedicalFile.category,
                'granted_date': r.FileAccess.granted_at.strftime('%Y-%m-%d')
            } for r in recent_files
        ]
    }
    
    return render_template('analytics/doctor_dashboard.html', metrics=metrics)

@analytics.route('/doctor/api/appointment-trends')
@login_required
def doctor_appointment_trends_api():
    """API endpoint for doctor's appointment trends"""
    if not current_user.has_role('doctor'):
        return jsonify({'error': 'Access denied'}), 403
    
    days = request.args.get('days', 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Appointments by date
    appointment_data = db.session.query(
        func.date(Appointment.appointment_date).label('date'),
        func.count(Appointment.id).label('count')
    ).filter(
        Appointment.doctor_id == current_user.id,
        Appointment.appointment_date >= start_date
    ).group_by(func.date(Appointment.appointment_date))\
     .order_by('date').all()
    
    return jsonify({
        'labels': [row.date.strftime('%Y-%m-%d') for row in appointment_data],
        'data': [row.count for row in appointment_data]
    })

@analytics.route('/doctor/api/patient-file-access')
@login_required
def doctor_patient_file_access_api():
    """API endpoint for patient file access patterns"""
    if not current_user.has_role('doctor'):
        return jsonify({'error': 'Access denied'}), 403
    
    # Files accessed by category
    file_access_data = db.session.query(
        MedicalFile.category,
        func.count(FileAccess.id).label('access_count')
    ).join(FileAccess, MedicalFile.id == FileAccess.file_id)\
     .filter(FileAccess.doctor_id == current_user.id, FileAccess.is_active == True)\
     .group_by(MedicalFile.category).all()
    
    category_labels = {
        'lab_report': 'Lab Reports',
        'prescription': 'Prescriptions',
        'scan': 'Medical Scans',
        'consultation': 'Consultation Notes',
        'insurance': 'Insurance Documents',
        'other': 'Other'
    }
    
    return jsonify({
        'labels': [category_labels.get(row.category, row.category) for row in file_access_data],
        'data': [row.access_count for row in file_access_data]
    })

# ============= PATIENT ANALYTICS =============

@analytics.route('/patient/dashboard')
@login_required
def patient_analytics_dashboard():
    """Patient analytics dashboard with health tracking metrics"""
    if not current_user.has_role('patient'):
        return jsonify({'error': 'Access denied'}), 403
    
    # Basic metrics
    total_files = MedicalFile.query.filter_by(patient_id=current_user.id).count()
    shared_files = db.session.query(func.count(func.distinct(FileAccess.file_id)))\
                             .filter_by(patient_id=current_user.id, is_active=True).scalar()
    
    total_appointments = Appointment.query.filter_by(patient_id=current_user.id).count()
    completed_appointments = Appointment.query.filter_by(
        patient_id=current_user.id, status='completed'
    ).count()
    
    upcoming_appointments = Appointment.query.filter_by(
        patient_id=current_user.id, status='scheduled'
    ).filter(Appointment.appointment_date >= datetime.utcnow()).count()
    
    active_prescriptions = Prescription.query.filter_by(
        patient_id=current_user.id, status='active'
    ).count()
    
    # Storage usage
    total_storage = db.session.query(func.sum(MedicalFile.file_size))\
                              .filter_by(patient_id=current_user.id).scalar() or 0
    
    # File categories distribution
    file_categories = db.session.query(
        MedicalFile.category,
        func.count(MedicalFile.id).label('count')
    ).filter_by(patient_id=current_user.id)\
     .group_by(MedicalFile.category).all()
    
    # Recent file uploads
    recent_files = MedicalFile.query.filter_by(patient_id=current_user.id)\
                                   .order_by(MedicalFile.uploaded_at.desc())\
                                   .limit(5).all()
    
    # Doctors with access
    doctors_with_access = db.session.query(User, func.count(FileAccess.id).label('file_count'))\
                                    .join(FileAccess, User.id == FileAccess.doctor_id)\
                                    .filter(FileAccess.patient_id == current_user.id, FileAccess.is_active == True)\
                                    .group_by(User.id).all()
    
    metrics = {
        'total_files': total_files,
        'shared_files': shared_files,
        'total_appointments': total_appointments,
        'completed_appointments': completed_appointments,
        'upcoming_appointments': upcoming_appointments,
        'active_prescriptions': active_prescriptions,
        'storage_mb': round(total_storage / (1024 * 1024), 2),
        'file_categories': [
            {'category': cat.category, 'count': cat.count} 
            for cat in file_categories
        ],
        'recent_files': [
            {
                'filename': f.original_filename,
                'category': f.category,
                'upload_date': f.uploaded_at.strftime('%Y-%m-%d'),
                'size_mb': round(f.file_size / (1024 * 1024), 2)
            } for f in recent_files
        ],
        'doctors_with_access': [
            {
                'name': f"Dr. {doc.first_name} {doc.last_name}",
                'specialization': doc.doctor_profile.specialization if doc.doctor_profile else 'General',
                'file_count': count
            } for doc, count in doctors_with_access
        ]
    }
    
    return render_template('analytics/patient_dashboard.html', metrics=metrics)

@analytics.route('/patient/api/file-upload-trends')
@login_required
def patient_file_upload_trends_api():
    """API endpoint for patient's file upload trends"""
    if not current_user.has_role('patient'):
        return jsonify({'error': 'Access denied'}), 403
    
    days = request.args.get('days', 90, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Files uploaded by date
    upload_data = db.session.query(
        func.date(MedicalFile.uploaded_at).label('date'),
        func.count(MedicalFile.id).label('count')
    ).filter(
        MedicalFile.patient_id == current_user.id,
        MedicalFile.uploaded_at >= start_date
    ).group_by(func.date(MedicalFile.uploaded_at))\
     .order_by('date').all()
    
    return jsonify({
        'labels': [row.date.strftime('%Y-%m-%d') for row in upload_data],
        'data': [row.count for row in upload_data]
    })

@analytics.route('/patient/api/health-summary')
@login_required
def patient_health_summary_api():
    """API endpoint for patient's health summary over time"""
    if not current_user.has_role('patient'):
        return jsonify({'error': 'Access denied'}), 403
    
    # Appointments by month for the last year
    one_year_ago = datetime.utcnow() - timedelta(days=365)
    
    monthly_appointments = db.session.query(
        extract('year', Appointment.appointment_date).label('year'),
        extract('month', Appointment.appointment_date).label('month'),
        func.count(Appointment.id).label('count')
    ).filter(
        Appointment.patient_id == current_user.id,
        Appointment.appointment_date >= one_year_ago
    ).group_by('year', 'month')\
     .order_by('year', 'month').all()
    
    # Format for chart
    chart_data = []
    for row in monthly_appointments:
        month_name = datetime(int(row.year), int(row.month), 1).strftime('%b %Y')
        chart_data.append({
            'month': month_name,
            'appointments': row.count
        })
    
    return jsonify({
        'labels': [item['month'] for item in chart_data],
        'data': [item['appointments'] for item in chart_data]
    })

# ============= GENERAL ANALYTICS UTILITIES =============

@analytics.route('/api/system-health')
@login_required
def system_health_api():
    """API endpoint for system health metrics"""
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    # Database health
    try:
        db.session.execute('SELECT 1')
        db_status = 'healthy'
    except:
        db_status = 'error'
    
    # Recent error logs
    error_logs = AuditLog.query.filter(
        AuditLog.status == 'failed',
        AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    # Active sessions (approximate)
    active_sessions = User.query.filter(
        User.last_login >= datetime.utcnow() - timedelta(hours=1)
    ).count()
    
    return jsonify({
        'database_status': db_status,
        'error_logs_24h': error_logs,
        'active_sessions': active_sessions,
        'timestamp': datetime.utcnow().isoformat()
    })

# Export analytics data
@analytics.route('/export/<data_type>')
@login_required
def export_analytics_data(data_type):
    """Export analytics data as CSV"""
    from flask import Response
    import csv
    from io import StringIO
    
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    output = StringIO()
    
    if data_type == 'users':
        writer = csv.writer(output)
        writer.writerow(['ID', 'Username', 'Email', 'Role', 'Created At', 'Last Login', 'Is Active'])
        
        users = User.query.all()
        for user in users:
            writer.writerow([
                user.id, user.username, user.email, user.role,
                user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Never',
                user.is_active
            ])
    
    elif data_type == 'files':
        writer = csv.writer(output)
        writer.writerow(['ID', 'Patient', 'Filename', 'Category', 'Size (MB)', 'Uploaded At'])
        
        files = db.session.query(MedicalFile, User)\
                          .join(User, MedicalFile.patient_id == User.id).all()
        
        for file, patient in files:
            writer.writerow([
                file.id, f"{patient.first_name} {patient.last_name}",
                file.original_filename, file.category,
                round(file.file_size / (1024 * 1024), 2),
                file.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={data_type}_export.csv'}
    )