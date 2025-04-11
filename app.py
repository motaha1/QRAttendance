from flask import Flask, render_template, request, redirect, url_for, session, make_response, send_file, flash
from flask_sqlalchemy import SQLAlchemy
import qrcode
from io import BytesIO
import pandas as pd
from datetime import datetime
import hashlib
import getpass
from werkzeug.security import generate_password_hash
import base64
import os
import secrets

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Database Models
class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class AttendanceSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    session_code = db.Column(db.String(10), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    start_time = db.Column(db.DateTime, default=datetime.now)
    end_time = db.Column(db.DateTime)


class AttendanceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_name = db.Column(db.String(100), nullable=False)
    student_id = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, default=datetime.now().date)
    ip_address = db.Column(db.String(15), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('attendance_session.id'))



# Template filter for base64 encoding
@app.template_filter('b64encode')
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return None


# Teacher Routes
@app.route('/teacher', methods=['GET', 'POST'])
def teacher_login():
    if request.method == 'POST':
        teacher = Teacher.query.filter_by(
            username=request.form['username'],
            password=hashlib.sha256(request.form['password'].encode()).hexdigest()
        ).first()
        if teacher:
            session['teacher_id'] = teacher.id
            return redirect(url_for('teacher_dashboard'))
        return render_template('teacher_login.html', error="Invalid credentials")
    return render_template('teacher_login.html')


@app.route('/teacher/dashboard')
def teacher_dashboard():
    if 'teacher_id' not in session:
        return redirect(url_for('teacher_login'))

    current_session = AttendanceSession.query.filter_by(
        teacher_id=session['teacher_id'],
        is_active=True
    ).first()

    return render_template('dashboard.html',
                           current_session=current_session,
                           teacher=Teacher.query.get(session['teacher_id']))


@app.route('/teacher/generate_qr', methods=['POST'])
def generate_qr():
    if 'teacher_id' not in session:
        return redirect(url_for('teacher_login'))

    # Check if there's already an active session
    active_session = AttendanceSession.query.filter_by(
        teacher_id=session['teacher_id'],
        is_active=True
    ).first()

    if active_session:
        flash("You already have an active session. Please stop it before creating a new one.", "warning")
        return redirect(url_for('teacher_dashboard'))

    session_code = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:10]
    new_session = AttendanceSession(
        teacher_id=session['teacher_id'],
        session_code=session_code
    )

    db.session.add(new_session)
    db.session.commit()

    qr_url = f"{request.host_url}reg/{session_code}"
    img = qrcode.make(qr_url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    img_data = buf.getvalue()

    # Store QR code in session to display on dashboard
    session['qr_code'] = img_data
    return redirect(url_for('teacher_dashboard'))


@app.route('/teacher/stop_session', methods=['POST'])
def stop_session():
    if 'teacher_id' not in session:
        return redirect(url_for('teacher_login'))

    current_session = AttendanceSession.query.filter_by(
        teacher_id=session['teacher_id'],
        is_active=True
    ).first()

    if current_session:
        current_session.is_active = False
        current_session.end_time = datetime.now()
        db.session.commit()
        session.pop('qr_code', None)  # Remove QR code from session

    return redirect(url_for('teacher_dashboard'))


# Updated Records View with Filtering
@app.route('/teacher/records', methods=['GET', 'POST'])
def view_records():
    if 'teacher_id' not in session:
        return redirect(url_for('teacher_login'))

    # Get filter parameters from request
    student_id_filter = request.args.get('student_id', '').strip()
    student_name_filter = request.args.get('student_name', '').strip()
    date_filter = request.args.get('date', '').strip()

    # Base query
    query = AttendanceRecord.query.join(AttendanceSession) \
        .filter(AttendanceSession.teacher_id == session['teacher_id'])

    # Apply filters
    if student_id_filter:
        query = query.filter(AttendanceRecord.student_id.contains(student_id_filter))
    if student_name_filter:
        query = query.filter(AttendanceRecord.student_name.contains(student_name_filter))
    if date_filter:
        try:
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(AttendanceRecord.date == filter_date)
        except ValueError:
            flash("Invalid date format. Use YYYY-MM-DD", "warning")

    records = query.order_by(AttendanceRecord.date.desc()).all()

    return render_template('records.html',
                           records=records,
                           filters={
                               'student_id': student_id_filter,
                               'student_name': student_name_filter,
                               'date': date_filter
                           })

@app.route('/teacher/logout')
def teacher_logout():
    session.clear()
    return redirect(url_for('teacher_login'))

@app.route('/view_qrcode')
def view_qrcode():
    if 'teacher_id' not in session or 'qr_code' not in session:
        return redirect(url_for('teacher_login'))
    return render_template('view_qrcode.html')

# Updated Export Function with Filters
@app.route('/teacher/export')
def export_records():
    if 'teacher_id' not in session:
        return redirect(url_for('teacher_login'))

    # Get the same filters as view_records
    student_id_filter = request.args.get('student_id', '').strip()
    student_name_filter = request.args.get('student_name', '').strip()
    date_filter = request.args.get('date', '').strip()

    # Base query
    query = AttendanceRecord.query.join(AttendanceSession) \
        .filter(AttendanceSession.teacher_id == session['teacher_id'])

    # Apply the same filters as the view
    if student_id_filter:
        query = query.filter(AttendanceRecord.student_id.contains(student_id_filter))
    if student_name_filter:
        query = query.filter(AttendanceRecord.student_name.contains(student_name_filter))
    if date_filter:
        try:
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(AttendanceRecord.date == filter_date)
        except ValueError:
            flash("Invalid date format. Use YYYY-MM-DD", "warning")
            return redirect(url_for('view_records'))

    records = query.order_by(AttendanceRecord.date.desc()).all()

    # Create DataFrame
    data = {
        'Name': [r.student_name for r in records],
        'ID': [r.student_id for r in records],
        'Date': [r.date.strftime('%Y-%m-%d') for r in records],
        'IP Address': [r.ip_address for r in records],
        'Session Code': [AttendanceSession.query.get(r.session_id).session_code for r in records]
    }
    df = pd.DataFrame(data)

    # Create Excel file in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Attendance')

    output.seek(0)
    response = make_response(output.read())
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    response.headers[
        'Content-Disposition'] = f'attachment; filename=attendance_filtered_{datetime.now().strftime("%Y%m%d")}.xlsx'

    return response


# Student Routes
@app.route('/reg/<session_code>', methods=['GET', 'POST'])
def student_reg(session_code):
    session_data = AttendanceSession.query.filter_by(session_code=session_code).first()

    if not session_data or not session_data.is_active:
        return render_template('session_expired.html')

    if request.method == 'POST':
        ip = request.remote_addr
        today = datetime.now().date()

        # existing = AttendanceRecord.query.filter_by(
        #     ip_address=ip,
        #     date=today ,
        # ).first()

        existing = AttendanceRecord.query.join(AttendanceSession).filter(
            (AttendanceRecord.ip_address == ip) ,
            AttendanceRecord.date == today,
            AttendanceSession.teacher_id == session_data.teacher_id
        ).first()


        if existing:
            return render_template('error.html',
                                message=f"Attendance already registered from this device today by: {existing.student_name} (ID: {existing.student_id})",
                                existing_record=existing)

        new_record = AttendanceRecord(
            student_name=request.form['name'].strip(),
            student_id=request.form['student_id'].strip(),
            date=today,
            ip_address=ip,
            session_id=session_data.id
        )

        db.session.add(new_record)
        db.session.commit()
        return render_template('success.html')

    return render_template('student_form.html', session_code=session_code)


# CLI Commands
@app.cli.command("init-db")
def init_db_command():
    """Initialize the database."""
    with app.app_context():
        db.drop_all()
        db.create_all()



    print("Initialized the database with default admin account.")


@app.cli.command("create-teacher")
def create_teacher():
    """Create a new teacher account interactively."""
    try:
        username = input("Enter username: ").strip()
        if not username:
            raise ValueError("Username cannot be empty")

        if Teacher.query.filter_by(username=username).first():
            raise ValueError("Username already exists")

        password = getpass.getpass("Enter password: ")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters")

        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            raise ValueError("Passwords don't match")

        with app.app_context():
            new_teacher = Teacher(
                username=username,
                password=hashlib.sha256(password.encode()).hexdigest()
            )
            db.session.add(new_teacher)
            db.session.commit()

        print(f"✅ Successfully created teacher: {username}")

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        db.session.rollback()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)