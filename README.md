﻿# QR Attendance University 

## Description
The QR Attendance System is a web application built using Flask and SQLAlchemy for tracking student attendance. Teachers can generate unique session codes, share them as QR codes, and students can register their attendance by scanning the QR code. The system maintains attendance records and allows teachers to manage sessions, view records, and export data.

## Features
- **Teacher Login**: Teachers can securely log in to their account to manage attendance sessions.
- **QR Code Generation**: Teachers can generate QR codes for session registration.
- **Attendance Recording**: Students can register attendance by scanning the generated QR code.
- **Session Management**: Teachers can start, stop, and view attendance sessions.
- **Attendance Records**: Teachers can filter and view attendance records for each session.
- **Export Data**: Attendance data can be exported as an Excel file with filters for specific records.

## Technologies Used
- **Flask**: A lightweight web framework for Python.
- **SQLAlchemy**: ORM for interacting with the SQLite database.
- **QRCode**: Library to generate QR codes for attendance session registration.
- **Pandas**: For exporting attendance data into Excel files.
- **SQLite**: Used as the database for storing teacher, session, and attendance records.
- **HTML, CSS**: For the frontend, utilizing Flask templates.

## Setup and Installation

1. Clone the repository:
   ```
   git clone https://github.com/motaha1/QRAttendance.git
   ```

2. Navigate into the project directory:
   ```
   cd QRAttendance
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Initialize the database:
   ```
   flask init-db
   ```

5. To create a new teacher account:
   ```
   flask create-teacher
   ```

6. Run the Flask application:
   ```
   flask run
   ```

## Endpoints

- **/teacher**: Teacher login page.
- **/teacher/dashboard**: Teacher dashboard showing active sessions and QR code generation.
- **/teacher/generate_qr**: Generates a QR code for session registration.
- **/teacher/stop_session**: Stops the current active session.
- **/teacher/records**: View attendance records with filtering options.
- **/teacher/export**: Export attendance records to an Excel file.
- **/reg/<session_code>**: Student registration page for marking attendance using the session code.

## Database Models

### Teacher
- `id`: Primary key for the teacher.
- `username`: Teacher's username (unique).
- `password`: Teacher's password (hashed).

### AttendanceSession
- `id`: Primary key for the attendance session.
- `teacher_id`: Foreign key referencing the Teacher model.
- `session_code`: Unique code for the session.
- `is_active`: Whether the session is active or not.
- `start_time`: Time the session started.
- `end_time`: Time the session ended.

### AttendanceRecord
- `id`: Primary key for the attendance record.
- `student_name`: Name of the student.
- `student_id`: ID of the student.
- `date`: Date of the attendance.
- `ip_address`: IP address from which the attendance was recorded.
- `session_id`: Foreign key referencing the AttendanceSession model.

## Commands
- **init-db**: Initializes the database by creating all tables.
- **create-teacher**: Interactively creates a new teacher account.

## Usage

- Teachers can log in to the system, generate session codes, and manage attendance.
- Students can register their attendance by entering their name, student ID, and scanning the session's QR code.
- Teachers can view records, filter them, and export the data as an Excel file.
