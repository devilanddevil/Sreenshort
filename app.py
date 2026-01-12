import os
import re
import datetime
import sqlite3
import csv
import io
from flask import Flask, render_template, request, redirect, url_for, flash, Response, abort
import pytesseract
from PIL import Image
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask App
app = Flask(__name__)
app.secret_key = 'super_secret_key_for_flash_messages'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['Db_PATH'] = 'idle_tracker.db'

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure Tesseract Path
tesseract_paths = [
    r'C:\Program Files\Tesseract-OCR\tesseract.exe',
    os.path.join(os.environ.get('LOCALAPPDATA', ''), r'Tesseract-OCR\tesseract.exe'),
    r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe'
]

tesseract_cmd = None
for path in tesseract_paths:
    if os.path.exists(path):
        tesseract_cmd = path
        break

if tesseract_cmd:
    pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
    print(f"Using Tesseract at: {tesseract_cmd}")
else:
    print("Tesseract not found in common paths. Relying on system PATH.")

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def init_db():
    conn = sqlite3.connect(app.config['Db_PATH'])
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            filename TEXT,
            idle_minutes INTEGER,
            original_text TEXT,
            reason TEXT
        )
    ''')
    
    # Create Users Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0
        )
    ''')

    # Simple migration: try to add 'reason' column if it doesn't exist
    try:
        c.execute("ALTER TABLE records ADD COLUMN reason TEXT")
    except sqlite3.OperationalError:
        pass # Column likely already exists

    # Migration: records.user_id
    try:
        c.execute("ALTER TABLE records ADD COLUMN user_id INTEGER REFERENCES users(id)")
    except sqlite3.OperationalError:
        pass
        
    conn.commit()
    conn.close()

# User Model
class User(UserMixin):
    def __init__(self, id, username, password_hash, is_admin=False):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = bool(is_admin) # Ensure boolean
        
    @staticmethod
    def get(user_id):
        conn = sqlite3.connect(app.config['Db_PATH'])
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_data = c.fetchone()
        conn.close()
        if user_data:
            return User(id=user_data[0], username=user_data[1], password_hash=user_data[2], is_admin=user_data[3])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

init_db()

from PIL import Image, ImageOps

# ... (imports stay same)

def parse_idle_time(text):
    print(f"DEBUG OCR TEXT:\n{text}\n----------------") # Debug print
    
    # Regex patterns
    # 1. "You were idle for: 13m"
    # 2. "Not Working - 8m" (allowing for spaces, different dashes, case insensitivity)
    patterns = [
        r'idle for:?\s*.*?((\d+\s*h\s*)?(\d+\s*m))',
        r'Not Working\s*[-–—]?\s*.*?((\d+\s*h\s*)?(\d+\s*m))'
    ]
    
    time_str = None
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            time_str = match.group(1).lower()
            print(f"DEBUG MATCHED: {time_str}")
            break
            
    if time_str:
        hours = 0
        minutes = 0
        
        h_match = re.search(r'(\d+)\s*h', time_str)
        if h_match:
            hours = int(h_match.group(1))
            
        m_match = re.search(r'(\d+)\s*m', time_str)
        if m_match:
            minutes = int(m_match.group(1))
            
        total_minutes = (hours * 60) + minutes
        if total_minutes > 0:
            return total_minutes, time_str.strip()
    
    return 0, "No time detected"

def get_stats(page=1, per_page=5, user_id=None):
    if not user_id:
        return {'today': 0, 'month': 0, 'recent': {'records': [], 'page': 1, 'per_page': 5, 'total_pages': 0, 'total_count': 0}}

    conn = sqlite3.connect(app.config['Db_PATH'])
    c = conn.cursor()
    
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    current_month = datetime.datetime.now().strftime('%Y-%m')
    
    # Today's Total
    c.execute("SELECT SUM(idle_minutes) FROM records WHERE date(timestamp) = ? AND user_id = ?", (today, user_id))
    result = c.fetchone()
    today_minutes = result[0] if result[0] else 0
    
    # Month's Total
    c.execute("SELECT SUM(idle_minutes) FROM records WHERE strftime('%Y-%m', timestamp) = ? AND user_id = ?", (current_month, user_id))
    result = c.fetchone()
    month_minutes = result[0] if result[0] else 0
    
    # Pagination for Recent History
    offset = (page - 1) * per_page
    
    # Get Total Count
    c.execute("SELECT COUNT(*) FROM records WHERE user_id = ?", (user_id,))
    total_count = c.fetchone()[0]
    total_pages = (total_count + per_page - 1) // per_page
    
    # Recent History (Paginated)
    c.execute("SELECT id, timestamp, filename, idle_minutes, original_text, reason FROM records WHERE user_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?", (user_id, per_page, offset))
    recent_records = c.fetchall()
    
    conn.close()
    
    return {
        'today': today_minutes,
        'month': month_minutes,
        'recent': {
            'records': recent_records,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'total_count': total_count
        }
    }

def format_minutes(total_minutes):
    if total_minutes is None:
        return "0m"
    h = total_minutes // 60
    m = total_minutes % 60
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"

app.jinja_env.filters['format_minutes'] = format_minutes

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(app.config['Db_PATH'])
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = c.fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[2], password):
            user = User(id=user_data[0], username=user_data[1], password_hash=user_data[2], is_admin=user_data[3])
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
            
        conn = sqlite3.connect(app.config['Db_PATH'])
        c = conn.cursor()
        
        # Check if username exists
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            flash('Username already exists', 'error')
            conn.close()
            return redirect(url_for('register'))
            
        # Check if this is the FIRST user (to make Admin)
        c.execute("SELECT COUNT(*) FROM users")
        user_count = c.fetchone()[0]
        is_admin = (user_count == 0)
        
        hashed_pw = generate_password_hash(password)
        
        try:
            c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", 
                      (username, hashed_pw, is_admin))
            new_user_id = c.lastrowid
            
            # MIGRATION: Assign ALL existing 'orphan' records to this new user (only if it's the first user)
            if is_admin:
                c.execute("UPDATE records SET user_id = ? WHERE user_id IS NULL", (new_user_id,))
                
            conn.commit()
            
            # Auto login
            user = User(id=new_user_id, username=username, password_hash=hashed_pw, is_admin=is_admin)
            login_user(user)
            
            flash('Account created successfully!', 'success')
            if is_admin:
                flash('You are the first user and have been granted ADMIN privileges.', 'info')
                
            return redirect(url_for('index'))
            
        except sqlite3.Error as e:
            flash(f'Database error: {e}', 'error')
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # Dashboard always shows top 5 recent, no pagination, filtered by current_user
    stats = get_stats(page=1, per_page=5, user_id=current_user.id)
    return render_template('index.html', stats=stats)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    manual_minutes = request.form.get('manual_minutes')
    reason = request.form.get('reason', '')
    
    # CASE 1: Manual Entry
    if manual_minutes:
        try:
            minutes = int(manual_minutes)
            if minutes > 0:
                conn = sqlite3.connect(app.config['Db_PATH'])
                c = conn.cursor()
                filename = 'manual_entry' # Placeholder
                detected_text = "Manual Entry"
                
                current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                c.execute("INSERT INTO records (filename, idle_minutes, original_text, reason, user_id, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                          (filename, minutes, detected_text, reason, current_user.id, current_time))
                conn.commit()
                conn.close()
                flash(f'Success! Manually logged {format_minutes(minutes)}.', 'success')
            else:
                flash('Minutes must be positive.', 'error')
        except ValueError:
            flash('Invalid minutes value.', 'error')
        return redirect(url_for('index'))

    # CASE 2: File Upload
    if 'screenshot' not in request.files:
        flash('No file part and no manual minutes provided.')
        return redirect(request.url)
    
    file = request.files['screenshot']
    
    if file.filename == '' and not manual_minutes:
        flash('No selected file and no manual minutes.')
        return redirect(request.url)
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Preprocessing for better OCR
            base_img = Image.open(filepath)
            
            # Strategy 1: Grayscale + PSM 3 (Standard)
            img_gray = base_img.convert('L')
            text = pytesseract.image_to_string(img_gray)
            minutes, detected_text = parse_idle_time(text)
            
            # Strategy 2: Grayscale + PSM 6 (Assume uniform block)
            if minutes == 0:
                print("Strategy 1 failed. Trying PSM 6...")
                text = pytesseract.image_to_string(img_gray, config='--psm 6')
                minutes, detected_text = parse_idle_time(text)

            # Strategy 3: Thresholding + PSM 6
            if minutes == 0:
                print("Strategy 2 failed. Trying Thresholding...")
                # Threshold: anything lighter than 128 becomes white, else black
                # Note: If text is black on white bg, this works well.
                try:
                    threshold = 150
                    img_thresh = img_gray.point(lambda p: p > threshold and 255)
                    text = pytesseract.image_to_string(img_thresh, config='--psm 6')
                    minutes, detected_text = parse_idle_time(text)
                except Exception as e:
                    print(f"Strategy 3 error: {e}")
            
            # Strategy 4: Invert + Threshold (for dark mode support if needed)
            if minutes == 0:
                 print("Strategy 3 failed. Trying Inverted Thresholding...")
                 try:
                     img_invert = ImageOps.invert(base_img.convert('RGB')) # Invert colors
                     img_invert_gray = img_invert.convert('L')
                     text = pytesseract.image_to_string(img_invert_gray, config='--psm 6')
                     minutes, detected_text = parse_idle_time(text)
                 except Exception as e:
                     print(f"Strategy 4 error: {e}")


            if minutes > 0:
                conn = sqlite3.connect(app.config['Db_PATH'])
                c = conn.cursor()
                current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                c.execute("INSERT INTO records (filename, idle_minutes, original_text, reason, user_id, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                          (filename, minutes, detected_text, reason, current_user.id, current_time))
                conn.commit()
                conn.close()
                flash(f'Success! Logged {format_minutes(minutes)} of idle time.', 'success')
            else:
                # Capture the last text attempted for debugging
                flash(f'Could not detect idle time. OCR Text: "{text.strip()[:100]}..."', 'error')
                
        except Exception as e:
            flash(f'Error processing image: {str(e)}', 'error')
            
        return redirect(url_for('index'))

import openpyxl
from openpyxl.styles import Font
from flask import send_file

# ... imports ...

@app.route('/history')
@login_required
def history():
    month_filter = request.args.get('month')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 5, type=int)
    
    if per_page > 100: per_page = 100
    if per_page < 1: per_page = 5
        
    offset = (page - 1) * per_page
    
    # Determine which user's data to show
    target_user_id = current_user.id
    target_username = current_user.username
    
    if current_user.is_admin and request.args.get('user_id'):
        target_user_id = request.args.get('user_id', type=int)
        # Fetch username for display
        target_user = User.get(target_user_id)
        if target_user:
            target_username = target_user.username
    
    conn = sqlite3.connect(app.config['Db_PATH'])
    c = conn.cursor()
    
    # Get available months (Filtered by Target User)
    c.execute("SELECT DISTINCT strftime('%Y-%m', timestamp) FROM records WHERE user_id = ? ORDER BY timestamp DESC", (target_user_id,))
    available_months = [row[0] for row in c.fetchall()]
    
    # Build Query
    base_query = "FROM records WHERE user_id = ? "
    params = [target_user_id]
    
    if month_filter:
        base_query += "AND strftime('%Y-%m', timestamp) = ? "
        params.append(month_filter)
        
    # Get Total Count
    c.execute(f"SELECT COUNT(*) {base_query}", tuple(params))
    total_count = c.fetchone()[0]
    total_pages = (total_count + per_page - 1) // per_page
    
    # Get Records
    query = f"SELECT id, timestamp, filename, idle_minutes, original_text, reason {base_query} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    
    c.execute(query, tuple(params))
    records = c.fetchall()
    
    # Calculate Total Minutes
    sum_query = f"SELECT SUM(idle_minutes) {base_query}"
    c.execute(sum_query, tuple(params[:-2])) 
    result = c.fetchone()
    total_minutes = result[0] if result[0] else 0
    
    conn.close()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('ajax') == '1':
        return render_template('partials/table_content.html', 
                               records=records,
                               page=page,
                               per_page=per_page,
                               total_pages=total_pages,
                               endpoint='history',
                               current_month=month_filter,
                               target_user_id=target_user_id)
    
    return render_template('history.html', 
                           records=records, 
                           available_months=available_months, 
                           current_month=month_filter, 
                           total_minutes=total_minutes,
                           page=page,
                           per_page=per_page,
                           total_pages=total_pages,
                           target_username=target_username if target_user_id != current_user.id else None,
                           target_user_id=target_user_id,
                           endpoint='history')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
        
    conn = sqlite3.connect(app.config['Db_PATH'])
    c = conn.cursor()
    c.execute("""
        SELECT u.id, u.username, u.is_admin, 
               COALESCE(SUM(r.idle_minutes), 0) as total_minutes,
               COUNT(r.id) as total_records
        FROM users u
        LEFT JOIN records r ON u.id = r.user_id
        GROUP BY u.id
    """)
    users = c.fetchall()
    conn.close()
    
    return render_template('admin.html', users=users)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
        
    if user_id == current_user.id:
        flash('You cannot delete your own account!', 'error')
        return redirect(url_for('admin'))
        
    conn = sqlite3.connect(app.config['Db_PATH'])
    c = conn.cursor()
    
    try:
        # First, delete all records associated with this user
        c.execute("DELETE FROM records WHERE user_id = ?", (user_id,))
        
        # Then delete the user
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        flash('User and all associated data deleted successfully.', 'success')
    except sqlite3.Error as e:
        flash(f'Error deleting user: {e}', 'error')
    finally:
        conn.close()
        
    return redirect(url_for('admin'))

@app.route('/admin/reset_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def reset_password(user_id):
    if not current_user.is_admin:
        abort(403)
        
    conn = sqlite3.connect(app.config['Db_PATH'])
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        flash('User not found.', 'error')
        return redirect(url_for('admin'))
        
    username = result[0]
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_pw = generate_password_hash(new_password)
        
        conn = sqlite3.connect(app.config['Db_PATH'])
        c = conn.cursor()
        c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_pw, user_id))
        conn.commit()
        conn.close()
        
        flash(f'Password for {username} reset successfully.', 'success')
        return redirect(url_for('admin'))
        
    return render_template('reset_password.html', user_id=user_id, username=username)

@app.route('/export_excel')
@login_required
def export_excel():
    conn = sqlite3.connect(app.config['Db_PATH'])
    c = conn.cursor()
    c.execute("SELECT id, timestamp, filename, idle_minutes, original_text, reason FROM records WHERE user_id = ? ORDER BY timestamp DESC", (current_user.id,))
    records = c.fetchall()
    conn.close()
    
    # ... (Excel generation code same as before) ...
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Idle Time Report"
    
    # Headers
    headers = ['ID', 'Date', 'Idle Time', 'Reason', 'Detected Text', 'Screenshot Link']
    ws.append(headers)
    
    # Style headers
    for cell in ws[1]:
        cell.font = Font(bold=True)
        
    for row in records:
        record_id = row[0]
        timestamp = row[1]
        filename = row[2]
        idle_minutes = row[3]
        original_text = row[4]
        reason = row[5]
        
        # Calculate readable time
        h = idle_minutes // 60
        m = idle_minutes % 60
        readable_time = f"{h}h {m}m" if h > 0 else f"{m}m"
        
        abs_path = os.path.abspath(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        ws.append([record_id, timestamp, readable_time, reason, original_text])
        
        current_row = ws.max_row
        cell = ws.cell(row=current_row, column=6)
        cell.value = "View Screenshot"
        cell.hyperlink = abs_path
        cell.style = "Hyperlink"
        
    ws.column_dimensions['B'].width = 20
    ws.column_dimensions['C'].width = 15
    ws.column_dimensions['D'].width = 25
    ws.column_dimensions['E'].width = 40
    ws.column_dimensions['F'].width = 20
    
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='idle_time_report.xlsx'
    )

@app.route('/delete/<int:record_id>', methods=['POST'])
@login_required
def delete_record(record_id):
    conn = sqlite3.connect(app.config['Db_PATH'])
    c = conn.cursor()
    # Ensure user owns the record
    c.execute("DELETE FROM records WHERE id = ? AND user_id = ?", (record_id, current_user.id))
    conn.commit()
    conn.close()
    flash('Record deleted.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
