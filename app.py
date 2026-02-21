from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime, timedelta, date
from functools import wraps
import sqlite3
import csv
from io import StringIO
from flask import make_response
import os
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # More secure random key

# Email configuration (Update with your email settings)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your-app-password'      # Replace with your app password
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

mail = Mail(app)

# Serializer for token generation
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Flask-Login setup
# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Database helper functions
def get_db():
    conn = sqlite3.connect('fleet_management.db')
    conn.row_factory = sqlite3.Row
    return conn

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email, role, name, active=True):
        self.id = id
        self.email = email
        self.role = role
        self.name = name
        self._active = active
    
    @property
    def is_active(self):
        """Return True if the user is active."""
        return self._active
    
    @is_active.setter
    def is_active(self, value):
        """Set the active status."""
        self._active = value
    
    def get_id(self):
        """Return the user ID as a string."""
        return str(self.id)

# 👇 YOUR CODE GOES HERE - RIGHT AFTER THE USER CLASS
@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        is_active = user['is_active'] if 'is_active' in user.keys() and user['is_active'] else True
        return User(user['id'], user['email'], user['role'], user['name'], is_active)
    return None

# The rest of your routes continue below...# Role-based access control decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            if current_user.role not in roles:
                flash(f'Access denied. You need {", ".join(roles)} privileges to view this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Initialize database with more users for different roles
def init_db():
    conn = get_db()
    
    # Create users table with all necessary fields
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            reset_token TEXT,
            reset_token_expiry TIMESTAMP,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Check if last_login column exists (for existing databases)
    try:
        # Try to add last_login column if it doesn't exist
        conn.execute('ALTER TABLE users ADD COLUMN last_login TIMESTAMP')
    except sqlite3.OperationalError:
        # Column already exists
        pass
    
    try:
        # Try to add reset_token column if it doesn't exist
        conn.execute('ALTER TABLE users ADD COLUMN reset_token TEXT')
    except sqlite3.OperationalError:
        pass
    
    try:
        # Try to add reset_token_expiry column if it doesn't exist
        conn.execute('ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP')
    except sqlite3.OperationalError:
        pass
    
    try:
        # Try to add is_active column if it doesn't exist
        conn.execute('ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1')
    except sqlite3.OperationalError:
        pass
    
    # Create vehicles table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            model TEXT NOT NULL,
            license_plate TEXT UNIQUE NOT NULL,
            max_capacity REAL NOT NULL,
            odometer INTEGER DEFAULT 0,
            acquisition_cost REAL DEFAULT 0,
            status TEXT DEFAULT 'Available',
            type TEXT NOT NULL,
            region TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create drivers table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS drivers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            license_number TEXT UNIQUE NOT NULL,
            license_expiry DATE NOT NULL,
            phone TEXT,
            status TEXT DEFAULT 'On Duty',
            safety_score INTEGER DEFAULT 100,
            trips_completed INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create trips table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS trips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_id INTEGER NOT NULL,
            driver_id INTEGER NOT NULL,
            cargo_weight REAL NOT NULL,
            cargo_description TEXT,
            origin TEXT NOT NULL,
            destination TEXT NOT NULL,
            distance REAL,
            status TEXT DEFAULT 'Draft',
            revenue REAL DEFAULT 0,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vehicle_id) REFERENCES vehicles (id),
            FOREIGN KEY (driver_id) REFERENCES drivers (id)
        )
    ''')
    
    # Create maintenance logs table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS maintenance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_id INTEGER NOT NULL,
            service_date DATE NOT NULL,
            service_type TEXT NOT NULL,
            description TEXT,
            cost REAL NOT NULL,
            vendor TEXT,
            next_service_date DATE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vehicle_id) REFERENCES vehicles (id)
        )
    ''')
    
    # Create fuel logs table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS fuel_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_id INTEGER NOT NULL,
            trip_id INTEGER,
            liters REAL NOT NULL,
            cost REAL NOT NULL,
            odometer INTEGER NOT NULL,
            fuel_date DATE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vehicle_id) REFERENCES vehicles (id),
            FOREIGN KEY (trip_id) REFERENCES trips (id)
        )
    ''')
    
    # Create expenses table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_id INTEGER NOT NULL,
            trip_id INTEGER,
            expense_type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            expense_date DATE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vehicle_id) REFERENCES vehicles (id),
            FOREIGN KEY (trip_id) REFERENCES trips (id)
        )
    ''')
    
    # Insert default users for each role if not exists
    users_data = [
        ('Admin User', 'admin@fleet.com', generate_password_hash('admin123', method='pbkdf2:sha256'), 'Manager'),
        ('John Dispatcher', 'dispatcher@fleet.com', generate_password_hash('dispatch123', method='pbkdf2:sha256'), 'Dispatcher'),
        ('Sarah Safety', 'safety@fleet.com', generate_password_hash('safety123', method='pbkdf2:sha256'), 'Safety Officer'),
        ('Mike Finance', 'finance@fleet.com', generate_password_hash('finance123', method='pbkdf2:sha256'), 'Financial Analyst')
    ]
    
    for name, email, password, role in users_data:
        existing = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if not existing:
            conn.execute('''
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, ?)
            ''', (name, email, password, role))
    
    # Insert sample data for testing
    sample_vehicles = conn.execute('SELECT COUNT(*) as count FROM vehicles').fetchone()
    if sample_vehicles['count'] == 0:
        vehicles_data = [
            ('Truck A', 'Volvo FH16', 'ABC-123', 20000, 150000, 150000, 'Available', 'Truck', 'North'),
            ('Van B', 'Mercedes Sprinter', 'XYZ-789', 3500, 75000, 45000, 'On Trip', 'Van', 'South'),
            ('Bike C', 'Honda CB150', 'DEF-456', 150, 15000, 8000, 'In Shop', 'Bike', 'East')
        ]
        conn.executemany('''
            INSERT INTO vehicles (name, model, license_plate, max_capacity, odometer, acquisition_cost, status, type, region)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', vehicles_data)
    
    sample_drivers = conn.execute('SELECT COUNT(*) as count FROM drivers').fetchone()
    if sample_drivers['count'] == 0:
        drivers_data = [
            ('John Smith', 'DL123456', '2025-12-31', '555-0101', 'On Duty', 95, 150),
            ('Sarah Johnson', 'DL789012', '2024-06-30', '555-0102', 'On Duty', 98, 200),
            ('Mike Brown', 'DL345678', '2023-12-31', '555-0103', 'Suspended', 75, 50)
        ]
        conn.executemany('''
            INSERT INTO drivers (name, license_number, license_expiry, phone, status, safety_score, trips_completed)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', drivers_data)
    
    conn.commit()
    conn.close()
# Add custom Jinja2 filters
@app.template_filter('days_until')
def days_until_filter(date_str):
    """Calculate days until a given date"""
    if not date_str:
        return None
    try:
        if isinstance(date_str, str):
            target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            target_date = date_str
        today = date.today()
        delta = target_date - today
        return delta.days
    except (ValueError, TypeError):
        return None

@app.template_filter('format_date')
def format_date_filter(date_str, format='%Y-%m-%d'):
    """Format date string safely"""
    if not date_str:
        return 'N/A'
    try:
        if isinstance(date_str, str):
            dt = datetime.strptime(date_str, '%Y-%m-%d')
        else:
            dt = date_str
        return dt.strftime(format)
    except (ValueError, TypeError):
        return date_str

@app.context_processor
def utility_processor():
    """Add utility functions to template context"""
    def get_today():
        return date.today().isoformat()
    
    def is_expired(expiry_date):
        """Check if a date is expired"""
        if not expiry_date:
            return False
        try:
            if isinstance(expiry_date, str):
                expiry = datetime.strptime(expiry_date, '%Y-%m-%d').date()
            else:
                expiry = expiry_date
            return expiry < date.today()
        except (ValueError, TypeError):
            return False
    
    def days_until(expiry_date):
        """Calculate days until expiry"""
        if not expiry_date:
            return None
        try:
            if isinstance(expiry_date, str):
                expiry = datetime.strptime(expiry_date, '%Y-%m-%d').date()
            else:
                expiry = expiry_date
            delta = expiry - date.today()
            return delta.days
        except (ValueError, TypeError):
            return None
    
    return dict(
        today=get_today,
        is_expired=is_expired,
        days_until=days_until,
        now=date.today().isoformat()
    )

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('home'))

@app.route('/home')
@app.route('/index')
def home():
    """Public home page / landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = True if request.form.get('remember') else False
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            # Update last login if column exists
            try:
                conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
                conn.commit()
            except sqlite3.OperationalError:
                pass
            
            # Get is_active value from database or default to True
            is_active = user['is_active'] if 'is_active' in user.keys() and user['is_active'] else True
            
            user_obj = User(user['id'], user['email'], user['role'], user['name'], is_active)
            login_user(user_obj, remember=remember)
            session['user_role'] = user['role']
            session['user_name'] = user['name']
            
            flash(f'Welcome back, {user["name"]}! You are logged in as {user["role"]}.', 'success')
            
            # Role-based redirect
            if user['role'] == 'Manager':
                return redirect(url_for('dashboard'))
            elif user['role'] == 'Dispatcher':
                return redirect(url_for('trips'))
            elif user['role'] == 'Safety Officer':
                return redirect(url_for('drivers'))
            elif user['role'] == 'Financial Analyst':
                return redirect(url_for('reports'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
        
        conn.close()
    
    return render_template('login.html')
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # Generate reset token
            token = serializer.dumps(email, salt='password-reset-salt')
            
            # Store token in database with expiry (24 hours)
            expiry = datetime.now() + timedelta(hours=24)
            conn.execute('''
                UPDATE users 
                SET reset_token = ?, reset_token_expiry = ? 
                WHERE email = ?
            ''', (token, expiry, email))
            conn.commit()
            
            # Create reset link
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Send email
            try:
                msg = Message('Password Reset Request - FleetMaster Pro',
                            recipients=[email])
                msg.body = f'''Dear {user['name']},

You have requested to reset your password for your FleetMaster Pro account.

Please click the following link to reset your password:
{reset_url}

This link will expire in 24 hours.

If you did not request this password reset, please ignore this email or contact support.

Best regards,
FleetMaster Pro Team
'''
                msg.html = f'''
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; background: #f9f9f9; }}
        .button {{ display: inline-block; padding: 12px 30px; background: #3498db; color: white; text-decoration: none; border-radius: 25px; margin: 20px 0; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>FleetMaster Pro</h2>
        </div>
        <div class="content">
            <h3>Password Reset Request</h3>
            <p>Dear {user['name']},</p>
            <p>You have requested to reset your password for your FleetMaster Pro account.</p>
            <p>Click the button below to reset your password:</p>
            <p style="text-align: center;">
                <a href="{reset_url}" class="button">Reset Password</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all;"><small>{reset_url}</small></p>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you did not request this password reset, please ignore this email or contact support.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>FleetMaster Pro Team</p>
        </div>
    </div>
</body>
</html>
'''
                mail.send(msg)
                flash('Password reset instructions have been sent to your email.', 'success')
            except Exception as e:
                flash('Error sending email. Please try again later.', 'danger')
                print(f"Email error: {e}")
        else:
            # Don't reveal if email exists or not for security
            flash('If your email is registered, you will receive password reset instructions.', 'info')
        
        conn.close()
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    try:
        # Verify token (expires after 24 hours)
        email = serializer.loads(token, salt='password-reset-salt', max_age=86400)
    except SignatureExpired:
        flash('The password reset link has expired. Please request a new one.', 'warning')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid password reset link. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('reset_password.html', token=token)
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND reset_token = ?', 
                          (email, token)).fetchone()
        
        if user:
            # Update password and clear reset token
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            conn.execute('''
                UPDATE users 
                SET password = ?, reset_token = NULL, reset_token_expiry = NULL 
                WHERE email = ?
            ''', (hashed_password, email))
            conn.commit()
            flash('Your password has been successfully reset. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid reset request. Please try again.', 'danger')
        
        conn.close()
    
    return render_template('reset_password.html', token=token)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
    conn.close()
    return render_template('profile.html', user=user)

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
    
    if not check_password_hash(user['password'], current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('profile'))
    
    if len(new_password) < 6:
        flash('Password must be at least 6 characters long.', 'danger')
        return redirect(url_for('profile'))
    
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, current_user.id))
    conn.commit()
    conn.close()
    
    flash('Your password has been successfully changed.', 'success')
    return redirect(url_for('profile'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    
    # Get KPIs
    active_fleet = conn.execute('SELECT COUNT(*) as count FROM vehicles WHERE status = "On Trip"').fetchone()['count']
    in_shop = conn.execute('SELECT COUNT(*) as count FROM vehicles WHERE status = "In Shop"').fetchone()['count']
    total_vehicles = conn.execute('SELECT COUNT(*) as count FROM vehicles WHERE status != "Retired"').fetchone()['count']
    pending_cargo = conn.execute('SELECT COUNT(*) as count FROM trips WHERE status = "Draft"').fetchone()['count']
    
    # Calculate utilization rate
    utilization_rate = 0
    if total_vehicles > 0:
        utilization_rate = round((active_fleet / total_vehicles) * 100, 1)
    
    # Get recent trips based on role
    if current_user.role == 'Dispatcher':
        # Dispatchers see all trips
        recent_trips = conn.execute('''
            SELECT t.*, v.name as vehicle_name, d.name as driver_name 
            FROM trips t
            JOIN vehicles v ON t.vehicle_id = v.id
            JOIN drivers d ON t.driver_id = d.id
            ORDER BY t.created_at DESC LIMIT 5
        ''').fetchall()
    else:
        # Others see limited view
        recent_trips = conn.execute('''
            SELECT t.*, v.name as vehicle_name, d.name as driver_name 
            FROM trips t
            JOIN vehicles v ON t.vehicle_id = v.id
            JOIN drivers d ON t.driver_id = d.id
            ORDER BY t.created_at DESC LIMIT 5
        ''').fetchall()
    
    # Get maintenance alerts
    maintenance_alerts = conn.execute('''
        SELECT v.name, v.license_plate, m.service_type, m.next_service_date
        FROM maintenance m
        JOIN vehicles v ON m.vehicle_id = v.id
        WHERE m.next_service_date IS NOT NULL 
        AND m.next_service_date <= date('now', '+7 days')
        ORDER BY m.next_service_date ASC
    ''').fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         active_fleet=active_fleet,
                         in_shop=in_shop,
                         utilization_rate=utilization_rate,
                         pending_cargo=pending_cargo,
                         recent_trips=recent_trips,
                         maintenance_alerts=maintenance_alerts)

# Vehicle Management
@app.route('/vehicles')
@login_required
@role_required('Manager', 'Dispatcher', 'Safety Officer', 'Financial Analyst')
def vehicles():
    conn = get_db()
    vehicles = conn.execute('SELECT * FROM vehicles ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('vehicles.html', vehicles=vehicles)

@app.route('/vehicles/add', methods=['POST'])
@login_required
@role_required('Manager')
def add_vehicle():
    if request.method == 'POST':
        name = request.form['name']
        model = request.form['model']
        license_plate = request.form['license_plate']
        max_capacity = request.form['max_capacity']
        odometer = request.form['odometer']
        acquisition_cost = request.form['acquisition_cost']
        vehicle_type = request.form['type']
        region = request.form['region']
        
        conn = get_db()
        try:
            conn.execute('''
                INSERT INTO vehicles (name, model, license_plate, max_capacity, odometer, acquisition_cost, type, region)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, model, license_plate, max_capacity, odometer, acquisition_cost, vehicle_type, region))
            conn.commit()
            flash('Vehicle added successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('License plate already exists!', 'danger')
        finally:
            conn.close()
    
    return redirect(url_for('vehicles'))

@app.route('/vehicles/update/<int:vehicle_id>', methods=['POST'])
@login_required
@role_required('Manager')
def update_vehicle(vehicle_id):
    if request.method == 'POST':
        status = request.form['status']
        
        conn = get_db()
        conn.execute('UPDATE vehicles SET status = ? WHERE id = ?', (status, vehicle_id))
        conn.commit()
        conn.close()
        
        flash('Vehicle updated successfully!', 'success')
    
    return redirect(url_for('vehicles'))

@app.route('/vehicles/delete/<int:vehicle_id>')
@login_required
@role_required('Manager')
def delete_vehicle(vehicle_id):
    conn = get_db()
    conn.execute('DELETE FROM vehicles WHERE id = ?', (vehicle_id,))
    conn.commit()
    conn.close()
    
    flash('Vehicle deleted successfully!', 'success')
    return redirect(url_for('vehicles'))

# Trip Management
@app.route('/trips')
@login_required
@role_required('Manager', 'Dispatcher')
def trips():
    conn = get_db()
    
    # Get available vehicles and drivers for the form
    available_vehicles = conn.execute('''
        SELECT * FROM vehicles 
        WHERE status = 'Available' OR status = 'On Trip'
    ''').fetchall()
    
    available_drivers = conn.execute('''
        SELECT * FROM drivers 
        WHERE status = 'On Duty' AND license_expiry > date('now')
    ''').fetchall()
    
    # Get all trips
    trips = conn.execute('''
        SELECT t.*, v.name as vehicle_name, v.max_capacity, d.name as driver_name 
        FROM trips t
        JOIN vehicles v ON t.vehicle_id = v.id
        JOIN drivers d ON t.driver_id = d.id
        ORDER BY t.created_at DESC
    ''').fetchall()
    
    conn.close()
    
    return render_template('trips.html', 
                         trips=trips, 
                         vehicles=available_vehicles, 
                         drivers=available_drivers)

@app.route('/trips/add', methods=['POST'])
@login_required
@role_required('Manager', 'Dispatcher')
def add_trip():
    if request.method == 'POST':
        vehicle_id = request.form['vehicle_id']
        driver_id = request.form['driver_id']
        cargo_weight = float(request.form['cargo_weight'])
        cargo_description = request.form['cargo_description']
        origin = request.form['origin']
        destination = request.form['destination']
        distance = request.form['distance']
        revenue = request.form['revenue']
        
        conn = get_db()
        
        # Check vehicle capacity
        vehicle = conn.execute('SELECT max_capacity FROM vehicles WHERE id = ?', (vehicle_id,)).fetchone()
        
        if cargo_weight > vehicle['max_capacity']:
            flash(f'Error: Cargo weight exceeds vehicle capacity by {cargo_weight - vehicle["max_capacity"]} kg', 'danger')
        else:
            try:
                # Create trip
                conn.execute('''
                    INSERT INTO trips (vehicle_id, driver_id, cargo_weight, cargo_description, 
                                      origin, destination, distance, revenue, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (vehicle_id, driver_id, cargo_weight, cargo_description, origin, destination, 
                      distance, revenue, 'Draft'))
                
                # Update vehicle status
                conn.execute('UPDATE vehicles SET status = "On Trip" WHERE id = ?', (vehicle_id,))
                
                conn.commit()
                flash('Trip created successfully!', 'success')
            except Exception as e:
                flash(f'Error creating trip: {str(e)}', 'danger')
            finally:
                conn.close()
    
    return redirect(url_for('trips'))

@app.route('/trips/update_status/<int:trip_id>', methods=['POST'])
@login_required
@role_required('Manager', 'Dispatcher')
def update_trip_status(trip_id):
    if request.method == 'POST':
        status = request.form['status']
        
        conn = get_db()
        
        if status == 'Completed':
            # Update trip end time
            conn.execute('''
                UPDATE trips 
                SET status = ?, end_time = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (status, trip_id))
            
            # Get vehicle_id for this trip
            trip = conn.execute('SELECT vehicle_id FROM trips WHERE id = ?', (trip_id,)).fetchone()
            
            # Update vehicle status back to available
            conn.execute('UPDATE vehicles SET status = "Available" WHERE id = ?', (trip['vehicle_id'],))
            
            # Update driver trip count
            driver = conn.execute('SELECT driver_id FROM trips WHERE id = ?', (trip_id,)).fetchone()
            conn.execute('UPDATE drivers SET trips_completed = trips_completed + 1 WHERE id = ?', (driver['driver_id'],))
        else:
            conn.execute('UPDATE trips SET status = ? WHERE id = ?', (status, trip_id))
        
        conn.commit()
        conn.close()
        
        flash(f'Trip status updated to {status}!', 'success')
    
    return redirect(url_for('trips'))

# Maintenance Management
@app.route('/maintenance')
@login_required
@role_required('Manager', 'Safety Officer')
def maintenance():
    conn = get_db()
    
    vehicles = conn.execute('SELECT * FROM vehicles WHERE status != "Retired"').fetchall()
    
    maintenance_logs = conn.execute('''
        SELECT m.*, v.name as vehicle_name, v.license_plate 
        FROM maintenance m
        JOIN vehicles v ON m.vehicle_id = v.id
        ORDER BY m.service_date DESC
    ''').fetchall()
    
    conn.close()
    
    return render_template('maintenance.html', vehicles=vehicles, maintenance_logs=maintenance_logs)

@app.route('/maintenance/add', methods=['POST'])
@login_required
@role_required('Manager', 'Safety Officer')
def add_maintenance():
    if request.method == 'POST':
        vehicle_id = request.form['vehicle_id']
        service_date = request.form['service_date']
        service_type = request.form['service_type']
        description = request.form['description']
        cost = request.form['cost']
        vendor = request.form['vendor']
        next_service_date = request.form['next_service_date']
        
        conn = get_db()
        
        try:
            # Add maintenance log
            conn.execute('''
                INSERT INTO maintenance (vehicle_id, service_date, service_type, description, cost, vendor, next_service_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (vehicle_id, service_date, service_type, description, cost, vendor, next_service_date))
            
            # Update vehicle status to In Shop
            conn.execute('UPDATE vehicles SET status = "In Shop" WHERE id = ?', (vehicle_id,))
            
            conn.commit()
            flash('Maintenance log added successfully!', 'success')
        except Exception as e:
            flash(f'Error adding maintenance log: {str(e)}', 'danger')
        finally:
            conn.close()
    
    return redirect(url_for('maintenance'))

@app.route('/maintenance/complete/<int:maintenance_id>', methods=['POST'])
@login_required
@role_required('Manager', 'Safety Officer')
def complete_maintenance(maintenance_id):
    if request.method == 'POST':
        vehicle_id = request.form['vehicle_id']
        
        conn = get_db()
        
        # Update vehicle status back to available
        conn.execute('UPDATE vehicles SET status = "Available" WHERE id = ?', (vehicle_id,))
        
        conn.commit()
        conn.close()
        
        flash('Maintenance completed, vehicle is now available!', 'success')
    
    return redirect(url_for('maintenance'))

# Expenses and Fuel Logging
@app.route('/expenses')
@login_required
@role_required('Manager', 'Financial Analyst')
def expenses():
    conn = get_db()
    
    vehicles = conn.execute('SELECT * FROM vehicles').fetchall()
    active_trips = conn.execute('SELECT id, cargo_description FROM trips WHERE status != "Completed"').fetchall()
    
    fuel_logs = conn.execute('''
        SELECT f.*, v.name as vehicle_name, v.license_plate, t.cargo_description as trip_desc
        FROM fuel_logs f
        JOIN vehicles v ON f.vehicle_id = v.id
        LEFT JOIN trips t ON f.trip_id = t.id
        ORDER BY f.fuel_date DESC
    ''').fetchall()
    
    expense_logs = conn.execute('''
        SELECT e.*, v.name as vehicle_name, v.license_plate, t.cargo_description as trip_desc
        FROM expenses e
        JOIN vehicles v ON e.vehicle_id = v.id
        LEFT JOIN trips t ON e.trip_id = t.id
        ORDER BY e.expense_date DESC
    ''').fetchall()
    
    # Calculate total operational cost per vehicle
    operational_costs = conn.execute('''
        SELECT 
            v.id,
            v.name,
            v.license_plate,
            COALESCE(SUM(f.cost), 0) as total_fuel_cost,
            COALESCE(SUM(m.cost), 0) as total_maintenance_cost,
            COALESCE(SUM(e.amount), 0) as total_other_expenses
        FROM vehicles v
        LEFT JOIN fuel_logs f ON v.id = f.vehicle_id
        LEFT JOIN maintenance m ON v.id = m.vehicle_id
        LEFT JOIN expenses e ON v.id = e.vehicle_id
        GROUP BY v.id
    ''').fetchall()
    
    conn.close()
    
    return render_template('expenses.html', 
                         vehicles=vehicles,
                         active_trips=active_trips,
                         fuel_logs=fuel_logs,
                         expense_logs=expense_logs,
                         operational_costs=operational_costs)

@app.route('/expenses/add_fuel', methods=['POST'])
@login_required
@role_required('Manager', 'Financial Analyst')
def add_fuel():
    if request.method == 'POST':
        vehicle_id = request.form['vehicle_id']
        trip_id = request.form.get('trip_id')
        liters = request.form['liters']
        cost = request.form['cost']
        odometer = request.form['odometer']
        fuel_date = request.form['fuel_date']
        
        conn = get_db()
        
        try:
            conn.execute('''
                INSERT INTO fuel_logs (vehicle_id, trip_id, liters, cost, odometer, fuel_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (vehicle_id, trip_id if trip_id else None, liters, cost, odometer, fuel_date))
            
            # Update vehicle odometer
            conn.execute('UPDATE vehicles SET odometer = ? WHERE id = ?', (odometer, vehicle_id))
            
            conn.commit()
            flash('Fuel log added successfully!', 'success')
        except Exception as e:
            flash(f'Error adding fuel log: {str(e)}', 'danger')
        finally:
            conn.close()
    
    return redirect(url_for('expenses'))

@app.route('/expenses/add_expense', methods=['POST'])
@login_required
@role_required('Manager', 'Financial Analyst')
def add_expense():
    if request.method == 'POST':
        vehicle_id = request.form['vehicle_id']
        trip_id = request.form.get('trip_id')
        expense_type = request.form['expense_type']
        amount = request.form['amount']
        description = request.form['description']
        expense_date = request.form['expense_date']
        
        conn = get_db()
        
        try:
            conn.execute('''
                INSERT INTO expenses (vehicle_id, trip_id, expense_type, amount, description, expense_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (vehicle_id, trip_id if trip_id else None, expense_type, amount, description, expense_date))
            
            conn.commit()
            flash('Expense added successfully!', 'success')
        except Exception as e:
            flash(f'Error adding expense: {str(e)}', 'danger')
        finally:
            conn.close()
    
    return redirect(url_for('expenses'))

# Driver Management
@app.route('/drivers')
@login_required
@role_required('Manager', 'Safety Officer')
def drivers():
    conn = get_db()
    
    drivers = conn.execute('SELECT * FROM drivers ORDER BY created_at DESC').fetchall()
    
    conn.close()
    
    return render_template('drivers.html', drivers=drivers)

@app.route('/drivers/add', methods=['POST'])
@login_required
@role_required('Manager', 'Safety Officer')
def add_driver():
    if request.method == 'POST':
        name = request.form['name']
        license_number = request.form['license_number']
        license_expiry = request.form['license_expiry']
        phone = request.form['phone']
        
        conn = get_db()
        
        try:
            conn.execute('''
                INSERT INTO drivers (name, license_number, license_expiry, phone)
                VALUES (?, ?, ?, ?)
            ''', (name, license_number, license_expiry, phone))
            
            conn.commit()
            flash('Driver added successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('License number already exists!', 'danger')
        finally:
            conn.close()
    
    return redirect(url_for('drivers'))

@app.route('/drivers/update_status/<int:driver_id>', methods=['POST'])
@login_required
@role_required('Manager', 'Safety Officer')
def update_driver_status(driver_id):
    if request.method == 'POST':
        status = request.form['status']
        
        conn = get_db()
        conn.execute('UPDATE drivers SET status = ? WHERE id = ?', (status, driver_id))
        conn.commit()
        conn.close()
        
        flash('Driver status updated successfully!', 'success')
    
    return redirect(url_for('drivers'))

# Reports
@app.route('/reports')
@login_required
@role_required('Manager', 'Financial Analyst')
def reports():
    conn = get_db()
    
    # Fuel efficiency report
    fuel_efficiency = conn.execute('''
        SELECT 
            v.id,
            v.name,
            v.license_plate,
            COALESCE(SUM(f.liters), 0) as total_fuel,
            COALESCE(MAX(f.odometer) - MIN(f.odometer), 0) as distance_traveled,
            CASE 
                WHEN COALESCE(SUM(f.liters), 0) > 0 
                THEN ROUND((COALESCE(MAX(f.odometer) - MIN(f.odometer), 0) * 1.0 / SUM(f.liters)), 2)
                ELSE 0 
            END as fuel_efficiency
        FROM vehicles v
        LEFT JOIN fuel_logs f ON v.id = f.vehicle_id
        GROUP BY v.id
    ''').fetchall()
    
    # Vehicle ROI calculation
    vehicle_roi = conn.execute('''
        SELECT 
            v.id,
            v.name,
            v.license_plate,
            v.acquisition_cost,
            COALESCE(SUM(t.revenue), 0) as total_revenue,
            COALESCE(SUM(f.cost), 0) as total_fuel_cost,
            COALESCE(SUM(m.cost), 0) as total_maintenance_cost,
            COALESCE(SUM(e.amount), 0) as total_expenses,
            CASE 
                WHEN v.acquisition_cost > 0 
                THEN ROUND(((COALESCE(SUM(t.revenue), 0) - (COALESCE(SUM(f.cost), 0) + COALESCE(SUM(m.cost), 0) + COALESCE(SUM(e.amount), 0))) * 100.0 / v.acquisition_cost), 2)
                ELSE 0 
            END as roi_percentage
        FROM vehicles v
        LEFT JOIN trips t ON v.id = t.vehicle_id AND t.status = 'Completed'
        LEFT JOIN fuel_logs f ON v.id = f.vehicle_id
        LEFT JOIN maintenance m ON v.id = m.vehicle_id
        LEFT JOIN expenses e ON v.id = e.vehicle_id
        GROUP BY v.id
    ''').fetchall()
    
    conn.close()
    
    return render_template('reports.html', 
                         fuel_efficiency=fuel_efficiency,
                         vehicle_roi=vehicle_roi)

@app.route('/reports/export/<report_type>')
@login_required
@role_required('Manager', 'Financial Analyst')
def export_report(report_type):
    conn = get_db()
    
    if report_type == 'fuel_efficiency':
        data = conn.execute('''
            SELECT 
                v.name as Vehicle,
                v.license_plate as License,
                SUM(f.liters) as Total_Fuel_Liters,
                SUM(f.cost) as Total_Fuel_Cost,
                COUNT(f.id) as Fueling_Events
            FROM vehicles v
            LEFT JOIN fuel_logs f ON v.id = f.vehicle_id
            GROUP BY v.id
        ''').fetchall()
        
        filename = 'fuel_efficiency_report.csv'
    elif report_type == 'maintenance':
        data = conn.execute('''
            SELECT 
                v.name as Vehicle,
                v.license_plate as License,
                m.service_date as Date,
                m.service_type as Type,
                m.description as Description,
                m.cost as Cost,
                m.vendor as Vendor
            FROM maintenance m
            JOIN vehicles v ON m.vehicle_id = v.id
            ORDER BY m.service_date DESC
        ''').fetchall()
        
        filename = 'maintenance_report.csv'
    else:
        data = conn.execute('''
            SELECT 
                v.name as Vehicle,
                v.license_plate as License,
                t.cargo_description as Trip,
                t.revenue as Revenue,
                f.cost as Fuel_Cost,
                m.cost as Maintenance_Cost,
                e.amount as Other_Expenses
            FROM vehicles v
            LEFT JOIN trips t ON v.id = t.vehicle_id
            LEFT JOIN fuel_logs f ON v.id = f.vehicle_id
            LEFT JOIN maintenance m ON v.id = m.vehicle_id
            LEFT JOIN expenses e ON v.id = e.vehicle_id
            WHERE t.status = 'Completed'
        ''').fetchall()
        
        filename = 'financial_report.csv'
    
    conn.close()
    
    # Create CSV
    si = StringIO()
    cw = csv.writer(si)
    
    # Write headers
    if data:
        cw.writerow([description[0] for description in data[0].keys()])
        
        # Write data
        for row in data:
            cw.writerow(row)
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={filename}"
    output.headers["Content-type"] = "text/csv"
    
    return output

if __name__ == '__main__':
    init_db()
    app.run(debug=True)