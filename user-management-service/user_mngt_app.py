import sqlite3
import logging
import os
import uuid
import re
from datetime import datetime
from flask import Flask, request, jsonify
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from dotenv import load_dotenv

# --- Configuration & Setup ---

load_dotenv()
APP_NAME = "user_mngt_service"
DB_NAME_FILE = os.getenv("DB_PATH", "user_mngt_db.sqlite") # Use ENV for flexibility
SECRET_KEY = os.getenv('SECRET_KEY', 'default-fallback-secret-key-change-me')
BASE_API_URL = os.getenv('BASE_API_URL', 'http://127.0.0.1:5000')
CONFIRMATION_EXPIRY_SECONDS = 3600 # 1 hour expiry

app = Flask(APP_NAME)
app.config['SECRET_KEY'] = SECRET_KEY

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# 2. Status Code Constants (Avoid hardcoding)
STATUS_OK = 200
STATUS_CREATED = 201
STATUS_ACCEPTED = 202
STATUS_BAD_REQUEST = 400
STATUS_UNAUTHORIZED = 401
STATUS_FORBIDDEN = 403
STATUS_SERVER_ERROR = 500

# 3. Logging Setup (Debug Mode)
if os.getenv('FLASK_ENV') == 'development':
    app.config['DEBUG'] = True
    logging.basicConfig(level=logging.DEBUG, 
                        format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    app.logger.setLevel(logging.DEBUG)
    app.logger.debug(f"Application running in DEBUG mode. Database: {DB_NAME_FILE}")
else:
    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)

# --- Database Initialization and Helpers ---

def get_user_mngt_db():
    """Establishes a connection to the SQLite database."""
    try:
        conn = sqlite3.connect(DB_NAME_FILE)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        app.logger.error(f"Database connection error: {e}")
        return None

def user_mngt_init_db():
    """Initializes the database schema (V2: 2 tables). No dropping of tables."""
    conn = get_user_mngt_db()
    if not conn: return
    
    cursor = conn.cursor()
    # Table 1: Users (V2 Schema with all profile fields)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_mngt_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE CHECK(LENGTH(email) BETWEEN 5 AND 25),
            password TEXT NOT NULL CHECK(LENGTH(password) = 6),
            confirmation_token TEXT UNIQUE,
            is_confirmed INTEGER NOT NULL DEFAULT 0,
            first_name TEXT,
            last_name TEXT,
            address1 TEXT,
            address2 TEXT,
            city TEXT,
            state TEXT,
            country TEXT,
            pin_code TEXT,
            contact_country_code TEXT,
            contact_number TEXT,
            created_at TEXT NOT NULL
        )
    """)
    # Table 2: Sessions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_mngt_sessions (
            session_key TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user_mngt_users(id)
        )
    """)
    conn.commit()
    conn.close()
    app.logger.info("Database schema initialized for user_mngt_users and user_mngt_sessions.")

# Initialize DB on application startup
with app.app_context():
    # Ensure the directory exists if we use the 'data/' prefix
    db_dir = os.path.dirname(DB_NAME_FILE)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
    user_mngt_init_db()

# --- Validation Functions ---

def validate_registration_data(email, password):
    """Performs validation based on SRS for V1 fields."""
    errors = {}
    if not (5 <= len(email) <= 25):
        errors['email'] = "Email must be between 5 and 25 characters."
    if len(password) != 6:
        errors['password'] = "Password must be exactly 6 characters."
    return errors

def validate_profile_data(data, is_mandatory_check=False):
    """Performs validation for V2 profile fields."""
    errors = {}
    
    fields = [
        ('first_name', True, lambda v: re.fullmatch(r'[a-zA-Z]{5,25}', v)),
        ('last_name', True, lambda v: re.fullmatch(r'[a-zA-Z]{5,25}', v)),
        ('address1', False, lambda v: 5 <= len(v) <= 25),
        ('address2', False, lambda v: 5 <= len(v) <= 25),
        ('city', False, lambda v: 5 <= len(v) <= 25),
        ('state', False, lambda v: 5 <= len(v) <= 25),
        ('country', True, lambda v: 5 <= len(v) <= 25),
        ('pin_code', True, lambda v: 5 <= len(v) <= 25),
        ('contact_country_code', True, lambda v: re.fullmatch(r'\d{3}', v)), # Exactly 3 digits
        ('contact_number', True, lambda v: re.fullmatch(r'\d{10}', v)),    # Exactly 10 digits
    ]
    
    for field, mandatory, rule in fields:
        value = data.get(field)
        if mandatory and is_mandatory_check and not value:
            errors[field] = f"{field} is mandatory."
        elif value:
            if not rule(value):
                errors[field] = f"Invalid format or length for {field}."
    
    return errors

# --- Authentication and Session Utilities ---

def check_session(email, session_key):
    """Authenticates the user and session."""
    conn = get_user_mngt_db()
    if not conn: return None, {"message": "Database connection error."}, STATUS_SERVER_ERROR
    
    cursor = conn.cursor()
    # Join users and sessions tables to validate key and activity
    cursor.execute("""
        SELECT u.id, s.is_active FROM user_mngt_users u
        JOIN user_mngt_sessions s ON u.id = s.user_id
        WHERE u.email = ? AND s.session_key = ?
    """, (email, session_key))
    
    record = cursor.fetchone()
    conn.close()
    
    if not record:
        app.logger.warning(f"Session check failed: Invalid key or email for {email}")
        return None, {"message": "Invalid email or session key."}, STATUS_UNAUTHORIZED
    
    if record['is_active'] == 0:
        app.logger.warning(f"Session check failed: Session is inactive for {email}")
        return None, {"message": "Session is inactive. Please login again."}, STATUS_UNAUTHORIZED
        
    return record['id'], None, None # Returns user_id, error_data, status

# --- API Endpoints ---

@app.route('/version', methods=['GET'])
def user_mngt_get_version():
    """API-001: Returns the system version (V2)."""
    return jsonify({
        "version": "2.0.0",
        "service": APP_NAME
    }), STATUS_OK

# API-002 and API-003 (Registration and Confirmation) remain largely the same, 
# ensuring they initialize profile fields to NULLs in V2.

@app.route('/register', methods=['POST'])
def user_mngt_register():
    """API-002: Registers a new user (pre-confirmation) with V2 fields as NULL."""
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    validation_errors = validate_registration_data(email, password)
    if validation_errors:
        return jsonify({"message": "Invalid input format.", "errors": validation_errors}), STATUS_BAD_REQUEST

    conn = get_user_mngt_db()
    if not conn: return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM user_mngt_users WHERE email = ?", (email,))
        if cursor.fetchone():
            return jsonify({"message": "User with this email already exists."}), STATUS_BAD_REQUEST

        confirmation_token = serializer.dumps(email, salt='email-confirm-salt')
        confirmation_link = f"{BASE_API_URL}/confirm_registration/{confirmation_token}"
        
        # Insert user record with required V1 fields and NULLs for V2 fields
        # Note: The first_name/last_name fields are NOT NULL in final schema, 
        # but they are set to temporary placeholders here until first login/update.
        # REAL WORLD NOTE: V2 registration should require all mandatory fields. 
        # Following SRS, setting placeholders for NOT NULL fields.
        cursor.execute(
            """INSERT INTO user_mngt_users (email, password, confirmation_token, is_confirmed,
            first_name, last_name, country, pin_code, contact_country_code, contact_number, created_at)
            VALUES (?, ?, ?, 0, 'temp', 'temp', 'temp', 'temp', '000', '0000000000', DATETIME('now'))""",
            (email, password, confirmation_token)
        )
        conn.commit()
        app.logger.info(f"User registered successfully (pending confirmation): {email}")

        return jsonify({
            "message": "Registration successful, please click the confirmation link.",
            "confirmation_link": confirmation_link
        }), STATUS_CREATED

    except sqlite3.Error as e:
        app.logger.error(f"DB error during registration for {email}: {e}")
        return jsonify({"message": "Internal server error during registration."}), STATUS_SERVER_ERROR
    finally:
        conn.close()

@app.route('/confirm_registration/<token>', methods=['GET'])
def user_mngt_confirm_registration(token):
    """API-003: Completes user registration."""
    conn = get_user_mngt_db()
    if not conn: return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR

    try:
        try:
            email = serializer.loads(token, salt='email-confirm-salt', max_age=CONFIRMATION_EXPIRY_SECONDS)
        except (SignatureExpired, BadTimeSignature):
            return jsonify({"message": "Invalid or expired confirmation token."}), STATUS_FORBIDDEN
            
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_mngt_users SET is_confirmed = 1, confirmation_token = NULL WHERE email = ? AND is_confirmed = 0",
            (email,)
        )
        conn.commit()
        
        if cursor.rowcount == 0:
            # Check if user is already confirmed or token invalid
            cursor.execute("SELECT is_confirmed FROM user_mngt_users WHERE email = ?", (email,))
            user_record = cursor.fetchone()
            if user_record and user_record['is_confirmed'] == 1:
                return jsonify({"message": "Registration successfully confirmed. You can now login."}), STATUS_OK
            else:
                 return jsonify({"message": "Invalid or expired confirmation token."}), STATUS_FORBIDDEN

        app.logger.info(f"User confirmed registration successfully: {email}")
        return jsonify({"message": "Registration successfully confirmed. You can now login."}), STATUS_OK

    except sqlite3.Error as e:
        app.logger.error(f"DB error during confirmation for token {token}: {e}")
        return jsonify({"message": "Internal server error during confirmation."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


@app.route('/login', methods=['POST'])
def user_mngt_login():
    """API-004: Authenticates user and generates session key (V2 Update)."""
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({"message": "Email and password are required."}), STATUS_BAD_REQUEST

    conn = get_user_mngt_db()
    if not conn: return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, is_confirmed FROM user_mngt_users WHERE email = ?", (email,))
        user_record = cursor.fetchone()

        if not user_record or user_record['password'] != password:
            return jsonify({"message": "Invalid email or password."}), STATUS_UNAUTHORIZED

        if user_record['is_confirmed'] == 0:
            return jsonify({"message": "Account not confirmed. Please check your email."}), STATUS_FORBIDDEN

        # Generate and store Session Key
        user_id = user_record['id']
        session_key = str(uuid.uuid4())
        
        # Insert new active session
        cursor.execute(
            "INSERT INTO user_mngt_sessions (session_key, user_id, is_active, created_at) VALUES (?, ?, 1, DATETIME('now'))",
            (session_key, user_id)
        )
        conn.commit()
        app.logger.info(f"User logged in and session created: {email}, Key: {session_key}")

        return jsonify({
            "message": "Login successful.",
            "user_id": user_id,
            "session_key": session_key
        }), STATUS_OK

    except sqlite3.Error as e:
        app.logger.error(f"DB error during login for {email}: {e}")
        return jsonify({"message": "Internal server error during login."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


@app.route('/logout', methods=['POST'])
def user_mngt_logout():
    """API-005: Deactivates the user session."""
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    session_key = data.get('session_key')

    if not email or not session_key:
        return jsonify({"message": "Email and session_key are required."}), STATUS_BAD_REQUEST

    user_id, error_data, status = check_session(email, session_key)
    if error_data:
        return jsonify(error_data), status
        
    conn = get_user_mngt_db()
    if not conn: return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_mngt_sessions SET is_active = 0 WHERE session_key = ? AND user_id = ?",
            (session_key, user_id)
        )
        conn.commit()
        app.logger.info(f"User logged out and session deactivated: {email}")

        return jsonify({"message": "Logout successful."}), STATUS_OK

    except sqlite3.Error as e:
        app.logger.error(f"DB error during logout for {email}: {e}")
        return jsonify({"message": "Internal server error during logout."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


@app.route('/user_mngt_user', methods=['GET'])
def user_mngt_get_user():
    """API-006: Retrieves user details."""
    email = request.args.get('email', '').strip()
    session_key = request.args.get('session_key')

    if not email or not session_key:
        return jsonify({"message": "Email and session_key are required query parameters."}), STATUS_BAD_REQUEST

    user_id, error_data, status = check_session(email, session_key)
    if error_data:
        return jsonify(error_data), status
        
    conn = get_user_mngt_db()
    if not conn: return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR
    
    try:
        cursor = conn.cursor()
        # Retrieve all user details (excluding password and token)
        cursor.execute("""
            SELECT email, first_name, last_name, address1, address2, city, state, country, pin_code, contact_country_code, contact_number
            FROM user_mngt_users WHERE id = ?
        """, (user_id,))
        
        user_data = cursor.fetchone()
        
        return jsonify(dict(user_data)), STATUS_OK

    except sqlite3.Error as e:
        app.logger.error(f"DB error getting user details for {email}: {e}")
        return jsonify({"message": "Internal server error."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


@app.route('/user_mngt_user', methods=['PUT'])
def user_mngt_update_user():
    """API-007: Updates user details."""
    email = request.args.get('email', '').strip()
    session_key = request.args.get('session_key')
    data = request.get_json() or {}

    if not email or not session_key:
        return jsonify({"message": "Email and session_key are required query parameters."}), STATUS_BAD_REQUEST

    user_id, error_data, status = check_session(email, session_key)
    if error_data:
        return jsonify(error_data), status
        
    # Mandatory check for all V2 profile fields
    validation_errors = validate_profile_data(data, is_mandatory_check=True)
    if validation_errors:
        return jsonify({"message": "Invalid input format or missing mandatory fields.", "errors": validation_errors}), STATUS_BAD_REQUEST

    # Check that email field is not in the update body (per SRS)
    if 'email' in data:
        app.logger.warning(f"Attempt to change email blocked for user {email}")
        return jsonify({"message": "Email field cannot be changed."}), STATUS_BAD_REQUEST

    conn = get_user_mngt_db()
    if not conn: return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR
    
    try:
        # Prepare the update statement dynamically
        set_clause = ", ".join([f"{k} = ?" for k in data.keys()])
        update_values = list(data.values())
        update_values.append(user_id)
        
        cursor = conn.cursor()
        cursor.execute(f"""
            UPDATE user_mngt_users SET {set_clause} WHERE id = ?
        """, update_values)
        
        conn.commit()
        app.logger.info(f"User details updated for {email}")

        return jsonify({"message": "User details successfully updated."}), STATUS_OK

    except sqlite3.Error as e:
        app.logger.error(f"DB error updating user details for {email}: {e}")
        return jsonify({"message": "Internal server error."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


@app.route('/user_mngt_user', methods=['DELETE'])
def user_mngt_delete_user():
    """API-008: Deletes user and all related sessions."""
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')
    session_key = data.get('session_key')

    if not email or not password or not session_key:
        return jsonify({"message": "Email, password, and session_key are required."}), STATUS_BAD_REQUEST

    # 1. Check Session
    user_id, error_data, status = check_session(email, session_key)
    if error_data:
        return jsonify(error_data), status
        
    conn = get_user_mngt_db()
    if not conn: return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR

    try:
        cursor = conn.cursor()
        # 2. Re-authenticate password
        cursor.execute("SELECT password FROM user_mngt_users WHERE id = ?", (user_id,))
        record = cursor.fetchone()
        
        if record['password'] != password:
            return jsonify({"message": "Invalid password."}), STATUS_UNAUTHORIZED
            
        # 3. Delete related sessions
        cursor.execute("DELETE FROM user_mngt_sessions WHERE user_id = ?", (user_id,))
        
        # 4. Delete user record
        cursor.execute("DELETE FROM user_mngt_users WHERE id = ?", (user_id,))
        
        conn.commit()
        app.logger.info(f"User and all sessions deleted for {email}")

        return jsonify({"message": "User account successfully deleted."}), STATUS_OK

    except sqlite3.Error as e:
        app.logger.error(f"DB error deleting user {email}: {e}")
        return jsonify({"message": "Internal server error."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


@app.route('/forget_password', methods=['PUT'])
def user_mngt_forget_password():
    """API-009: Updates user password (requires active session)."""
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    new_password = data.get('new_password', '')
    confirm_new_password = data.get('confirm_new_password', '')
    session_key = data.get('session_key')

    if not email or not new_password or not confirm_new_password or not session_key:
        return jsonify({"message": "All fields are required."}), STATUS_BAD_REQUEST

    # 1. Check Session
    user_id, error_data, status = check_session(email, session_key)
    if error_data:
        return jsonify(error_data), status

    # 2. Validate password rules
    if new_password != confirm_new_password:
        return jsonify({"message": "New password and confirm password do not match."}), STATUS_BAD_REQUEST
    if len(new_password) != 6:
        return jsonify({"message": "New password must be exactly 6 characters."}), STATUS_BAD_REQUEST

    conn = get_user_mngt_db()
    if not conn: return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_mngt_users SET password = ? WHERE id = ?",
            (new_password, user_id)
        )
        conn.commit()
        app.logger.info(f"Password updated for {email}")

        return jsonify({"message": "Password successfully updated."}), STATUS_OK

    except sqlite3.Error as e:
        app.logger.error(f"DB error updating password for {email}: {e}")
        return jsonify({"message": "Internal server error."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


@app.route('/resend_registration_link', methods=['POST'])
def user_mngt_resend_link():
    """API-010: Resends confirmation link if account is unconfirmed."""
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({"message": "Email and password are required."}), STATUS_BAD_REQUEST

    conn = get_user_mngt_db()
    if not conn: return jsonify({"message": "Service unavailable due to database error."}), STATUS_SERVER_ERROR

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, is_confirmed FROM user_mngt_users WHERE email = ?", (email,))
        user_record = cursor.fetchone()

        if not user_record or user_record['password'] != password:
            return jsonify({"message": "Invalid email or password."}), STATUS_UNAUTHORIZED
            
        if user_record['is_confirmed'] == 1:
            return jsonify({"message": "Account is already confirmed."}), STATUS_BAD_REQUEST

        # Generate a NEW token and link
        new_token = serializer.dumps(email, salt='email-confirm-salt')
        confirmation_link = f"{BASE_API_URL}/confirm_registration/{new_token}"
        
        # Update the database with the new token
        cursor.execute(
            "UPDATE user_mngt_users SET confirmation_token = ? WHERE id = ?",
            (new_token, user_record['id'])
        )
        conn.commit()
        
        app.logger.info(f"New registration link sent for unconfirmed user: {email}")

        return jsonify({
            "message": "New registration link generated.",
            "confirmation_link": confirmation_link
        }), STATUS_OK

    except sqlite3.Error as e:
        app.logger.error(f"DB error resending link for {email}: {e}")
        return jsonify({"message": "Internal server error."}), STATUS_SERVER_ERROR
    finally:
        conn.close()


if __name__ == '__main__':
    # Running directly will use the settings in the environment or defaults
    app.run(host='0.0.0.0', port=5000, debug=True)