from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'ThisIsAHSecKey'  # Replace with a strong secret key

DATABASE = 'user_credentials.db'

def initialize_database():
    """Initializes the SQLite database if it doesn't exist."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

def validate_password(password):
    """Validates the password based on the given criteria."""
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter.")
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit.")
    return errors

def validate_email(email):
    """Validates the email address using a regular expression."""
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        return "Invalid email address format."
    return None

def get_db_connection():
    """Gets a database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE email=?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            if check_password_hash(user['password'], password):
                return redirect(url_for('success'))
            else:
                flash("Incorrect password.")
        else:
            flash("User not found.")

    return render_template('login.html')

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        errors = []
        if password != confirm_password:
            errors.append("Passwords do not match.")

        password_errors = validate_password(password)
        if password_errors:
            errors.extend(password_errors)

        email_error = validate_email(email)
        if email_error:
            errors.append(email_error)

        if errors:
            for error in errors:
                flash(error)
            return render_template('signup.html')

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("An account with this email address already exists.")
            return render_template('signup.html')

        cursor.execute("INSERT INTO users (first_name, last_name, email, password) VALUES (?,?,?,?)", 
                       (first_name, last_name, email, hashed_password))
        conn.commit()
        conn.close()

        flash("Registration successful. You can now log in.")
        return redirect(url_for('thank_you'))

    return render_template('signup.html')

@app.route('/success')
def success():
    return render_template('secretPage.html')

@app.route('/thank_you')
def thank_you():
    return render_template('thankyou.html')

initialize_database()

if __name__ == '__main__':
    app.run(debug=True)
