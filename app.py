from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
import hashlib
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from difflib import SequenceMatcher
import openai
openai.api_key = 'your-openai-api-key'


# Initialize Flask app
app = Flask(__name__)
app.secret_key = "supersecretkey"  # Required to keep session data secure

# Database connection function
def create_connection():
    conn = sqlite3.connect('project.db')
    return conn

# Helper function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Register user function
def register_user(username, password, role):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password, role, credits) VALUES (?, ?, ?, ?)",
                   (username, hash_password(password), role, 20))  # 20 free credits by default
    conn.commit()
    conn.close()

# Login user function
def login_user(username, password):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hash_password(password)))
    user = cursor.fetchone()
    conn.close()
    return user

# Initialize the users table
# Initialize the database
def init_db():
    conn = create_connection()
    cursor = conn.cursor()

    # Create the users table with a 'credits' column
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        role TEXT NOT NULL,
                        credits INTEGER NOT NULL
                    )''')

    # Create the documents table
    cursor.execute('''CREATE TABLE IF NOT EXISTS documents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        document_name TEXT NOT NULL,
                        document_content TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )''')

    # Create a table for credit requests
    cursor.execute('''CREATE TABLE IF NOT EXISTS credit_requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        credits_requested INTEGER NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending',
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )''')

    conn.commit()
    conn.close()


# Function to reset credits at midnight (daily reset)
def reset_credits():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET credits = 20 WHERE credits < 20")
    conn.commit()
    conn.close()

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        register_user(username, password, role)
        return redirect(url_for('login'))
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = login_user(username, password)
        if user:
            session['username'] = user[1]
            session['role'] = user[3]
            return redirect(url_for('profile'))
        else:
            return "Invalid login credentials"
    return render_template('login.html')

# Profile route
@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch user details from the database, including credits
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT credits FROM users WHERE username=?", (session['username'],))
    credits = cursor.fetchone()[0]
    conn.close()

    if session['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))  # Admin dashboard route

    # Pass the credits to the profile page
    return render_template('profile.html', username=session['username'], role=session['role'], credits=credits)

# Route for users to request credits
@app.route('/request_credits', methods=['GET', 'POST'])
def request_credits():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        credits_requested = int(request.form['credits'])

        # Fetch user ID from the session
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username=?", (session['username'],))
        user_id = cursor.fetchone()[0]

        # Insert the credit request into the database
        cursor.execute("INSERT INTO credit_requests (user_id, credits_requested) VALUES (?, ?)", (user_id, credits_requested))
        conn.commit()
        conn.close()

        flash("Credit request submitted successfully. Please wait for admin approval.")
        return redirect(url_for('profile'))


# Logout route
@app.route('/logout')
def logout():
    # Clear session data
    session.clear()
    return redirect(url_for('home'))

# Admin Dashboard route
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    return render_template('admin_dashboard.html')  # Admin-specific page


@app.route('/admin_dashboard/system_analytics')
def system_analytics():
    if session.get('role') != 'admin':
        return redirect('/')
    # Add logic to fetch system analytics data
    return render_template('system_analytics.html')

# Admin route to view and manage credit requests
# Admin route to view and manage credit requests
@app.route('/manage_credit_requests')
def manage_credit_requests():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = create_connection()
    cursor = conn.cursor()
    
    # Fetch all pending credit requests
    cursor.execute('''SELECT credit_requests.id, users.username, credit_requests.credits_requested
                      FROM credit_requests
                      JOIN users ON credit_requests.user_id = users.id
                      WHERE credit_requests.status = 'pending' ''')
    requests = cursor.fetchall()
    conn.close()

    return render_template('manage_credit_requests.html', requests=requests)

# Admin route to approve or deny credit requests
@app.route('/approve_credit/<int:request_id>/<string:decision>', methods=['POST'])
def approve_credit(request_id, decision):
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = create_connection()
    cursor = conn.cursor()

    # Fetch the request and user ID
    cursor.execute("SELECT user_id, credits_requested FROM credit_requests WHERE id=?", (request_id,))
    request_data = cursor.fetchone()
    user_id = request_data[0]
    credits_requested = request_data[1]

    if decision == 'approve':
        # Update user's credits
        cursor.execute("UPDATE users SET credits = credits + ? WHERE id=?", (credits_requested, user_id))
        cursor.execute("UPDATE credit_requests SET status = 'approved' WHERE id=?", (request_id,))
    else:
        # Deny the request
        cursor.execute("UPDATE credit_requests SET status = 'denied' WHERE id=?", (request_id,))

    conn.commit()
    conn.close()

    return redirect(url_for('manage_credit_requests'))




def update_credits(username, credits_change):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET credits = credits + ? WHERE username = ?", (credits_change, username))
    conn.commit()
    conn.close()

# Function to get current user credits
def get_credits(username):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT credits FROM users WHERE username=?", (username,))
    credits = cursor.fetchone()[0]
    conn.close()
    return credits

def compare_documents_with_openai(doc1, doc2):
    messages = [
        {"role": "system", "content": "You are an expert in comparing documents for similarity."},
        {"role": "user", "content": f"Compare the following two documents and rate their similarity on a scale from 0 to 100. \n\nDocument 1: {doc1}\n\nDocument 2: {doc2}"}
    ]
    
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # You can use "gpt-4" if available
            messages=messages
        )
        similarity_score = response.choices[0].message['content'].strip()
        return float(similarity_score)
    except Exception as e:
        print(f"Error in GPT API: {e}")
        return 0.0

def check_similar_documents_with_gpt(content):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT document_name, document_content FROM documents")
    documents = cursor.fetchall()
    conn.close()

    similar_docs = []
    for doc_name, doc_content in documents:
        similarity = compare_documents_with_openai(content, doc_content)
        if similarity > 50:  # Threshold for similarity, adjust as needed
            similar_docs.append((doc_name, similarity))
    
    return similar_docs

# Route for scanning documents
@app.route('/scan', methods=['POST'])
def scan_document():
    if 'username' not in session:
        return redirect(url_for('login'))

    if 'document' not in request.files:
        return "No file uploaded", 400

    document = request.files['document']
    document_content = document.read().decode('utf-8')  # Assuming text format

    # Fetch user's current credits
    username = session['username']
    credits = get_credits(username)

    if credits <= 0:
        flash("You don't have enough credits to scan a document.")
        return redirect(url_for('profile'))

    # Save document details in the database
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    user_id = cursor.fetchone()[0]

    cursor.execute("INSERT INTO documents (user_id, document_name, document_content) VALUES (?, ?, ?)",
                   (user_id, document.filename, document_content))
    conn.commit()

    # Reduce user's credits by 1
    update_credits(username, -1)

    # Perform AI-powered document matching
    similar_docs = check_similar_documents_with_gpt(document_content)

    return render_template('scan_result.html', similar_docs=similar_docs, credits=credits - 1)



def schedule_credit_reset():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=reset_credits, trigger='cron', hour=0, minute=0)  # Schedule to run at midnight
    scheduler.start()

# Start Flask app and scheduler
if __name__ == '__main__':
    init_db()
    schedule_credit_reset()  # Start the scheduler
    app.run(debug=True)