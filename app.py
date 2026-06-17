from flask import Flask, request, redirect, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ---------------- DATABASE SETUP ----------------
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Login attempt tracking
login_attempts = {}

# ---------------- HOME ----------------
@app.route('/')
def home():
    if 'user' in session:
        return f'''
            <h2>Welcome {session['user']}!</h2>
            <a href="/logout">Logout</a>
        '''
    return '''
        <h2>You are not logged in</h2>
        <a href="/login">Login</a> | <a href="/register">Register</a>
    '''

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, hashed))
            conn.commit()
            conn.close()
            return '''
                <h3>Registration successful!</h3>
                <a href="/login">Go to Login</a>
            '''
        except:
            return "<h3>User already exists!</h3>"

    return '''
        <h2>Register</h2>
        <form method="post">
            <input name="username" placeholder="Username" required><br><br>
            <input name="password" type="password" placeholder="Password" required><br><br>
            <button type="submit">Register</button>
        </form>
    '''

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # lock after 3 attempts
        if username in login_attempts and login_attempts[username] >= 3:
            return "<h3>Account locked due to too many failed attempts</h3>"

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[0]):
            session['user'] = username
            login_attempts[username] = 0
            return redirect('/')
        else:
            login_attempts[username] = login_attempts.get(username, 0) + 1
            return "<h3>Invalid credentials!</h3>"

    return '''
        <h2>Login</h2>
        <form method="post">
            <input name="username" placeholder="Username" required><br><br>
            <input name="password" type="password" placeholder="Password" required><br><br>
            <button type="submit">Login</button>
        </form>
    '''

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

# ---------------- RUN APP ----------------
if __name__ == '__main__':
    app.run(debug=True)