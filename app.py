from flask import Flask, request, render_template_string, redirect, url_for, send_from_directory
import os
import subprocess
import sqlite3
import logging
from datetime import datetime

app = Flask(__name__, static_folder='static')

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DB_PATH = os.path.join(app.root_path, 'nexus_corp.db')

# Configure SIEM-friendly Log File
LOG_FILE = os.path.join(app.root_path, 'app_access.log')
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

# Initialize SQLite database for Employee Directory / Auth
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT,
            email TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            department TEXT,
            title TEXT,
            email TEXT
        )
    ''')
    # Seed data if empty
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, role, email) VALUES ('admin', 'AdminPass2026!', 'Administrator', 'admin@nexuscorp.local')")
        cursor.execute("INSERT INTO users (username, password, role, email) VALUES ('jdoe', 'Password123', 'Staff Engineer', 'jdoe@nexuscorp.local')")
        
        cursor.execute("INSERT INTO employees (name, department, title, email) VALUES ('Sarah Connor', 'Cybersecurity', 'Lead Security Specialist', 'sconnor@nexuscorp.local')")
        cursor.execute("INSERT INTO employees (name, department, title, email) VALUES ('Alex Mercer', 'Infrastructure', 'Senior DevOps Engineer', 'amercer@nexuscorp.local')")
        cursor.execute("INSERT INTO employees (name, department, title, email) VALUES ('Elena Rostova', 'Data Science', 'AI Research Lead', 'erostova@nexuscorp.local')")
        cursor.execute("INSERT INTO employees (name, department, title, email) VALUES ('Marcus Vance', 'IT Support', 'Systems Administrator', 'mvance@nexuscorp.local')")
        conn.commit()
    conn.close()

init_db()

# In-memory storage for employee community feedback (Stored XSS lab component)
FEEDBACK_ITEMS = [
    {"user": "Sarah C.", "time": "2026-09-06 14:30", "comment": "Great to see the new server monitoring dashboard live!"},
    {"user": "Alex M.", "time": "2026-09-07 09:15", "comment": "Please remember to update your profile avatars before Friday."}
]

# SIEM Middleware for detailed request logging
@app.before_request
def log_request_info():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    method = request.method
    path = request.path
    query_str = request.query_string.decode('utf-8')
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Capture POST body content snippets for SIEM detection of payloads
    body_snippet = ""
    if method in ['POST', 'PUT']:
        if request.form:
            body_snippet = str(dict(request.form))
        elif request.files:
            file_names = [f.filename for f in request.files.values() if f]
            body_snippet = f"FilesUploaded: {file_names}"
            
    log_entry = f"CLIENT_IP={client_ip} | METHOD={method} | PATH={path} | QUERY={query_str} | BODY={body_snippet} | AGENT=\"{user_agent}\""
    logging.info(log_entry)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SIEM LOG: {log_entry}")

# Shared CSS Header layout
BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Enterprise Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0b0f19;
            --bg-card: #151c2c;
            --bg-input: #1e293b;
            --border: #334155;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --accent: #10b981;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --danger: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background: var(--bg-primary); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; }
        
        /* Navbar */
        .navbar { background: #0f172a; border-bottom: 1px solid var(--border); padding: 15px 40px; display: flex; justify-content: space-between; align-items: center; }
        .logo { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.2rem; color: var(--text-main); text-decoration: none; }
        .logo-icon { background: linear-gradient(135deg, #3b82f6, #8b5cf6); width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: bold; }
        .nav-links { display: flex; gap: 25px; align-items: center; }
        .nav-links a { color: var(--text-muted); text-decoration: none; font-size: 0.95rem; font-weight: 500; transition: color 0.2s; }
        .nav-links a:hover, .nav-links a.active { color: var(--primary); }
        .user-badge { display: flex; align-items: center; gap: 10px; background: var(--bg-card); padding: 6px 14px; border-radius: 20px; border: 1px solid var(--border); }
        .avatar-sm { width: 28px; height: 28px; border-radius: 50%; background: var(--primary); display: flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: bold; overflow: hidden; }
        .avatar-sm img { width: 100%; height: 100%; object-fit: cover; }

        /* Container */
        .container { max-width: 1100px; margin: 30px auto; padding: 0 20px; flex: 1; width: 100%; }
        .page-title { font-size: 1.8rem; font-weight: 700; margin-bottom: 8px; }
        .page-desc { color: var(--text-muted); margin-bottom: 30px; font-size: 0.95rem; }

        /* Card grid & components */
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 25px; margin-bottom: 30px; }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .card-title { font-size: 1.1rem; font-weight: 600; color: var(--text-main); }
        
        /* Form controls */
        .form-group { margin-bottom: 18px; }
        label { display: block; margin-bottom: 6px; font-size: 0.85rem; font-weight: 500; color: var(--text-muted); }
        input[type="text"], input[type="password"], input[type="file"], select, textarea {
            width: 100%; background: var(--bg-input); border: 1px solid var(--border); color: var(--text-main);
            padding: 10px 14px; border-radius: 8px; font-size: 0.95rem; outline: none; transition: border 0.2s;
        }
        input:focus, textarea:focus { border-color: var(--primary); }
        button, .btn {
            background: var(--primary); color: white; border: none; padding: 10px 20px; border-radius: 8px;
            font-weight: 600; font-size: 0.95rem; cursor: pointer; transition: background 0.2s; text-decoration: none; display: inline-block;
        }
        button:hover, .btn:hover { background: var(--primary-hover); }

        /* Alert/Status */
        .alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-size: 0.9rem; }
        .alert-success { background: rgba(16, 185, 129, 0.15); border: 1px solid var(--accent); color: var(--accent); }
        .alert-info { background: rgba(59, 130, 246, 0.15); border: 1px solid var(--primary); color: var(--primary); }

        /* Terminal/Pre output */
        .terminal { background: #090d16; border: 1px solid var(--border); border-radius: 8px; padding: 15px; font-family: monospace; color: #38bdf8; overflow-x: auto; white-space: pre-wrap; font-size: 0.85rem; }

        /* Footer */
        footer { background: #0f172a; border-top: 1px solid var(--border); padding: 20px; text-align: center; color: var(--text-muted); font-size: 0.85rem; margin-top: auto; }
    </style>
</head>
<body>
    <div class="navbar">
        <a href="/" class="logo">
            <div class="logo-icon">N</div>
            Nexus Enterprise Portal
        </a>
        <div class="nav-links">
            <a href="/">Dashboard</a>
            <a href="/directory">Directory</a>
            <a href="/search">Knowledge Base</a>
            <a href="/feedback">Community</a>
            <a href="/admin/tools">Admin Tools</a>
            <a href="/profile">Profile</a>
        </div>
        <div class="user-badge">
            <div class="avatar-sm">
                {% if avatar_url %}
                    <img src="{{ avatar_url }}" alt="Avatar">
                {% else %}
                    U
                {% endif %}
            </div>
            <span style="font-size: 0.85rem; font-weight: 500;">User Account</span>
        </div>
    </div>

    <div class="container">
        {% block content %}{% endblock %}
    </div>

    <footer>
        &copy; 2026 Nexus Corp Information Systems | Security Operations & Observability Portal
    </footer>
</body>
</html>
"""

# Route: Main Dashboard
@app.route("/")
def home():
    avatar_filename = request.cookies.get('avatar_file', '')
    avatar_url = f"/static/uploads/{avatar_filename}" if avatar_filename else None
    
    html = BASE_HTML.replace("{% block content %}{% endblock %}", """
        <div class="page-title">Corporate Workspace Dashboard</div>
        <div class="page-desc">Welcome to the Nexus Enterprise Security Operations and Information Portal.</div>

        <div class="grid">
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Employee Directory</span>
                    <span style="color: var(--accent); font-size: 0.8rem;">● Live DB</span>
                </div>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 15px;">Search team members across engineering, IT, and security operations.</p>
                <a href="/directory" class="btn">View Directory</a>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">Knowledge Base</span>
                    <span style="color: var(--primary); font-size: 0.8rem;">Search</span>
                </div>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 15px;">Access internal documentation, security policies, and standard procedures.</p>
                <a href="/search" class="btn">Search Portal</a>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">Community Board</span>
                    <span style="color: var(--accent); font-size: 0.8rem;">Interactive</span>
                </div>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 15px;">Share operational updates, announcements, and team feedback.</p>
                <a href="/feedback" class="btn">Community Feedback</a>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">System Health & Tools</span>
                    <span style="color: var(--danger); font-size: 0.8rem;">Admin Restricted</span>
                </div>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 15px;">Run server diagnostics, network connectivity tests, and uptime checks.</p>
                <a href="/admin/tools" class="btn" style="background: #334155;">Network Utility</a>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">Account Settings</span>
                    <span style="color: var(--text-muted); font-size: 0.8rem;">Profile</span>
                </div>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 15px;">Update your user details and upload custom profile avatar images.</p>
                <a href="/profile" class="btn">Edit Profile</a>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">Portal Login</span>
                    <span style="color: var(--text-muted); font-size: 0.8rem;">Auth</span>
                </div>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 15px;">Sign in to management account with administrator credentials.</p>
                <a href="/login" class="btn">User Login</a>
            </div>
        </div>
    """)
    return render_template_string(html, avatar_url=avatar_url)


# Route 1: Profile Avatar Upload (Concealed File Upload Vulnerability)
@app.route("/profile", methods=["GET", "POST"])
def profile():
    message = ""
    avatar_filename = request.cookies.get('avatar_file', '')
    avatar_url = f"/static/uploads/{avatar_filename}" if avatar_filename else None

    if request.method == "POST":
        file = request.files.get("avatar")
        if file and file.filename != '':
            # INTENTIONAL LAB VULNERABILITY: No extension verification, saved directly into static uploads
            filename = file.filename
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            message = f"Profile avatar successfully updated: static/uploads/{filename}"
            avatar_url = f"/static/uploads/{filename}"
            
            resp = redirect(url_for('profile'))
            resp.set_cookie('avatar_file', filename)
            return resp

    content = f"""
        <div class="page-title">User Account Settings</div>
        <div class="page-desc">Manage your profile details and update your corporate avatar image.</div>

        {'<div class="alert alert-success">' + message + '</div>' if message else ''}

        <div class="card" style="max-width: 600px;">
            <div class="card-title" style="margin-bottom: 20px;">Upload Profile Avatar</div>
            
            <form method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label>Select Avatar Image File (.png, .jpg)</label>
                    <input type="file" name="avatar" required>
                </div>
                <button type="submit">Upload & Save Avatar</button>
            </form>
            
            <div style="margin-top: 25px; padding-top: 20px; border-top: 1px solid var(--border);">
                <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 10px;">Current Avatar Preview:</div>
                <div style="width: 80px; height: 80px; border-radius: 50%; background: var(--bg-input); border: 2px solid var(--primary); display: flex; align-items: center; justify-content: center; overflow: hidden;">
                    {'<img src="' + avatar_url + '" style="width:100%; height:100%; object-fit:cover;">' if avatar_url else '<span style="font-size:1.5rem; font-weight:bold; color:var(--primary);">USER</span>'}
                </div>
            </div>
        </div>
    """
    html = BASE_HTML.replace("{% block content %}{% endblock %}", content)
    return render_template_string(html, avatar_url=avatar_url)


# Route 2: Knowledge Base Search (Concealed Reflected XSS)
@app.route("/search")
def search():
    query = request.args.get("q", "")
    avatar_filename = request.cookies.get('avatar_file', '')
    avatar_url = f"/static/uploads/{avatar_filename}" if avatar_filename else None

    # INTENTIONAL LAB VULNERABILITY: Raw template string interpolation of query (Reflected XSS)
    content = f"""
        <div class="page-title">Internal Knowledge Base</div>
        <div class="page-desc">Search technical articles, security compliance standards, and operating guides.</div>

        <div class="card" style="margin-bottom: 30px;">
            <form method="GET">
                <div style="display: flex; gap: 15px;">
                    <input type="text" name="q" value="{query}" placeholder="Enter keywords (e.g., Firewall, Remote Access, Security)...">
                    <button type="submit">Search</button>
                </div>
            </form>
        </div>

        {f'''
        <div class="card">
            <div style="font-size: 1rem; color: var(--text-muted); margin-bottom: 15px;">
                Search Results for: <strong style="color: var(--text-main);">{query}</strong>
            </div>
            
            <div class="alert alert-info">
                No archived internal documentation matched your search query "{query}". Please try different keywords.
            </div>
        </div>
        ''' if query else ''}
    """
    html = BASE_HTML.replace("{% block content %}{% endblock %}", content)
    return render_template_string(html, avatar_url=avatar_url)


# Route 3: Community Feedback Board (Concealed Stored XSS)
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    avatar_filename = request.cookies.get('avatar_file', '')
    avatar_url = f"/static/uploads/{avatar_filename}" if avatar_filename else None

    if request.method == "POST":
        user_name = request.form.get("name", "Anonymous")
        comment_text = request.form.get("comment", "")
        if comment_text:
            # INTENTIONAL LAB VULNERABILITY: Stored unescaped comment string
            FEEDBACK_ITEMS.insert(0, {
                "user": user_name,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "comment": comment_text
            })

    comments_html = ""
    for item in FEEDBACK_ITEMS:
        # Render raw item['comment'] without HTML escaping
        comments_html += f"""
        <div style="padding: 15px; background: var(--bg-input); border-radius: 8px; border: 1px solid var(--border); margin-bottom: 15px;">
            <div style="display:flex; justify-weight:space-between; margin-bottom: 8px;">
                <strong style="color: var(--primary); font-size: 0.95rem;">{item['user']}</strong>
                <span style="color: var(--text-muted); font-size: 0.8rem;">{item['time']}</span>
            </div>
            <div style="color: var(--text-main); font-size: 0.9rem;">{item['comment']}</div>
        </div>
        """

    content = f"""
        <div class="page-title">Employee Community Feedback</div>
        <div class="page-desc">Post feedback, request IT equipment, or announce team updates.</div>

        <div class="grid" style="grid-template-columns: 1fr 1.5fr;">
            <div class="card">
                <div class="card-title" style="margin-bottom: 15px;">Post New Feedback</div>
                <form method="POST">
                    <div class="form-group">
                        <label>Your Name</label>
                        <input type="text" name="name" placeholder="John Doe" required>
                    </div>
                    <div class="form-group">
                        <label>Feedback / Announcement</label>
                        <textarea name="comment" rows="4" placeholder="Enter message..." required></textarea>
                    </div>
                    <button type="submit">Submit Comment</button>
                </form>
            </div>

            <div class="card">
                <div class="card-title" style="margin-bottom: 20px;">Recent Community Posts</div>
                {comments_html}
            </div>
        </div>
    """
    html = BASE_HTML.replace("{% block content %}{% endblock %}", content)
    return render_template_string(html, avatar_url=avatar_url)


# Route 4: Admin Network Health Monitor (Concealed OS Command Injection)
@app.route("/admin/tools", methods=["GET", "POST"])
def admin_tools():
    result = ""
    target_host = ""
    avatar_filename = request.cookies.get('avatar_file', '')
    avatar_url = f"/static/uploads/{avatar_filename}" if avatar_filename else None

    if request.method == "POST":
        target_host = request.form.get("host", "")
        if target_host:
            # INTENTIONAL LAB VULNERABILITY: Shell command string concatenation passed directly to shell
            cmd = f"ping -c 1 {target_host}"
            result = subprocess.getoutput(cmd)

    content = f"""
        <div class="page-title">Server Health & Network Diagnostics</div>
        <div class="page-desc">Internal system tool for checking latency and connectivity to infrastructure servers.</div>

        <div class="card" style="margin-bottom: 30px;">
            <form method="POST">
                <div class="form-group">
                    <label>Target Hostname or IPv4 Address</label>
                    <div style="display: flex; gap: 15px;">
                        <input type="text" name="host" value="{target_host}" placeholder="e.g. 127.0.0.1 or google.com" required>
                        <button type="submit">Run Diagnostic</button>
                    </div>
                </div>
            </form>
        </div>

        {f'''
        <div class="card">
            <div class="card-title" style="margin-bottom: 15px;">Execution Output Terminal</div>
            <div class="terminal">{result}</div>
        </div>
        ''' if result else ''}
    """
    html = BASE_HTML.replace("{% block content %}{% endblock %}", content)
    return render_template_string(html, avatar_url=avatar_url)


# Route 5: Employee Directory & Search (Concealed SQL Injection)
@app.route("/directory")
def directory():
    search_term = request.args.get("search", "")
    avatar_filename = request.cookies.get('avatar_file', '')
    avatar_url = f"/static/uploads/{avatar_filename}" if avatar_filename else None

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # INTENTIONAL LAB VULNERABILITY: String formatting in SQL query
    if search_term:
        query = f"SELECT name, department, title, email FROM employees WHERE name LIKE '%{search_term}%' OR department LIKE '%{search_term}%'"
    else:
        query = "SELECT name, department, title, email FROM employees"

    rows = []
    error_msg = ""
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
    except Exception as e:
        error_msg = str(e)
    conn.close()

    table_rows = ""
    for r in rows:
        table_rows += f"""
        <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 12px; font-weight: 500;">{r[0]}</td>
            <td style="padding: 12px; color: var(--text-muted);">{r[1]}</td>
            <td style="padding: 12px; color: var(--primary);">{r[2]}</td>
            <td style="padding: 12px; color: var(--text-muted);">{r[3]}</td>
        </tr>
        """

    content = f"""
        <div class="page-title">Employee Directory</div>
        <div class="page-desc">Browse staff details, department structures, and contact information.</div>

        <div class="card" style="margin-bottom: 25px;">
            <form method="GET">
                <div style="display: flex; gap: 15px;">
                    <input type="text" name="search" value="{search_term}" placeholder="Search employee name or department...">
                    <button type="submit">Filter Directory</button>
                </div>
            </form>
        </div>

        {'<div class="alert alert-danger" style="background: rgba(239,68,68,0.15); border: 1px solid var(--danger); color: var(--danger);">' + error_msg + '</div>' if error_msg else ''}

        <div class="card">
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem;">
                <thead>
                    <tr style="border-bottom: 2px solid var(--border); color: var(--text-muted);">
                        <th style="padding: 12px;">Full Name</th>
                        <th style="padding: 12px;">Department</th>
                        <th style="padding: 12px;">Job Title</th>
                        <th style="padding: 12px;">Email Contact</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows if table_rows else '<tr><td colspan="4" style="padding: 20px; text-align: center; color: var(--text-muted);">No records found matching query criteria.</td></tr>'}
                </tbody>
            </table>
        </div>
    """
    html = BASE_HTML.replace("{% block content %}{% endblock %}", content)
    return render_template_string(html, avatar_url=avatar_url)


# Route 6: Portal Authentication Login (Concealed SQL Injection)
@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    avatar_filename = request.cookies.get('avatar_file', '')
    avatar_url = f"/static/uploads/{avatar_filename}" if avatar_filename else None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # INTENTIONAL LAB VULNERABILITY: Raw unescaped SQL query string formatting
        raw_sql = f"SELECT username, role FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            cursor.execute(raw_sql)
            user = cursor.fetchone()
            if user:
                message = f"Authenticated successfully! Logged in as user '{user[0]}' (Role: {user[1]})."
            else:
                message = "Invalid username or password credentials."
        except Exception as e:
            message = f"Database Auth Error: {str(e)}"
        conn.close()

    content = f"""
        <div class="page-title">Administrative Portal Login</div>
        <div class="page-desc">Access privileged administrative tools and system operations.</div>

        {'<div class="alert alert-info">' + message + '</div>' if message else ''}

        <div class="card" style="max-width: 450px; margin: 0 auto;">
            <div class="card-title" style="margin-bottom: 20px;">System Authentication</div>
            <form method="POST">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" placeholder="••••••••" required>
                </div>
                <button type="submit" style="width: 100%;">Sign In to Portal</button>
            </form>
        </div>
    """
    html = BASE_HTML.replace("{% block content %}{% endblock %}", content)
    return render_template_string(html, avatar_url=avatar_url)


if __name__ == "__main__":
    print("==================================================================")
    print("  NEXUS ENTERPRISE PORTAL - RED/BLUE TEAM LAB TARGET INITIALIZED  ")
    print("  Listening on: http://0.0.0.0:5000                              ")
    print(f"  SIEM Access Log file: {LOG_FILE}                              ")
    print("==================================================================")
    
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
