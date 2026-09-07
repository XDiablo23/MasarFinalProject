# Red/Blue Team Security Lab - Target Application & SIEM Observability Report

---

## 1. How to Run the Web Application

### Prerequisites
- **Python 3.x**
- **Flask**: `pip install flask` (already verified and installed)

### Execution Commands

To run the application directly from the target machine (**VM1**):

```bash
cd /home/omar/Desktop/masar/final_Project/
python3 app.py
```

#### Running in the Background (Daemon mode)
If you want the web app to run continuously in the background during your Penetration Testing session:

```bash
nohup python3 app.py > app_output.log 2>&1 &
```

#### Verification & Port Check
To verify that the application is running and listening on port **5000**:

```bash
netstat -tulpn | grep 5000
# OR
curl -I http://127.0.0.1:5000/
```

- **Web App URL**: `http://<VM1-IP>:5000/`
- **SIEM Access Log Path**: `/home/omar/Desktop/masar/final_Project/app_access.log`

---

## 2. Refactored Web Application Architecture & Realism

The application has been transformed from a raw lab demo into **Nexus Enterprise Portal**—a realistic corporate dashboard featuring:
- Glassmorphic dark mode corporate interface.
- Realistic navigation: Dashboard, Employee Directory, Knowledge Base Search, Community Board, Server Diagnostic Tools, Account Profile Settings, and Portal Login.
- Hidden intentional vulnerabilities seamlessly integrated into typical enterprise user workflows.

---

## 3. Vulnerability Map & Penetration Testing Trigger Guide

| Vulnerability | Concealed Location / Endpoint | HTTP Method | Parameter Name | Trigger Description / Payload Type |
|---|---|---|---|---|
| **File Upload** | `/profile` (User Settings Avatar Upload) | `POST` | `avatar` (multipart/form-data) | Uploads any file directly to `/static/uploads/` without extension validation or MIME type restrictions. Accessible at `http://<VM1-IP>:5000/static/uploads/<filename>`. |
| **Reflected XSS** | `/search` (Knowledge Base Search) | `GET` | `q` | Search string is rendered directly into the search results template without HTML escaping. |
| **Stored XSS** | `/feedback` (Community Board) | `POST` | `comment`, `name` | Feedback comments are stored in server memory and rendered raw to all visiting users without sanitization. |
| **OS Command Injection** | `/admin/tools` (Server Diagnostics) | `POST` | `host` | Host string is passed to `subprocess.getoutput("ping -c 1 " + host)`. Allows shell command chaining using operators (`;`, `\|`, `&&`, `\n`). |
| **SQL Injection (Auth)** | `/login` (Portal Authentication) | `POST` | `username`, `password` | Password/Username strings are directly formatted into SQLite SQL string queries (`SELECT * FROM users WHERE username = '...' AND password = '...'`). |
| **SQL Injection (Search)** | `/directory` (Employee Search) | `GET` | `search` | Search term is interpolated into SQL `LIKE` query (`SELECT * FROM employees WHERE name LIKE '%<input>%'`). |

---

## 4. SIEM Logging System & Observability

### Log File Location
`/home/omar/Desktop/masar/final_Project/app_access.log`

### SIEM Log Structure
Every HTTP request generates a structured log line formatted as follows:

```text
YYYY-MM-DD HH:MM:SS,ms | INFO | CLIENT_IP=<ip> | METHOD=<method> | PATH=<path> | QUERY=<query> | BODY=<body_payload> | AGENT="<user_agent>"
```

### Sample Log Entries Generated During Exploitation

#### 1. File Upload Log Example:
```text
2026-09-07 18:15:00,123 | INFO | CLIENT_IP=192.168.1.50 | METHOD=POST | PATH=/profile | QUERY= | BODY=FilesUploaded: ['webshell.py'] | AGENT="Mozilla/5.0"
```

#### 2. Command Injection Log Example:
```text
2026-09-07 18:16:10,456 | INFO | CLIENT_IP=192.168.1.50 | METHOD=POST | PATH=/admin/tools | QUERY= | BODY={'host': '127.0.0.1; id; uname -a'} | AGENT="Mozilla/5.0"
```

#### 3. XSS Log Example:
```text
2026-09-07 18:17:20,789 | INFO | CLIENT_IP=192.168.1.50 | METHOD=GET | PATH=/search | QUERY=q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E | BODY= | AGENT="Mozilla/5.0"
```

#### 4. SQL Injection Log Example:
```text
2026-09-07 18:18:30,912 | INFO | CLIENT_IP=192.168.1.50 | METHOD=POST | PATH=/login | QUERY= | BODY={'username': "admin' OR '1'='1", 'password': 'foo'} | AGENT="Mozilla/5.0"
```

---

## 5. VM1 Log Forwarder Configuration for SIEM (Student 1 Setup)

To forward these logs from **VM1 (Target)** to **VM2 (SIEM)** (e.g. Elastic Stack, Wazuh, Splunk, or Rsyslog):

### Option A: Using Rsyslog (Standard Linux Log Forwarder)
Edit `/etc/rsyslog.conf` or add `/etc/rsyslog.d/nexus_app.conf` on VM1:

```rsyslog
$ModInit imfile
$InputFileName /home/omar/Desktop/masar/final_Project/app_access.log
$InputFileTag nexus-app:
$InputFileStateFile stat-nexus-app
$InputFileSeverity info
$InputFileFacility local0
$InputRunFileMonitor

local0.* @@<VM2-SIEM-IP>:514
```
Then restart rsyslog: `sudo systemctl restart rsyslog`.

---

## 6. Student Role Mapping for Report

- **Student 1 (Architecture & Visibility)**: Use Section 1, 2, 4, 5 to document application deployment, realistic feature layout, and log forwarding architecture.
- **Student 2 (Red Team / PT)**: Use Section 3 for black-box testing target endpoints.
- **Student 3 (Blue Team / IR)**: Use Section 4 log format to write SIEM detection rules matching suspicious keywords (e.g., `BODY=*FilesUploaded:*`, `;`, `|`, `<script>`, `' OR '1'='1`).
- **Student 4 (Mitigation)**: Use Section 3 locations to implement parameterized SQL queries, `html.escape()`, secure file extensions (`secure_filename()`), and `shlex.quote()`.
