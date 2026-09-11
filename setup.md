# Nexus Enterprise Portal - Setup Guide for SIEM & SOC Analysts

This guide explains how to set up the vulnerable Nexus Enterprise Portal application and analyze its security logs. 

**This lab already contains the penetration testing logs (`app_access.log`). You do not need to perform the attacks again.**

---

## 1. Prerequisites
Ensure you have the following installed on your machine:
- Python 3.x
- pip (Python package manager)

## 2. Installation & Setup

1. **Clone or Download this Repository**
   Download the project files and extract them, or clone via git:
   ```bash
   git clone <YOUR_REPOSITORY_URL>
   cd final_Project
   ```
   *(If you downloaded a ZIP, just extract it and open a terminal inside the folder)*

2. **Install Required Libraries**
   The application requires the Flask framework:
   ```bash
   pip3 install Flask
   ```

3. **Verify the Files**
   Ensure the following crucial files are present in your directory:
   - `app.py`: The main server code.
   - `app_access.log`: **The pre-populated log file containing the attacker's web attack footprints.**
   - `apache_logs/`: **A folder containing the Apache logs (`access.log`, `error.log`) capturing the PHP webshell execution.**
   - `bash_history.log`: **System-level real-time Bash command audit log (Requirement 2.4.3).**
   - `shell_history.log`: **Full terminal command execution history (attacker actions, reverse shells, curl payloads).**
   - `nexus_corp.db`: The SQLite database.
   - `static/`: Contains images and the uploaded files.

## 3. Running the Server

If you need to view the web application to understand the context of the logs, start the server:

```bash
python3 app.py
```
*The portal will be accessible at `http://localhost:5000` or `http://127.0.0.1:5000`*

---

## 4. SIEM & Log Analysis Task (Student 3)

Your primary objective is to analyze the provided `app_access.log` file. 

### Understanding the Log Format
The logs are formatted specifically for SIEM parsing. Here is the structure:
`[TIMESTAMP] SIEM LOG: CLIENT_IP=... | METHOD=... | PATH=... | QUERY=... | BODY=... | AGENT=...`

### Key Attack Signatures to Look For:
1. **Unrestricted File Upload (CWE-434)**
   - Look for `POST` requests to `/profile`.
   - Check the `BODY=` field for suspicious file uploads (e.g., `FilesUploaded: ['shell.php']`).
2. **Command Injection (CWE-78)**
   - Look for `POST` requests to `/admin/tools`.
   - Check the `BODY=` field for shell characters (`|`, `;`, `&&`) mixed with typical inputs like IP addresses.
3. **Cross-Site Scripting (XSS) (CWE-79)**
   - **Reflected:** Look at `GET` requests to `/search` where the `QUERY=` contains HTML tags like `<script>`.
   - **Stored:** Look at `POST` requests to `/feedback` where the `BODY=` contains malicious JavaScript.
4. **SQL Injection (CWE-89)**
   - Look for inputs containing `' OR 1=1`, `UNION SELECT`, or `--` in `POST /login` (in the `BODY`) or `GET /directory` (in the `QUERY`).
5. **Webshell Execution**
   - Look for `GET` requests to `/static/uploads/shell.php` with suspicious commands in the `QUERY` parameter (e.g., `cmd=id`, `cmd=whoami`, `cmd=bash...`).

### How to analyze (Example Tools)
You can ingest `app_access.log` into a SIEM like Splunk, or analyze it via terminal:

**Find all PHP file access:**
```bash
grep "\.php" app_access.log
```

**Find all POST requests:**
```bash
grep "METHOD=POST" app_access.log
```

**Find command execution attempts:**
```bash
grep "cmd=" app_access.log
```
