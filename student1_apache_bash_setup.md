# Student 1: Apache Web Server & Bash History Log Forwarding Setup Guide

This guide completes **Section 2: Architecture & Infrastructure (Student 1)** requirements:
- **2.4.2 Apache Log Ingestion** (Hosting the Flask web app behind Apache web server on Port 80)
- **2.4.3 Bash History Capture** (Logging all system commands executed on VM1 for SIEM investigation)

---

## Step 1: Configure Apache Web Server (Requirement 2.4.2)

Apache is already installed on your system. We will configure Apache as a **Reverse Proxy** on Port 80 pointing to our Python web app running on Port 5000. This ensures all web traffic creates official Apache access logs in `/var/log/apache2/access.log`.

### 1.1 Enable Required Apache Modules
Run these commands in terminal:

```bash
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod headers
```

### 1.2 Create Apache Site Configuration
Create a new VirtualHost file `/etc/apache2/sites-available/nexus-app.conf`:

```bash
sudo nano /etc/apache2/sites-available/nexus-app.conf
```

Paste the following configuration:

```apache
<VirtualHost *:80>
    ServerAdmin admin@nexuscorp.local
    ServerName localhost

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5000/
    ProxyPassReverse / http://127.0.0.1:5000/

    # Standard Apache Log Format for SIEM Ingestion
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

### 1.3 Enable Site and Restart Apache
```bash
sudo a2dissite 000-default.conf
sudo a2ensite nexus-app.conf
sudo systemctl restart apache2
```

### 1.4 Test Apache Access
Start the Python web app in the background:
```bash
cd /home/omar/Desktop/masar/final_Project/
python3 app.py &
```
Now browse to `http://localhost/` or `http://<VM1-IP>/` (on port 80).
Check Apache log generation:
```bash
sudo tail -f /var/log/apache2/access.log
```

---

## Step 2: Configure Real-Time Bash History Capture (Requirement 2.4.3)

To capture every command executed by an attacker (Student 2) after gaining Remote Code Execution (RCE) on VM1:

### 2.1 Configure System-Wide Bash Logging
Add automatic command logging to `/etc/bash.bashrc`:

```bash
sudo nano /etc/bash.bashrc
```

Append the following lines at the end of `/etc/bash.bashrc`:

```bash
# SIEM Real-Time Bash History Logging
export PROMPT_COMMAND='history -a; logger -t bash_history "[USER=$(whoami)] [PWD=$PWD] $(history 1 | sed "s/^[ ]*[0-9]*[ ]*//")"'
```

### 2.2 Create Dedicated Bash History Log File
Configure `rsyslog` to direct all `bash_history` syslog messages to `/var/log/bash_history.log`:

```bash
sudo nano /etc/rsyslog.d/bash_history.conf
```

Add this line:
```rsyslog
if $programname == 'bash_history' then /var/log/bash_history.log
& stop
```

Restart rsyslog:
```bash
sudo systemctl restart rsyslog
```

### 2.3 Test Bash Logging
Open a new terminal window, type a command (e.g. `whoami` or `uname -a`), then check the log file:

```bash
cat /var/log/bash_history.log
```
*Output example:*
`Sep 7 19:55:00 VM1-Target bash_history: [USER=www-data] [PWD=/home/omar/Desktop/masar/final_Project] whoami`

---

## Step 3: Log Forwarding from VM1 to VM2 SIEM (Requirement 2.4.1)

Now that **VM1** has both log sources active:
1. Web Access Logs: `/var/log/apache2/access.log`
2. Bash History Logs: `/var/log/bash_history.log`

### Forwarding via Rsyslog to VM2 SIEM:
Create `/etc/rsyslog.d/forward_to_siem.conf`:

```bash
sudo nano /etc/rsyslog.d/forward_to_siem.conf
```

Add the following lines (replace `<VM2-SIEM-IP>` with VM2's actual IP address):

```rsyslog
# Forward Apache Access Logs and Bash History to VM2 SIEM over UDP port 514
$ModInit imfile

# Monitor Apache Access Log
$InputFileName /var/log/apache2/access.log
$InputFileTag apache_access:
$InputFileStateFile stat-apache-access
$InputFileSeverity info
$InputFileFacility local0
$InputRunFileMonitor

# Monitor Bash History Log
$InputFileName /var/log/bash_history.log
$InputFileTag bash_history:
$InputFileStateFile stat-bash-history
$InputFileSeverity info
$InputFileFacility local1
$InputRunFileMonitor

# Forward all logs to VM2 SIEM Server
local0.* @<VM2-SIEM-IP>:514
local1.* @<VM2-SIEM-IP>:514
```

Restart Rsyslog to start forwarding:
```bash
sudo systemctl restart rsyslog
```
