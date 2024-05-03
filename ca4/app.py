import os
import subprocess
import time
from flask import Flask, render_template, request, redirect, url_for, jsonify
from zapv2 import ZAPv2
from urllib.parse import urlparse

app = Flask(__name__)

# Installation directory
install_directory = os.path.expanduser("~/zap")

def install_zap():
    try:
        # Create the installation directory
        os.makedirs(install_directory, exist_ok=True)

        # Install ZAP using the package manager
        subprocess.run(["sudo", "apt-get", "update"])
        subprocess.run(["sudo", "apt-get", "install", "-y", "zaproxy"])

        print("ZAP installation completed.")
    except Exception as e:
        print(f"Error installing ZAP: {e}")

# Call the install_zap function to install ZAP
install_zap()

# Start ZAP as a daemon
zap_path = subprocess.run(["which", "zaproxy"], capture_output=True, text=True).stdout.strip()
zap_process = subprocess.Popen([zap_path, "-daemon", "-host", "0.0.0.0", "-port", "8080", "-config", "api.disablekey=true"])

# Give some time for ZAP to start up before creating the ZAP API client
time.sleep(10)  # Adjust the sleep duration as needed

# Connect to the ZAP API client
zap = ZAPv2(proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})

# Dictionary to hold scan ids and their progress
scans = {}

def is_supported_protocol(url):
    supported_protocols = ['http', 'https', 'ftp']  # Add more protocols if needed
    parsed_url = urlparse(url)
    return parsed_url.scheme in supported_protocols

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target_url = request.form['target_url']
        if is_supported_protocol(target_url):
            scan_id = zap.spider.scan(target_url)
            scans[scan_id] = {'url': target_url, 'status': 0}
            return redirect(url_for('scan_status', scan_id=scan_id))
        else:
            return "Unsupported protocol", 400
    return render_template('index.html')

@app.route('/status/<scan_id>')
def scan_status(scan_id):
    if scan_id in scans:
        status = zap.spider.status(scan_id)
        return jsonify({'status': status})
    else:
        return jsonify({'error': 'Invalid scan ID'})

@app.route('/results/<scan_id>')
def scan_results(scan_id):
    if scan_id in scans:
        vulnerabilities = zap.core.alerts(scan_id=scan_id)
        if vulnerabilities:
            # Filter out unsupported protocols from vulnerabilities
            filtered_vulnerabilities = [vuln for vuln in vulnerabilities if is_supported_protocol(vuln['url'])]
            return render_template('scan_results.html', url=scans[scan_id]['url'], alerts=filtered_vulnerabilities)
        else:
            return "No vulnerabilities found."
    else:
        return "Invalid scan ID", 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
