from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import re
from email import message_from_string
from datetime import datetime
import socket

app = Flask(__name__)
CORS(app)

def parse_email_header(header_text):
    """Parse email header and extract relevant information"""
    try:
        msg = message_from_string(header_text)
        
        # Basic information
        basic_info = {
            'From': msg.get('From', 'Not found'),
            'To': msg.get('To', 'Not found'),
            'Subject': msg.get('Subject', 'Not found'),
            'Date': msg.get('Date', 'Not found'),
            'Message-ID': msg.get('Message-ID', 'Not found'),
            'Return-Path': msg.get('Return-Path', 'Not found')
        }
        
        # Security information
        security = {
            'SPF': msg.get('Received-SPF', 'Not found'),
            'DKIM-Signature': 'Present' if msg.get('DKIM-Signature') else 'Not found',
            'DMARC': 'Check Authentication-Results',
            'Authentication-Results': msg.get('Authentication-Results', 'Not found')
        }
        
        # Extract email route
        route = extract_route(msg.get_all('Received', []))
        
        # Warnings
        warnings = []
        
        # Check for SPF failures
        spf = msg.get('Received-SPF', '')
        if 'fail' in spf.lower():
            warnings.append('SPF check failed - email may be spoofed')
        
        # Check for missing DKIM
        if not msg.get('DKIM-Signature'):
            warnings.append('No DKIM signature found - authenticity cannot be verified')
        
        # Check for suspicious sender domain mismatch
        from_addr = msg.get('From', '')
        return_path = msg.get('Return-Path', '')
        if from_addr and return_path:
            from_domain = extract_domain(from_addr)
            return_domain = extract_domain(return_path)
            if from_domain and return_domain and from_domain != return_domain:
                warnings.append(f'Sender domain mismatch: From domain ({from_domain}) differs from Return-Path domain ({return_domain})')
        
        return {
            'basic_info': basic_info,
            'security': security,
            'route': route,
            'warnings': warnings
        }
    
    except Exception as e:
        return {'error': str(e)}

def extract_route(received_headers):
    """Extract email routing information from Received headers"""
    route = []
    
    for received in received_headers:
        hop = {}
        
        # Extract server/host information
        from_match = re.search(r'from\s+([^\s]+)', received, re.IGNORECASE)
        if from_match:
            hop['server'] = from_match.group(1)
        
        # Extract IP address
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
        if ip_match:
            hop['ip'] = ip_match.group(1)
        
        # Extract timestamp
        date_match = re.search(r';\s*(.+)$', received)
        if date_match:
            hop['timestamp'] = date_match.group(1).strip()
        
        if hop:
            route.append(hop)
    
    return route

def extract_domain(email_string):
    """Extract domain from email address"""
    match = re.search(r'@([^\s>]+)', email_string)
    return match.group(1) if match else None

# Serve the HTML frontend
@app.route('/')
def index():
    with open('index.html', 'r') as f:
        return f.read()

@app.route('/analyze', methods=['POST'])
def analyze():
    """API endpoint to analyze email headers"""
    try:
        data = request.get_json()
        header_text = data.get('header', '')
        
        if not header_text:
            return jsonify({'error': 'No header provided'}), 400
        
        result = parse_email_header(header_text)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("=" * 50)
    print("Email Header Analyzer Server")
    print("=" * 50)
    print("\nStarting server on http://localhost:5000")
    print("Press Ctrl+C to stop the server\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)