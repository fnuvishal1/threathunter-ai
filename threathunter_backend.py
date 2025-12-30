#!/usr/bin/env python3
"""
ThreatHunter AI - Backend Server with FREE Google Gemini AI
Real-time log analysis with AI-powered threat detection
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import re
import hashlib
from datetime import datetime
import pandas as pd
import yaml
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import requests

# Import Google Gemini AI (FREE!)
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("⚠️ google-generativeai not installed. AI features disabled.")

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# Initialize Gemini AI (FREE)
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
if GEMINI_API_KEY and GEMINI_AVAILABLE:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-1.5-flash')
        print("✅ Google Gemini AI initialized (FREE)")
    except Exception as e:
        print(f"⚠️ Gemini initialization failed: {e}")
        model = None
else:
    model = None
    print("⚠️ Gemini API key not found. Set GEMINI_API_KEY environment variable.")

# MITRE ATT&CK Mapping (subset for demo)
MITRE_TACTICS = {
    'T1003': {'name': 'Credential Dumping', 'tactic': 'Credential Access'},
    'T1021': {'name': 'Remote Services', 'tactic': 'Lateral Movement'},
    'T1059': {'name': 'Command-Line Interface', 'tactic': 'Execution'},
    'T1070': {'name': 'Indicator Removal', 'tactic': 'Defense Evasion'},
    'T1078': {'name': 'Valid Accounts', 'tactic': 'Defense Evasion'},
    'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
    'T1518': {'name': 'Software Discovery', 'tactic': 'Discovery'},
    'T1068': {'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'},
    'T1566': {'name': 'Phishing', 'tactic': 'Initial Access'},
    'T1090': {'name': 'Proxy', 'tactic': 'Command and Control'},
    'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactic': 'Exfiltration'},
    'T1136': {'name': 'Create Account', 'tactic': 'Persistence'}
}

# Sigma-like detection rules (simplified)
DETECTION_RULES = [
    {
        'id': 'mimikatz_detection',
        'name': 'Mimikatz Credential Dumping',
        'severity': 'critical',
        'mitre': 'T1003',
        'patterns': [r'mimikatz', r'lsass\.exe', r'sekurlsa', r'procdump.*lsass']
    },
    {
        'id': 'ransomware_indicators',
        'name': 'Ransomware Activity',
        'severity': 'critical',
        'mitre': 'T1486',
        'patterns': [r'\.encrypted', r'\.locked', r'ransom', r'\.crypt', r'YOUR_FILES_ARE_ENCRYPTED']
    },
    {
        'id': 'lateral_movement',
        'name': 'Lateral Movement via WMI/PSExec',
        'severity': 'high',
        'mitre': 'T1021',
        'patterns': [r'psexec', r'wmic.*process.*call.*create', r'\\\\.*\\admin\$', r'net use.*\\c\$']
    },
    {
        'id': 'suspicious_powershell',
        'name': 'Suspicious PowerShell Execution',
        'severity': 'high',
        'mitre': 'T1059',
        'patterns': [r'powershell.*-enc', r'powershell.*bypass', r'powershell.*hidden', r'IEX.*Net\.WebClient']
    },
    {
        'id': 'brute_force_ssh',
        'name': 'SSH Brute Force Attempt',
        'severity': 'high',
        'mitre': 'T1078',
        'patterns': [r'Failed password.*ssh', r'authentication failure.*ssh', r'Invalid user.*ssh']
    },
    {
        'id': 'privilege_escalation',
        'name': 'Privilege Escalation Attempt',
        'severity': 'critical',
        'mitre': 'T1068',
        'patterns': [r'sudo.*COMMAND', r'su\s+root', r'PsExec.*-s\s+', r'whoami.*admin']
    },
    {
        'id': 'data_exfiltration',
        'name': 'Potential Data Exfiltration',
        'severity': 'high',
        'mitre': 'T1048',
        'patterns': [r'curl.*-d\s+', r'wget.*--post', r'ftp.*PUT', r'scp.*sensitive']
    },
    {
        'id': 'log_clearing',
        'name': 'Security Log Clearing',
        'severity': 'high',
        'mitre': 'T1070',
        'patterns': [r'wevtutil.*cl.*security', r'Clear-EventLog', r'rm.*\.log', r'journalctl.*--vacuum']
    },
    {
        'id': 'suspicious_network',
        'name': 'Suspicious Network Connection',
        'severity': 'medium',
        'mitre': 'T1090',
        'patterns': [r'nc.*-l.*-p', r'netcat', r'reverse.*shell', r'meterpreter']
    },
    {
        'id': 'account_creation',
        'name': 'Suspicious Account Creation',
        'severity': 'medium',
        'mitre': 'T1136',
        'patterns': [r'net user.*\/add', r'useradd', r'New-LocalUser', r'adduser']
    }
]


def extract_iocs(log_content):
    """Extract IOCs (IP addresses, domains, hashes) from logs"""
    iocs = {
        'ips': [],
        'domains': [],
        'hashes': [],
        'urls': []
    }
    
    # IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    iocs['ips'] = list(set(re.findall(ip_pattern, log_content)))
    
    # Domains
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    potential_domains = list(set(re.findall(domain_pattern, log_content)))
    iocs['domains'] = [d for d in potential_domains if '.' in d and not re.match(ip_pattern, d)][:10]
    
    # MD5/SHA256 hashes
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
    iocs['hashes'] = list(set(re.findall(hash_pattern, log_content)))[:10]
    
    # URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    iocs['urls'] = list(set(re.findall(url_pattern, log_content)))[:10]
    
    return iocs


def analyze_with_gemini(threat_data, log_snippet):
    """
    FREE AI Analysis using Google Gemini
    No credit card required, 1500+ requests/day FREE!
    """
    if not model:
        return {
            'enabled': False,
            'message': '⚠️ AI analysis disabled. Set GEMINI_API_KEY environment variable.',
            'setup_url': 'https://aistudio.google.com/app/apikey'
        }
    
    try:
        prompt = f"""You are an expert cybersecurity threat analyst. Analyze this security incident:

**Threat Details:**
- Type: {threat_data.get('rule_name')}
- Severity: {threat_data.get('severity').upper()}
- MITRE Technique: {threat_data.get('mitre_id')} - {threat_data.get('mitre_name')}
- Tactic: {threat_data.get('mitre_tactic')}

**Log Sample:**
```
{log_snippet[:1000]}
```

**IOCs Detected:**
- IPs: {', '.join(threat_data.get('iocs', {}).get('ips', [])[:3])}
- Domains: {', '.join(threat_data.get('iocs', {}).get('domains', [])[:3])}

Provide a concise security analysis with:
1. **Impact Assessment** (2 sentences)
2. **Attack Context** (what the attacker is doing)
3. **Immediate Actions** (3 specific steps)
4. **Risk Level** (CRITICAL/HIGH/MEDIUM/LOW with brief reason)

Keep response under 250 words, technical and actionable. Use bullet points for actions.
"""
        
        response = model.generate_content(prompt)
        
        return {
            'enabled': True,
            'analysis': response.text,
            'model': 'gemini-1.5-flash',
            'cost': 'FREE'
        }
        
    except Exception as e:
        return {
            'enabled': True,
            'error': f'AI analysis failed: {str(e)}',
            'fallback': 'Manual analysis recommended for this threat.'
        }


def detect_threats(log_content):
    """Detect threats using pattern matching (Sigma-like rules)"""
    threats = []
    log_lower = log_content.lower()
    
    for rule in DETECTION_RULES:
        matches = []
        for pattern in rule['patterns']:
            found = re.findall(pattern, log_lower, re.IGNORECASE)
            if found:
                matches.extend(found[:3])  # Limit to 3 matches per pattern
        
        if matches:
            mitre_info = MITRE_TACTICS.get(rule['mitre'], {})
            
            threat = {
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'severity': rule['severity'],
                'mitre_id': rule['mitre'],
                'mitre_name': mitre_info.get('name', 'Unknown'),
                'mitre_tactic': mitre_info.get('tactic', 'Unknown'),
                'matches': matches[:5],  # Top 5 matches
                'timestamp': datetime.now().isoformat(),
                'confidence': min(len(matches) * 25, 100)  # Confidence score
            }
            
            threats.append(threat)
    
    return threats


@app.route('/')
def index():
    """Serve the main HTML page"""
    return send_from_directory('.', 'threathunter_ai.html')


@app.route('/api/analyze', methods=['POST'])
def analyze_logs():
    """Analyze uploaded log files for threats"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        # Read file content
        try:
            log_content = file.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return jsonify({'error': f'Failed to read file: {str(e)}'}), 400
        
        if not log_content.strip():
            return jsonify({'error': 'File is empty'}), 400
        
        # Extract IOCs
        iocs = extract_iocs(log_content)
        
        # Detect threats
        threats = detect_threats(log_content)
        
        # Add IOCs to each threat
        for threat in threats:
            threat['iocs'] = iocs
        
        # Add AI analysis to each threat (FREE with Gemini!)
        log_lines = log_content.split('\n')
        log_snippet = '\n'.join(log_lines[:30])  # First 30 lines
        
        for threat in threats:
            threat['ai_analysis'] = analyze_with_gemini(threat, log_snippet)
        
        # Calculate statistics
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for threat in threats:
            severity_counts[threat['severity']] += 1
        
        # Prepare response
        response_data = {
            'success': True,
            'filename': file.filename,
            'analyzed_at': datetime.now().isoformat(),
            'statistics': {
                'total_lines': len(log_lines),
                'threats_detected': len(threats),
                'severity_breakdown': severity_counts,
                'unique_ips': len(iocs['ips']),
                'unique_domains': len(iocs['domains']),
                'unique_hashes': len(iocs['hashes']),
                'risk_score': min(len(threats) * 15 + severity_counts['critical'] * 25, 100)
            },
            'threats': threats,
            'iocs': iocs,
            'ai_powered': model is not None,
            'ai_model': 'gemini-1.5-flash (FREE)' if model else None
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'ai_enabled': model is not None,
        'ai_provider': 'Google Gemini (FREE)' if model else None,
        'detection_rules': len(DETECTION_RULES),
        'mitre_techniques': len(MITRE_TACTICS),
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    print("\n" + "="*60)
    print("🎯 ThreatHunter AI - Starting Server")
    print("="*60)
    print(f"🌐 Server: http://0.0.0.0:{port}")
    print(f"🤖 AI Status: {'✅ Enabled (FREE Gemini)' if model else '⚠️ Disabled'}")
    print(f"📊 Detection Rules: {len(DETECTION_RULES)}")
    print(f"🎯 MITRE Techniques: {len(MITRE_TACTICS)}")
    if not model:
        print("\n⚠️  To enable FREE AI analysis:")
        print("   1. Get API key: https://aistudio.google.com/app/apikey")
        print("   2. Set: GEMINI_API_KEY=your-key-here")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=port, debug=False)
